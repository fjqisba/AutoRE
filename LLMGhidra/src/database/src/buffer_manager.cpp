/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/buffer_manager.hpp"

#include "llmghidra/db/database_change_set.hpp"
#include "llmghidra/db/local_managed_buffer_file.hpp"
#include "llmghidra/db/recovery_file.hpp"
#include "llmghidra/db/recovery_manager.hpp"

#include <algorithm>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {
namespace {

std::size_t normalize_maximum_undos(std::int32_t value,
                                    bool constructor_semantics) {
  if ((constructor_semantics && value < 1) || value < 0) {
    return BufferManager::default_undo_count;
  }
  return static_cast<std::size_t>(value);
}

void discard_destination_noexcept(
    const std::shared_ptr<LocalBufferFile> &destination) noexcept {
  if (!destination)
    return;
  const auto path = destination->path();
  try {
    if (!destination->closed() && !destination->read_only() &&
        destination->delete_file()) {
      return;
    }
  } catch (...) {
  }
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}

} // namespace

BufferManager::BufferManager(
    std::int32_t requested_buffer_size, std::size_t approximate_cache_size,
    std::int32_t maximum_undos,
    std::shared_ptr<FileOperations> recovery_file_operations)
    : buffer_size_(
          LocalBufferFile::recommended_buffer_size(requested_buffer_size)),
      max_undos_(normalize_maximum_undos(maximum_undos, true)),
      recovery_file_operations_(recovery_file_operations
                                    ? std::move(recovery_file_operations)
                                    : std::make_shared<FileOperations>()) {
  (void)approximate_cache_size;
  if (buffer_size_ <= 0) {
    throw std::invalid_argument("invalid BufferManager buffer size");
  }
  initialize_history();
}

BufferManager::BufferManager(
    std::shared_ptr<LocalBufferFile> source_file,
    std::size_t approximate_cache_size, std::int32_t maximum_undos,
    std::shared_ptr<FileOperations> recovery_file_operations)
    : source_file_(std::move(source_file)),
      max_undos_(normalize_maximum_undos(maximum_undos, true)),
      recovery_file_operations_(recovery_file_operations
                                    ? std::move(recovery_file_operations)
                                    : std::make_shared<FileOperations>()) {
  (void)approximate_cache_size;
  if (!source_file_ || source_file_->closed()) {
    throw std::invalid_argument("BufferManager source file is not open");
  }
  buffer_size_ = source_file_->buffer_size();
  source_index_count_ = source_file_->index_count();
  working_state_.indexes =
      IndexProvider(source_index_count_, source_file_->free_indexes());
  for (const auto &name : source_file_->parameter_names()) {
    parameters_.emplace(name, source_file_->parameter(name));
  }
  initialize_history();
}

BufferManager::~BufferManager() = default;

void BufferManager::initialize_history() {
  working_state_.revision = 0;
  history_.clear();
  history_.push_back(working_state_);
}

std::shared_ptr<LocalBufferFile> BufferManager::source_file() const {
  std::scoped_lock lock(mutex_);
  return source_file_;
}

void BufferManager::require_healthy_locked() const {
  if (corrupted_) {
    throw std::runtime_error("corrupted BufferManager state");
  }
}

void BufferManager::require_no_locks_locked(const char *operation) const {
  if (!locked_.empty()) {
    throw std::logic_error(std::string("cannot ") + operation +
                           " while buffers are locked");
  }
}

std::vector<std::uint8_t>
BufferManager::resolve_bytes_locked(std::int32_t id) const {
  if (id < 0 || id >= working_state_.indexes.index_count() ||
      working_state_.indexes.is_free(id)) {
    throw std::out_of_range("invalid BufferManager buffer id");
  }

  const auto overlay = working_state_.overlay.find(id);
  if (overlay != working_state_.overlay.end()) {
    return *overlay->second;
  }
  if (!source_file_ || id >= source_index_count_) {
    throw std::runtime_error("allocated buffer has no backing data");
  }

  DataBuffer source_buffer;
  source_file_->get(source_buffer, id);
  if (source_buffer.empty() || !source_buffer.has_data()) {
    throw std::runtime_error("source buffer is unexpectedly empty");
  }
  return source_buffer.bytes();
}

std::shared_ptr<DataBuffer> BufferManager::get_buffer(std::int32_t id) {
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  if (locked_.contains(id)) {
    throw std::logic_error("BufferManager buffer is already locked");
  }

  auto buffer = std::make_shared<DataBuffer>(resolve_bytes_locked(id));
  buffer->set_id(id);
  buffer->set_empty(false);
  buffer->set_dirty(false);
  locked_.emplace(id, LockEntry{buffer, false});
  return buffer;
}

std::shared_ptr<DataBuffer> BufferManager::create_buffer() {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  const auto id = working_state_.indexes.allocate();
  if (locked_.contains(id)) {
    throw std::logic_error("allocated BufferManager id is already locked");
  }

  std::shared_ptr<DataBuffer> buffer;
  const auto retired = working_state_.overlay.find(id);
  if (retired != working_state_.overlay.end()) {
    // BufferMgr recycles the cached DataBuffer for a deleted ID without
    // clearing its payload.  Nodes initialize only their live header/data, so
    // preserving these bytes is required for byte-for-byte Ghidra output.
    buffer = std::make_shared<DataBuffer>(*retired->second);
  } else {
    buffer =
        std::make_shared<DataBuffer>(static_cast<std::size_t>(buffer_size_));
  }
  buffer->set_id(id);
  buffer->set_empty(false);
  buffer->set_dirty(true);
  locked_.emplace(id, LockEntry{buffer, true});
  return buffer;
}

void BufferManager::start_change_locked() {
  if (working_dirty_)
    return;
  redo_history_.clear();
  if (next_revision_ == 0) {
    throw std::overflow_error("BufferManager revision space exhausted");
  }
  working_state_.revision = next_revision_++;
  working_dirty_ = true;
}

void BufferManager::release_buffer(const std::shared_ptr<DataBuffer> &buffer) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  if (!buffer) {
    throw std::invalid_argument("cannot release a null BufferManager buffer");
  }
  const auto found = locked_.find(buffer->id());
  if (found == locked_.end() || found->second.buffer.get() != buffer.get()) {
    throw std::logic_error("released buffer is not locked by this manager");
  }
  if (!buffer->dirty()) {
    if (found->second.newly_created) {
      throw std::logic_error("new BufferManager buffer must be released dirty");
    }
    locked_.erase(found);
    return;
  }

  ImmutableBytes replacement;
  if (buffer->has_data() &&
      buffer->size() == static_cast<std::size_t>(buffer_size_)) {
    replacement =
        std::make_shared<const std::vector<std::uint8_t>>(buffer->bytes());
  } else if (!buffer->empty()) {
    throw std::invalid_argument("released BufferManager buffer has wrong size");
  }

  start_change_locked();
  const auto id = buffer->id();
  if (buffer->empty()) {
    // Retain the last payload while the index is free.  It is not visible
    // through get_buffer() and is skipped during persistence, but it becomes
    // the initial payload if this exact ID is reallocated in the same manager.
    if (replacement)
      working_state_.overlay[id] = replacement;
    else
      working_state_.overlay.erase(id);
    working_state_.indexes.free(id);
  } else {
    working_state_.overlay[id] = replacement;
  }
  ++modification_count_;
  modified_since_snapshot_ = true;
  buffer->set_dirty(false);
  locked_.erase(found);
}

void BufferManager::delete_buffer(std::int32_t id) {
  auto buffer = get_buffer(id);
  buffer->set_empty(true);
  buffer->set_dirty(true);
  release_buffer(buffer);
}

std::size_t BufferManager::lock_count() const {
  std::scoped_lock lock(mutex_);
  return locked_.size();
}

std::int32_t BufferManager::allocated_buffer_count() const {
  std::scoped_lock lock(mutex_);
  return working_state_.indexes.index_count() -
         static_cast<std::int32_t>(working_state_.indexes.free_index_count());
}

std::size_t BufferManager::free_buffer_count() const {
  std::scoped_lock lock(mutex_);
  return working_state_.indexes.free_index_count();
}

BufferManager::BufferState BufferManager::buffer_state(std::int32_t id) const {
  std::scoped_lock lock(mutex_);
  if (id < 0 || id >= working_state_.indexes.index_count())
    return BufferState::out_of_range;
  return working_state_.indexes.is_free(id) ? BufferState::free
                                            : BufferState::allocated;
}

std::vector<std::int32_t> BufferManager::allocated_buffer_ids() const {
  std::scoped_lock lock(mutex_);
  std::vector<std::int32_t> result;
  result.reserve(static_cast<std::size_t>(
      working_state_.indexes.index_count() -
      static_cast<std::int32_t>(working_state_.indexes.free_index_count())));
  for (std::int32_t id = 0; id < working_state_.indexes.index_count(); ++id) {
    if (!working_state_.indexes.is_free(id))
      result.push_back(id);
  }
  return result;
}

std::uint8_t BufferManager::inspect_u8(std::int32_t id,
                                       std::size_t offset) const {
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  const auto locked = locked_.find(id);
  if (locked != locked_.end()) {
    if (offset >= locked->second.buffer->size())
      throw std::out_of_range("BufferManager inspection offset");
    return locked->second.buffer->get_u8(offset);
  }
  const auto bytes = resolve_bytes_locked(id);
  if (offset >= bytes.size())
    throw std::out_of_range("BufferManager inspection offset");
  return bytes[offset];
}

std::uint64_t BufferManager::modification_count() const {
  std::scoped_lock lock(mutex_);
  return modification_count_;
}

bool BufferManager::at_checkpoint() const {
  std::scoped_lock lock(mutex_);
  return !working_dirty_;
}

bool BufferManager::is_changed() const {
  std::scoped_lock lock(mutex_);
  return working_state_.revision != 0;
}

bool BufferManager::has_undo_checkpoints() const {
  std::scoped_lock lock(mutex_);
  return working_dirty_ || history_.size() > 1;
}

bool BufferManager::has_redo_checkpoints() const {
  std::scoped_lock lock(mutex_);
  return !redo_history_.empty();
}

std::size_t BufferManager::available_undo_count() const {
  std::scoped_lock lock(mutex_);
  return (history_.size() - 1) + (working_dirty_ ? 1 : 0);
}

std::size_t BufferManager::available_redo_count() const {
  std::scoped_lock lock(mutex_);
  return redo_history_.size();
}

void BufferManager::trim_history_locked() {
  while (history_.size() > max_undos_ + 1) {
    history_.erase(history_.begin());
  }
}

void BufferManager::checkpoint_locked() {
  history_.push_back(working_state_);
  working_dirty_ = false;
  trim_history_locked();
}

bool BufferManager::checkpoint(const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  if (!working_dirty_)
    return false;
  require_no_locks_locked("checkpoint");
  task.checkpoint();
  checkpoint_locked();
  return true;
}

bool BufferManager::undo(bool redoable) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  require_no_locks_locked("undo");

  State removed;
  if (working_dirty_) {
    removed = working_state_;
    working_state_ = history_.back();
    working_dirty_ = false;
  } else {
    if (history_.size() <= 1)
      return false;
    removed = history_.back();
    history_.pop_back();
    working_state_ = history_.back();
  }

  if (redoable) {
    redo_history_.push_back(std::move(removed));
  } else {
    redo_history_.clear();
  }
  modified_since_snapshot_ = true;
  return true;
}

bool BufferManager::redo() {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  require_no_locks_locked("redo");
  if (redo_history_.empty())
    return false;
  if (working_dirty_) {
    throw std::logic_error("cannot redo from an active checkpoint");
  }

  working_state_ = std::move(redo_history_.back());
  redo_history_.pop_back();
  history_.push_back(working_state_);
  trim_history_locked();
  modified_since_snapshot_ = true;
  return true;
}

void BufferManager::set_max_undos(std::int32_t maximum_undos) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  max_undos_ = normalize_maximum_undos(maximum_undos, false);
  if (working_dirty_ && max_undos_ == 0)
    checkpoint_locked();
  trim_history_locked();
  redo_history_.clear();
}

std::size_t BufferManager::max_undos() const {
  std::scoped_lock lock(mutex_);
  return max_undos_;
}

void BufferManager::clear_checkpoints() {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_no_locks_locked("clear checkpoints");
  if (working_dirty_)
    checkpoint_locked();
  history_.assign(1, working_state_);
  redo_history_.clear();
}

bool BufferManager::modified_since_snapshot() const {
  std::scoped_lock lock(mutex_);
  return modified_since_snapshot_;
}

void BufferManager::mark_snapshot_complete() {
  std::scoped_lock lock(mutex_);
  modified_since_snapshot_ = false;
}

void BufferManager::write_recovery_snapshot(RecoveryFile &recovery,
                                            const TaskContext &task) const {
  State snapshot_state;
  std::filesystem::path source_path;
  std::int64_t source_file_id = 0;
  std::int32_t source_index_count = 0;
  std::int32_t buffer_size = 0;
  {
    std::scoped_lock lock(mutex_);
    require_healthy_locked();
    require_no_locks_locked("take recovery snapshot");
    if (!source_file_) {
      throw std::logic_error("recovery snapshot requires a source file");
    }
    if (working_dirty_) {
      throw std::logic_error("recovery snapshot requires a checkpoint");
    }
    snapshot_state = working_state_;
    source_path = source_file_->path();
    source_file_id = source_file_->file_id();
    source_index_count = source_index_count_;
    buffer_size = buffer_size_;
  }

  // The public caller holds recovery_mutex_, so mutations cannot publish while
  // this immutable State is serialized. A separate source handle avoids both
  // holding the manager mutex across I/O and sharing one seekable stream with
  // get_buffer(), which remains available for concurrent reads.
  LocalBufferFile snapshot_source(source_path,
                                  LocalBufferFile::OpenMode::read_only);
  if (snapshot_source.file_id() != source_file_id ||
      snapshot_source.index_count() != source_index_count ||
      snapshot_source.buffer_size() != buffer_size) {
    throw std::runtime_error("recovery snapshot source identity changed");
  }
  const auto source_free_indexes = snapshot_source.free_indexes();

  const auto resolve_snapshot_bytes = [&](std::int32_t id) {
    const auto overlay = snapshot_state.overlay.find(id);
    if (overlay != snapshot_state.overlay.end())
      return *overlay->second;
    if (id < 0 || id >= source_index_count) {
      throw std::runtime_error("snapshot buffer has no source payload");
    }
    DataBuffer source_buffer;
    snapshot_source.get(source_buffer, id);
    if (source_buffer.empty() || !source_buffer.has_data()) {
      throw std::runtime_error("snapshot source buffer is unexpectedly empty");
    }
    return source_buffer.bytes();
  };

  auto obsolete = recovery.buffer_indexes();
  recovery.set_index_count(snapshot_state.indexes.index_count());
  recovery.set_free_indexes(snapshot_state.indexes.free_indexes());
  const auto total = static_cast<std::uint64_t>(
      (std::max)(snapshot_state.indexes.index_count(), 0));
  task.report("recovery-snapshot", 0, total);

  for (std::int32_t id = 0; id < snapshot_state.indexes.index_count(); ++id) {
    if (snapshot_state.indexes.is_free(id)) {
      task.report("recovery-snapshot", static_cast<std::uint64_t>(id) + 1,
                  total);
      continue;
    }
    const auto current = resolve_snapshot_bytes(id);
    bool differs =
        id >= source_index_count ||
        source_free_indexes.end() != (std::find)(source_free_indexes.begin(),
                                                 source_free_indexes.end(), id);
    if (!differs) {
      DataBuffer source;
      snapshot_source.get(source, id);
      differs =
          source.empty() || !source.has_data() || source.bytes() != current;
    }

    const auto prior = (std::find)(obsolete.begin(), obsolete.end(), id);
    if (differs) {
      bool write = prior == obsolete.end();
      if (!write) {
        DataBuffer old;
        write = !recovery.get_buffer(old, id) || old.empty() ||
                !old.has_data() || old.bytes() != current;
      }
      if (write) {
        DataBuffer buffer(current);
        buffer.set_id(id);
        recovery.put_buffer(buffer);
      }
    } else if (prior != obsolete.end()) {
      recovery.remove_buffer(id);
    }
    if (prior != obsolete.end())
      obsolete.erase(prior);
    task.report("recovery-snapshot", static_cast<std::uint64_t>(id) + 1, total);
  }
  for (const auto id : obsolete) {
    task.checkpoint();
    recovery.remove_buffer(id);
  }
}

void BufferManager::apply_recovery(RecoveryFile &recovery,
                                   std::int32_t recovery_index,
                                   const TaskContext &task) {
  (void)recovery_index;
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  require_no_locks_locked("recover");
  if (!source_file_ || working_state_.revision != 0 || working_dirty_) {
    throw std::logic_error("recovery requires an unchanged source state");
  }

  try {
    State recovered_state;
    recovered_state.indexes =
        IndexProvider(recovery.index_count(), recovery.free_indexes());
    const auto recovered_indexes = recovery.buffer_indexes();
    const auto total = static_cast<std::uint64_t>(
        recovered_indexes.size() +
        static_cast<std::size_t>((std::max)(recovery.index_count(), 0)));
    std::uint64_t completed = 0;
    task.report("recovery-apply", completed, total);
    for (const auto id : recovered_indexes) {
      DataBuffer buffer;
      if (!recovery.get_buffer(buffer, id) || buffer.empty() ||
          !buffer.has_data() ||
          buffer.size() != static_cast<std::size_t>(buffer_size_)) {
        throw std::runtime_error("invalid recovered buffer payload");
      }
      recovered_state.overlay[id] =
          std::make_shared<const std::vector<std::uint8_t>>(buffer.bytes());
      task.report("recovery-apply", ++completed, total);
    }

    for (std::int32_t id = 0; id < recovered_state.indexes.index_count();
         ++id) {
      if (recovered_state.indexes.is_free(id) ||
          recovered_state.overlay.contains(id)) {
        task.report("recovery-apply", ++completed, total);
        continue;
      }
      const bool source_live =
          id < source_index_count_ &&
          (std::find)(source_file_->free_indexes().begin(),
                      source_file_->free_indexes().end(),
                      id) == source_file_->free_indexes().end();
      if (!source_live) {
        throw std::runtime_error(
            "recovery has a live buffer without source or snapshot data");
      }
      task.report("recovery-apply", ++completed, total);
    }

    task.checkpoint();
    if (next_revision_ == 0) {
      throw std::overflow_error("BufferManager revision space exhausted");
    }
    recovered_state.revision = next_revision_++;
    working_state_ = recovered_state;
    history_.push_back(working_state_);
    trim_history_locked();
    redo_history_.clear();
    working_dirty_ = false;
    modified_since_snapshot_ = false;
    modification_count_ +=
        recovered_indexes.size() + recovery.free_indexes().size();
  } catch (...) {
    corrupted_ = true;
    throw;
  }
}

bool BufferManager::take_recovery_snapshot(
    const std::optional<std::filesystem::path> &change_set_file,
    const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  {
    std::scoped_lock lock(mutex_);
    require_healthy_locked();
    require_no_locks_locked("take recovery snapshot");
    if (!source_file_) {
      throw std::logic_error("recovery snapshot requires a source file");
    }
    if (working_dirty_)
      return false;
  }
  if (!recovery_manager_) {
    recovery_manager_ = std::make_unique<RecoveryManager>(
        *this, RecoveryManager::OpenMode::snapshots_only, TaskContext{},
        recovery_file_operations_);
  }
  return recovery_manager_->take_snapshot(change_set_file, task);
}

bool BufferManager::take_recovery_snapshot(DatabaseChangeSet &change_set,
                                           const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  {
    std::scoped_lock lock(mutex_);
    require_healthy_locked();
    require_no_locks_locked("take recovery snapshot");
    if (!source_file_) {
      throw std::logic_error("recovery snapshot requires a source file");
    }
    if (working_dirty_)
      return false;
  }
  task.checkpoint();
  if (!recovery_manager_) {
    recovery_manager_ = std::make_unique<RecoveryManager>(
        *this, RecoveryManager::OpenMode::snapshots_only, TaskContext{},
        recovery_file_operations_);
  }
  return recovery_manager_->take_snapshot(change_set, task);
}

bool BufferManager::recover(const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  {
    std::scoped_lock lock(mutex_);
    if (!source_file_ || working_state_.revision != 0 || working_dirty_ ||
        !locked_.empty() || corrupted_ || recovery_manager_) {
      return false;
    }
  }
  auto recovery = std::make_unique<RecoveryManager>(
      *this, RecoveryManager::OpenMode::recover_existing, task,
      recovery_file_operations_);
  const auto result = recovery->recovered();
  recovery_manager_ = std::move(recovery);
  return result;
}

void BufferManager::clear_recovery_files() {
  std::scoped_lock recovery_lock(recovery_mutex_);
  {
    std::scoped_lock lock(mutex_);
    if (!source_file_ || working_state_.revision != 0 || working_dirty_ ||
        !locked_.empty()) {
      return;
    }
  }
  if (recovery_manager_)
    recovery_manager_->clear();
  else {
    RecoveryManager cleanup(*this, RecoveryManager::OpenMode::snapshots_only,
                            TaskContext{}, recovery_file_operations_);
  }
  recovery_manager_.reset();
}

bool BufferManager::can_recover() const {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::shared_ptr<LocalBufferFile> source;
  {
    std::scoped_lock lock(mutex_);
    source = source_file_;
  }
  return source && !source->closed() &&
         RecoveryManager::can_recover(*source, recovery_file_operations_);
}

std::optional<std::filesystem::path>
BufferManager::recovery_change_set_path() const {
  std::scoped_lock recovery_lock(recovery_mutex_);
  if (!recovery_manager_)
    return std::nullopt;
  return recovery_manager_->recovery_change_set_path();
}

void BufferManager::read_recovery_change_set(DatabaseChangeSet &change_set,
                                             const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  if (!recovery_manager_) {
    throw std::logic_error("no recovery state is available");
  }
  recovery_manager_->read_change_set(change_set, task);
}

std::int32_t BufferManager::parameter(const std::string &name) const {
  std::scoped_lock lock(mutex_);
  const auto found = parameters_.find(name);
  if (found == parameters_.end()) {
    throw std::out_of_range("BufferManager parameter not found: " + name);
  }
  return found->second;
}

void BufferManager::set_parameter(std::string name, std::int32_t value) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  parameters_[std::move(name)] = value;
}

std::vector<std::string> BufferManager::parameter_names() const {
  std::scoped_lock lock(mutex_);
  std::vector<std::string> result;
  result.reserve(parameters_.size());
  for (const auto &[name, value] : parameters_) {
    (void)value;
    result.push_back(name);
  }
  return result;
}

void BufferManager::rebaseline_locked(
    std::shared_ptr<LocalBufferFile> new_source) {
  source_file_ = std::move(new_source);
  source_index_count_ = source_file_->index_count();
  working_state_.overlay.clear();
  working_state_.revision = 0;
  history_.assign(1, working_state_);
  redo_history_.clear();
  working_dirty_ = false;
  modified_since_snapshot_ = false;
  next_revision_ = 1;
}

bool BufferManager::can_save() const {
  std::scoped_lock lock(mutex_);
  const auto managed =
      std::dynamic_pointer_cast<LocalManagedBufferFile>(source_file_);
  return !corrupted_ && managed && managed->can_save();
}

void BufferManager::write_to_destination_locked(
    const std::shared_ptr<LocalBufferFile> &destination, bool make_read_only,
    const TaskContext &task, std::string_view operation) {
  if (!destination || destination->closed() || destination->read_only()) {
    throw std::invalid_argument("BufferManager destination is not writable");
  }
  if (destination->buffer_size() != buffer_size_) {
    throw std::invalid_argument(
        "BufferManager destination buffer size differs");
  }

  const auto index_count = working_state_.indexes.index_count();
  const auto pre_save_count = destination->index_count();
  const auto total = static_cast<std::uint64_t>((std::max)(index_count, 0));
  task.report(operation, 0, total);

  for (std::int32_t id = 0; id < index_count; ++id) {
    if (working_state_.indexes.is_free(id)) {
      // A completed managed pre-save already contains every old block.  Only
      // extend it for newly allocated free indexes; set_free_indexes() below
      // rewrites the final free chain and records newly freed old blocks.
      if (id >= pre_save_count) {
        destination->put_free_block(id, -1);
      }
    } else if (id >= pre_save_count || working_state_.overlay.contains(id)) {
      DataBuffer buffer(resolve_bytes_locked(id));
      buffer.set_id(id);
      destination->put(buffer, id);
    }
    task.report(operation, static_cast<std::uint64_t>(id) + 1, total);
  }
  task.checkpoint();
  if (destination->index_count() > index_count) {
    destination->truncate(index_count);
  }
  destination->set_free_indexes(working_state_.indexes.free_indexes());
  destination->clear_parameters();
  for (const auto &[name, value] : parameters_) {
    task.checkpoint();
    destination->set_parameter(name, value);
  }
  // This is the final cancellable boundary.  Managed save_completed(true) and
  // save-as set_read_only() publish durable state and must not subsequently
  // report cancellation to the caller.
  task.checkpoint();
  if (make_read_only && !destination->set_read_only()) {
    throw std::runtime_error("unable to finalize BufferManager destination");
  }
}

void BufferManager::save(const std::string &comment, const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  require_no_locks_locked("save");
  auto managed =
      std::dynamic_pointer_cast<LocalManagedBufferFile>(source_file_);
  if (!managed)
    throw std::logic_error("managed save is not available");
  auto destination = managed->get_save_file(task);
  if (!destination)
    throw std::logic_error("managed save is not available");
  bool committed = false;
  try {
    destination->set_version_comment(comment);
    write_to_destination_locked(destination, false, task, "buffer-save");
    managed->save_completed(true);
    committed = true;
    rebaseline_locked(destination);
  } catch (...) {
    if (!committed && managed->save_in_progress()) {
      try {
        managed->save_completed(false);
      } catch (...) {
      }
    }
    throw;
  }
}

void BufferManager::save(const std::string &comment,
                         DatabaseChangeSet &change_set,
                         const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  require_no_locks_locked("save");
  auto managed =
      std::dynamic_pointer_cast<LocalManagedBufferFile>(source_file_);
  if (!managed)
    throw std::logic_error("managed save is not available");
  auto destination = managed->get_save_file(task);
  if (!destination)
    throw std::logic_error("managed save is not available");
  bool committed = false;
  try {
    destination->set_version_comment(comment);
    write_to_destination_locked(destination, false, task, "buffer-save");
    auto change_file = managed->get_save_change_data_file();
    if (change_file)
      write_database_change_set(change_set, change_file, false, task);
    managed->save_completed(true);
    committed = true;
    rebaseline_locked(destination);
  } catch (...) {
    if (!committed && managed->save_in_progress()) {
      try {
        managed->save_completed(false);
      } catch (...) {
      }
    }
    throw;
  }
}

void BufferManager::save_as(const std::shared_ptr<LocalBufferFile> &destination,
                            bool associate_with_new_file,
                            const TaskContext &task) {
  std::scoped_lock recovery_lock(recovery_mutex_);
  std::scoped_lock lock(mutex_);
  require_healthy_locked();
  require_no_locks_locked("save_as");
  if (!destination || destination->closed() || destination->read_only()) {
    throw std::invalid_argument("BufferManager destination is not writable");
  }
  if (destination->buffer_size() != buffer_size_) {
    throw std::invalid_argument(
        "BufferManager destination buffer size differs");
  }
  if (destination->index_count() != 0) {
    throw std::invalid_argument(
        "BufferManager save_as requires an empty destination");
  }

  try {
    write_to_destination_locked(destination, true, task, "buffer-save-as");
    if (associate_with_new_file) {
      rebaseline_locked(destination);
    }
  } catch (...) {
    discard_destination_noexcept(destination);
    throw;
  }
}

void BufferManager::set_corrupted_state() noexcept {
  std::scoped_lock lock(mutex_);
  corrupted_ = true;
}

bool BufferManager::corrupted() const {
  std::scoped_lock lock(mutex_);
  return corrupted_;
}

} // namespace llmghidra::db
