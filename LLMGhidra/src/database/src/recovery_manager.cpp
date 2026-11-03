/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/recovery_manager.hpp"

#include "llmghidra/db/buffer_manager.hpp"
#include "llmghidra/db/database_change_set.hpp"
#include "llmghidra/db/recovery_file.hpp"

#include <chrono>
#include <stdexcept>
#include <thread>

namespace llmghidra::db {
namespace {

constexpr const char *snapshot_names[2] = {"snapshotA.grf", "snapshotB.grf"};
constexpr const char *change_names[2] = {"changeA.grf", "changeB.grf"};
constexpr const char *change_set_required_parameter = "";

void remove_path(const FileOperations &operations,
                 const std::filesystem::path &path) noexcept {
  std::error_code error;
  const bool removed = operations.remove(path, error);
  if (!removed || error)
    return;
  try {
    operations.sync_parent_directory(path);
  } catch (...) {
  }
}

void sync_file_and_parent(const FileOperations &operations,
                          const std::filesystem::path &path) {
  auto handle =
      operations.open_random_access(path, RandomAccessOpenMode::read_write);
  std::exception_ptr failure;
  try {
    handle->sync();
  } catch (...) {
    failure = std::current_exception();
  }
  try {
    handle->close();
  } catch (...) {
    if (!failure)
      failure = std::current_exception();
  }
  if (failure)
    std::rethrow_exception(failure);
  operations.sync_parent_directory(path);
}

bool is_regular_file(const FileOperations &operations,
                     const std::filesystem::path &path) {
  std::error_code error;
  const auto status = operations.symlink_status(path, error);
  if (error == std::errc::no_such_file_or_directory)
    return false;
  if (error)
    throw std::filesystem::filesystem_error(
        "unable to inspect recovery artifact", path, error);
  return std::filesystem::is_regular_file(status);
}

} // namespace

std::array<std::filesystem::path, 2>
RecoveryManager::snapshot_paths_for(const LocalBufferFile &source) {
  const auto directory = source.path().parent_path();
  return {directory / snapshot_names[0], directory / snapshot_names[1]};
}

std::array<std::filesystem::path, 2>
RecoveryManager::change_paths_for(const LocalBufferFile &source) {
  const auto directory = source.path().parent_path();
  return {directory / change_names[0], directory / change_names[1]};
}

bool RecoveryManager::change_set_required(const RecoveryFile &recovery) {
  try {
    return recovery.parameter(change_set_required_parameter) != 0;
  } catch (const std::out_of_range &) {
    return false;
  }
}

RecoveryManager::Selection RecoveryManager::select_recovery(
    LocalBufferFile &source, const std::array<std::filesystem::path, 2> &paths,
    const std::shared_ptr<FileOperations> &file_operations) {
  std::array<std::unique_ptr<RecoveryFile>, 2> candidates;
  std::array<std::int64_t, 2> timestamps{};
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    try {
      if (!is_regular_file(*file_operations, paths[index]))
        continue;
      auto candidate =
          std::make_unique<RecoveryFile>(source, paths[index], file_operations);
      if (candidate->valid()) {
        timestamps[index] = candidate->timestamp();
        candidates[index] = std::move(candidate);
      }
    } catch (const std::exception &) {
    }
  }

  if (candidates[0] && candidates[1]) {
    if (timestamps[0] == timestamps[1])
      return {};
    const auto selected = timestamps[1] > timestamps[0] ? 1 : 0;
    return {selected,
            std::move(candidates[static_cast<std::size_t>(selected)])};
  }
  if (candidates[0])
    return {0, std::move(candidates[0])};
  if (candidates[1])
    return {1, std::move(candidates[1])};
  return {};
}

RecoveryManager::RecoveryManager(
    BufferManager &buffer_manager, OpenMode mode, const TaskContext &task,
    std::shared_ptr<FileOperations> file_operations)
    : buffer_manager_(buffer_manager),
      file_operations_(file_operations ? std::move(file_operations)
                                       : std::make_shared<FileOperations>()) {
  auto source = buffer_manager_.source_file();
  if (!source || source->closed()) {
    throw std::logic_error("recovery requires an open LocalBufferFile source");
  }
  snapshot_paths_ = snapshot_paths_for(*source);
  change_paths_ = change_paths_for(*source);

  // RecoveryManager owns these private slots under the database/project lock.
  // Resolve interrupted LocalBufferFile publication before selecting or
  // reusing a slot; ordinary LocalBufferFile open deliberately refuses to
  // guess whether a marker belongs to a live writer.
  for (const auto &path : snapshot_paths_)
    (void)LocalBufferFile::recover_pending_publication(path, file_operations_);
  for (const auto &path : change_paths_)
    (void)LocalBufferFile::recover_pending_publication(path, file_operations_);

  if (mode == OpenMode::snapshots_only) {
    clear();
    return;
  }

  auto selected = select_recovery(*source, snapshot_paths_, file_operations_);
  if (selected.file) {
    snapshot_index_ = selected.index;
    last_snapshot_time_ = selected.file->timestamp();
    recovery_has_change_set_ = change_set_required(*selected.file);
    if (!recovery_has_change_set_ ||
        is_regular_file(
            *file_operations_,
            change_paths_[static_cast<std::size_t>(snapshot_index_)])) {
      buffer_manager_.apply_recovery(*selected.file, snapshot_index_, task);
      recovered_ = true;
    }
  }

  for (std::size_t index = 0; index < snapshot_paths_.size(); ++index) {
    if (static_cast<std::int32_t>(index) != snapshot_index_)
      delete_slot(index);
  }
}

RecoveryManager::~RecoveryManager() = default;

std::optional<std::filesystem::path>
RecoveryManager::recovery_change_set_path() const {
  if (!recovered_ || !recovery_has_change_set_ || snapshot_index_ < 0) {
    return std::nullopt;
  }
  return change_paths_[static_cast<std::size_t>(snapshot_index_)];
}

void RecoveryManager::delete_slot(std::size_t index) noexcept {
  remove_path(*file_operations_, snapshot_paths_.at(index));
  remove_path(*file_operations_, LocalBufferFile::pending_publication_path(
                                     snapshot_paths_.at(index)));
  remove_path(*file_operations_, change_paths_.at(index));
  remove_path(*file_operations_, LocalBufferFile::pending_publication_path(
                                     change_paths_.at(index)));
}

void RecoveryManager::clear() {
  for (std::size_t index = 0; index < snapshot_paths_.size(); ++index) {
    delete_slot(index);
  }
  snapshot_index_ = -1;
  last_snapshot_time_ = 0;
  recovered_ = false;
  recovery_has_change_set_ = false;
}

bool RecoveryManager::take_snapshot_impl(
    bool has_change_set,
    const std::function<void(const std::filesystem::path &)> &materialize,
    const TaskContext &task) {
  auto source = buffer_manager_.source_file();
  if (!source || source->closed()) {
    throw std::logic_error("recovery requires an open LocalBufferFile source");
  }
  task.checkpoint();

  auto next_index = snapshot_index_ + 1;
  if (next_index == 2)
    next_index = 0;
  const auto slot = static_cast<std::size_t>(next_index);
  (void)LocalBufferFile::recover_pending_publication(snapshot_paths_[slot],
                                                     file_operations_);
  (void)LocalBufferFile::recover_pending_publication(change_paths_[slot],
                                                     file_operations_);
  const bool create =
      !is_regular_file(*file_operations_, snapshot_paths_[slot]);

  const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  if (now == last_snapshot_time_) {
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }

  std::unique_ptr<RecoveryFile> recovery;
  try {
    try {
      recovery = std::make_unique<RecoveryFile>(*source, snapshot_paths_[slot],
                                                create, file_operations_);
    } catch (const std::exception &) {
      if (create)
        throw;
      delete_slot(slot);
      recovery = std::make_unique<RecoveryFile>(*source, snapshot_paths_[slot],
                                                true, file_operations_);
    }

    recovery->set_parameter(change_set_required_parameter,
                            has_change_set ? 1 : 0);
    if (has_change_set) {
      task.checkpoint();
      remove_path(*file_operations_, change_paths_[slot]);
      materialize(change_paths_[slot]);
      if (!is_regular_file(*file_operations_, change_paths_[slot])) {
        throw std::runtime_error(
            "change-set materializer did not create a regular file");
      }
    } else {
      remove_path(*file_operations_, change_paths_[slot]);
    }

    task.checkpoint();
    buffer_manager_.write_recovery_snapshot(*recovery, task);
    task.checkpoint();
    recovery->close();
    last_snapshot_time_ = recovery->timestamp();
  } catch (...) {
    if (recovery)
      recovery->abort();
    delete_slot(slot);
    throw;
  }

  snapshot_index_ = next_index;
  recovered_ = false;
  recovery_has_change_set_ = false;
  buffer_manager_.mark_snapshot_complete();
  return true;
}

bool RecoveryManager::take_snapshot(
    const std::optional<std::filesystem::path> &change_set_file,
    const TaskContext &task) {
  if (change_set_file &&
      !is_regular_file(*file_operations_, *change_set_file)) {
    throw std::invalid_argument("recovery change-set file does not exist");
  }
  if (!change_set_file) {
    return take_snapshot_impl(false, {}, task);
  }
  return take_snapshot_impl(
      true,
      [source = *change_set_file, operations = file_operations_](
          const std::filesystem::path &destination) {
        std::error_code error;
        operations->copy_file(source, destination,
                              std::filesystem::copy_options::overwrite_existing,
                              error);
        if (error)
          throw std::filesystem::filesystem_error(
              "unable to copy recovery change set", source, destination, error);
        sync_file_and_parent(*operations, destination);
      },
      task);
}

bool RecoveryManager::take_snapshot(DatabaseChangeSet &change_set,
                                    const TaskContext &task) {
  return take_snapshot_impl(
      true,
      [this, &change_set, &task](const std::filesystem::path &destination) {
        const auto source = buffer_manager_.source_file();
        if (!source || source->closed())
          throw std::logic_error("recovery requires an open source file");
        auto output = std::make_shared<LocalBufferFile>(
            destination, source->buffer_size(), file_operations_);
        write_database_change_set(change_set, output, true, task);
      },
      task);
}

void RecoveryManager::read_change_set(DatabaseChangeSet &change_set,
                                      const TaskContext &task) const {
  const auto path = recovery_change_set_path();
  if (!path)
    throw std::logic_error("no recovered change-set is available");
  read_database_change_set(change_set, *path, task);
}

bool RecoveryManager::can_recover(
    LocalBufferFile &source, std::shared_ptr<FileOperations> file_operations) {
  if (!file_operations)
    file_operations = std::make_shared<FileOperations>();
  const auto snapshots = snapshot_paths_for(source);
  const auto changes = change_paths_for(source);
  auto selected = select_recovery(source, snapshots, file_operations);
  if (!selected.file)
    return false;
  return !change_set_required(*selected.file) ||
         is_regular_file(*file_operations,
                         changes[static_cast<std::size_t>(selected.index)]);
}

} // namespace llmghidra::db
