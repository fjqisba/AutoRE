/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/recovery_file.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <set>
#include <stdexcept>
#include <string_view>

namespace llmghidra::db {

std::int64_t RecoveryFile::join_id(std::int32_t high,
                                   std::int32_t low) noexcept {
  const auto bits = (static_cast<std::uint64_t>(
                         std::bit_cast<std::uint32_t>(high))
                     << 32) |
                    std::bit_cast<std::uint32_t>(low);
  return std::bit_cast<std::int64_t>(bits);
}

void RecoveryFile::store_id(LocalBufferFile &file, const char *high_parameter,
                            const char *low_parameter, std::int64_t value) {
  const auto bits = std::bit_cast<std::uint64_t>(value);
  file.set_parameter(high_parameter, std::bit_cast<std::int32_t>(
      static_cast<std::uint32_t>(bits >> 32)));
  file.set_parameter(low_parameter, std::bit_cast<std::int32_t>(
      static_cast<std::uint32_t>(bits)));
}

RecoveryFile::RecoveryFile(LocalBufferFile &source, std::filesystem::path path,
                           bool create,
                           std::shared_ptr<FileOperations> file_operations)
    : path_(std::move(path)), source_file_id_(source.file_id()),
      index_count_(source.index_count()) {
  if (create) {
    file_ = std::make_unique<LocalBufferFile>(path_, source.buffer_size(),
                                              std::move(file_operations));
    file_->set_parameter(magic_parameter, magic_number);
    file_->set_parameter(valid_parameter, 0);
    store_id(*file_, source_id_high_parameter, source_id_low_parameter,
             source_file_id_);
    modified_ = true;
    return;
  }

  file_ = std::make_unique<LocalBufferFile>(
      path_, LocalBufferFile::OpenMode::read_write, std::move(file_operations));
  if (file_->parameter(valid_parameter) != 1) {
    throw std::runtime_error("cannot update invalid RecoveryFile");
  }
  valid_ = true;
  parse();
  if (source_file_id_ != source.file_id()) {
    throw std::runtime_error("RecoveryFile source identity mismatch");
  }
  storage_indexes_ = IndexProvider(file_->index_count(), file_->free_indexes());
}

RecoveryFile::RecoveryFile(LocalBufferFile &source, std::filesystem::path path,
                           std::shared_ptr<FileOperations> file_operations)
    : path_(std::move(path)), read_only_(true) {
  file_ = std::make_unique<LocalBufferFile>(
      path_, LocalBufferFile::OpenMode::read_only, std::move(file_operations));
  parse();
  valid_ = file_->parameter(valid_parameter) == 1 &&
           source_file_id_ == source.file_id();
}

RecoveryFile::~RecoveryFile() {
  abort();
}

void RecoveryFile::require_open() const {
  if (!file_) throw std::logic_error("RecoveryFile is closed");
}

void RecoveryFile::require_writable() const {
  require_open();
  if (read_only_) throw std::logic_error("RecoveryFile is read-only");
}

void RecoveryFile::set_modified() {
  require_writable();
  if (valid_) {
    file_->set_parameter(valid_parameter, 0);
    valid_ = false;
  }
  modified_ = true;
}

std::int32_t RecoveryFile::allocate_storage() {
  return storage_indexes_.allocate();
}

void RecoveryFile::parse() {
  require_open();
  if (file_->parameter(magic_parameter) != magic_number) {
    throw std::runtime_error("invalid RecoveryFile magic");
  }
  source_file_id_ = join_id(file_->parameter(source_id_high_parameter),
                            file_->parameter(source_id_low_parameter));
  index_count_ = file_->parameter(index_count_parameter);
  if (index_count_ < 0) throw std::runtime_error("negative recovery index count");
  try {
    timestamp_ = join_id(file_->parameter(timestamp_high_parameter),
                         file_->parameter(timestamp_low_parameter));
  }
  catch (const std::out_of_range &) {
    const auto file_time = std::filesystem::last_write_time(path_);
    const auto system_time =
        std::chrono::time_point_cast<std::chrono::milliseconds>(
            file_time - std::filesystem::file_time_type::clock::now() +
            std::chrono::system_clock::now());
    timestamp_ = system_time.time_since_epoch().count();
  }
  read_buffer_map();
  read_free_index_list();
  validate_storage_layout();
}

void RecoveryFile::read_buffer_map() {
  buffer_map_.clear();
  map_block_indexes_.clear();
  map_index_ = file_->parameter(map_index_parameter);
  auto current = map_index_;
  std::set<std::int32_t> chain;
  const auto maximum = static_cast<std::size_t>(
      (file_->buffer_size() - static_cast<std::int32_t>(map_entry_size)) & ~7);
  DataBuffer buffer;
  while (true) {
    if (current < 0 || current >= file_->index_count() ||
        !chain.insert(current).second) {
      throw std::runtime_error("corrupt RecoveryFile buffer map chain");
    }
    map_block_indexes_.push_back(current);
    file_->get(buffer, current);
    if (buffer.empty()) throw std::runtime_error("empty RecoveryFile map block");
    auto offset = first_entry_offset;
    while (offset <= maximum) {
      const auto real = buffer.get_i32(offset);
      if (real < 0) return;
      const auto stored = buffer.get_i32(offset + 4);
      if (real >= index_count_ || stored < 0 || stored >= file_->index_count() ||
          !buffer_map_.emplace(real, stored).second) {
        throw std::runtime_error("corrupt RecoveryFile buffer map entry");
      }
      offset += map_entry_size;
    }
    current = buffer.get_i32(next_buffer_offset);
  }
}

void RecoveryFile::read_free_index_list() {
  free_list_index_ = file_->parameter(free_list_index_parameter);
  const auto count = file_->parameter(free_list_size_parameter);
  if (count < 0 || count > index_count_) {
    throw std::runtime_error("corrupt RecoveryFile free-list size");
  }
  free_indexes_.clear();
  free_list_block_indexes_.clear();
  free_indexes_.reserve(static_cast<std::size_t>(count));
  auto current = free_list_index_;
  std::set<std::int32_t> chain;
  const auto maximum = static_cast<std::size_t>(
      (file_->buffer_size() - static_cast<std::int32_t>(free_entry_size)) & ~3);
  DataBuffer buffer;
  while (true) {
    if (current < 0 || current >= file_->index_count() ||
        !chain.insert(current).second) {
      throw std::runtime_error("corrupt RecoveryFile free-list chain");
    }
    free_list_block_indexes_.push_back(current);
    file_->get(buffer, current);
    if (buffer.empty()) throw std::runtime_error("empty RecoveryFile free-list block");
    auto offset = first_entry_offset;
    while (offset <= maximum) {
      const auto index = buffer.get_i32(offset);
      if (index < 0) {
        if (free_indexes_.size() != static_cast<std::size_t>(count)) {
          throw std::runtime_error("RecoveryFile free-list count mismatch");
        }
        (std::sort)(free_indexes_.begin(), free_indexes_.end());
        if ((std::adjacent_find)(free_indexes_.begin(), free_indexes_.end()) !=
            free_indexes_.end()) {
          throw std::runtime_error("duplicate RecoveryFile free index");
        }
        return;
      }
      if (index >= index_count_ ||
          free_indexes_.size() == static_cast<std::size_t>(count)) {
        throw std::runtime_error("corrupt RecoveryFile free-list entry");
      }
      free_indexes_.push_back(index);
      offset += free_entry_size;
    }
    current = buffer.get_i32(next_buffer_offset);
  }
}

void RecoveryFile::validate_storage_layout() {
  std::set<std::int32_t> metadata;
  for (const auto index : map_block_indexes_) {
    if (!metadata.insert(index).second) {
      throw std::runtime_error("duplicate RecoveryFile metadata block");
    }
  }
  for (const auto index : free_list_block_indexes_) {
    if (!metadata.insert(index).second) {
      throw std::runtime_error("overlapping RecoveryFile metadata chains");
    }
  }

  const std::set<std::int32_t> physically_free(file_->free_indexes().begin(),
                                                file_->free_indexes().end());
  for (const auto index : metadata) {
    if (physically_free.contains(index)) {
      throw std::runtime_error("RecoveryFile metadata block is physically free");
    }
  }

  const std::set<std::int32_t> logically_free(free_indexes_.begin(),
                                               free_indexes_.end());
  std::set<std::int32_t> stored_indexes;
  DataBuffer stored;
  for (const auto &[logical, physical] : buffer_map_) {
    if (logically_free.contains(logical)) {
      throw std::runtime_error("RecoveryFile maps a logically free buffer");
    }
    if (!stored_indexes.insert(physical).second || metadata.contains(physical) ||
        physically_free.contains(physical)) {
      throw std::runtime_error("overlapping RecoveryFile storage block");
    }
    file_->get(stored, physical);
    if (!stored.empty() && stored.id() != logical) {
      throw std::runtime_error("RecoveryFile stored buffer ID mismatch");
    }
  }
}

void RecoveryFile::set_index_count(std::int32_t count) {
  require_writable();
  if (count < 0) throw std::invalid_argument("negative recovery index count");
  set_modified();
  for (auto index = index_count_; index < count; ++index) remove_buffer(index);
  index_count_ = count;
}

void RecoveryFile::set_free_indexes(std::span<const std::int32_t> indexes) {
  require_writable();
  std::vector<std::int32_t> validated(indexes.begin(), indexes.end());
  (std::sort)(validated.begin(), validated.end());
  for (std::size_t i = 0; i < validated.size(); ++i) {
    if (validated[i] < 0 || validated[i] >= index_count_ ||
        (i != 0 && validated[i] == validated[i - 1])) {
      throw std::invalid_argument("invalid recovery free indexes");
    }
  }
  set_modified();
  free_indexes_ = std::move(validated);
  for (const auto index : free_indexes_) remove_buffer(index);
}

void RecoveryFile::put_buffer(const DataBuffer &buffer) {
  require_writable();
  const auto id = buffer.id();
  if (id < 0 || id >= index_count_) {
    throw std::invalid_argument("invalid recovery buffer");
  }
  set_modified();
  auto found = buffer_map_.find(id);
  if (found == buffer_map_.end()) {
    found = buffer_map_.emplace(id, allocate_storage()).first;
  }
  file_->put(buffer, found->second);
}

void RecoveryFile::remove_buffer(std::int32_t id) {
  require_writable();
  set_modified();
  const auto found = buffer_map_.find(id);
  if (found == buffer_map_.end()) return;
  storage_indexes_.free(found->second);
  buffer_map_.erase(found);
}

bool RecoveryFile::get_buffer(DataBuffer &buffer, std::int32_t id) {
  require_open();
  const auto found = buffer_map_.find(id);
  if (found == buffer_map_.end()) return false;
  file_->get(buffer, found->second);
  buffer.set_id(id);
  return true;
}

std::vector<std::int32_t> RecoveryFile::buffer_indexes() const {
  std::vector<std::int32_t> result;
  result.reserve(buffer_map_.size());
  for (const auto &[id, stored] : buffer_map_) {
    (void)stored;
    result.push_back(id);
  }
  return result;
}

void RecoveryFile::save_buffer_map() {
  DataBuffer buffer(static_cast<std::size_t>(file_->buffer_size()));
  if (map_index_ < 0) {
    map_index_ = allocate_storage();
    buffer.set_id(map_index_);
    buffer.put_i32(next_buffer_offset, -1);
    file_->set_parameter(map_index_parameter, map_index_);
  }
  else file_->get(buffer, map_index_);
  auto current = map_index_;
  auto offset = first_entry_offset;
  const auto maximum = static_cast<std::size_t>(
      (file_->buffer_size() - static_cast<std::int32_t>(map_entry_size)) & ~7);
  auto entry = buffer_map_.begin();
  while (true) {
    if (offset > maximum) {
      auto next = buffer.get_i32(next_buffer_offset);
      const bool allocated = next < 0;
      if (allocated) next = allocate_storage();
      buffer.put_i32(next_buffer_offset, next);
      file_->put(buffer, current);
      current = next;
      if (allocated) {
        buffer.set_id(current);
        buffer.put_i32(next_buffer_offset, -1);
      }
      else file_->get(buffer, current);
      offset = first_entry_offset;
    }
    if (entry == buffer_map_.end()) {
      buffer.put_i32(offset, -1);
      file_->put(buffer, current);
      return;
    }
    offset = buffer.put_i32(offset, entry->first);
    offset = buffer.put_i32(offset, entry->second);
    ++entry;
  }
}

void RecoveryFile::save_free_index_list() {
  DataBuffer buffer(static_cast<std::size_t>(file_->buffer_size()));
  if (free_list_index_ < 0) {
    free_list_index_ = allocate_storage();
    buffer.set_id(free_list_index_);
    buffer.put_i32(next_buffer_offset, -1);
    file_->set_parameter(free_list_index_parameter, free_list_index_);
  }
  else file_->get(buffer, free_list_index_);
  file_->set_parameter(free_list_size_parameter,
                       static_cast<std::int32_t>(free_indexes_.size()));
  auto current = free_list_index_;
  auto offset = first_entry_offset;
  const auto maximum = static_cast<std::size_t>(
      (file_->buffer_size() - static_cast<std::int32_t>(free_entry_size)) & ~3);
  std::size_t entry = 0;
  while (true) {
    if (offset > maximum) {
      auto next = buffer.get_i32(next_buffer_offset);
      const bool allocated = next < 0;
      if (allocated) next = allocate_storage();
      buffer.put_i32(next_buffer_offset, next);
      file_->put(buffer, current);
      current = next;
      if (allocated) {
        buffer.set_id(current);
        buffer.put_i32(next_buffer_offset, -1);
      }
      else file_->get(buffer, current);
      offset = first_entry_offset;
    }
    const auto value = entry == free_indexes_.size() ? -1 : free_indexes_[entry++];
    offset = buffer.put_i32(offset, value);
    if (value < 0) {
      file_->put(buffer, current);
      return;
    }
  }
}

std::vector<std::string> RecoveryFile::user_parameter_names() const {
  require_open();
  std::vector<std::string> result;
  for (const auto &name : file_->parameter_names()) {
    if (!std::string_view(name).starts_with(parameter_prefix)) result.push_back(name);
  }
  return result;
}

std::int32_t RecoveryFile::parameter(const std::string &name) const {
  require_open();
  return file_->parameter(name);
}

void RecoveryFile::clear_parameters() {
  require_writable();
  set_modified();
  std::map<std::string, std::int32_t> internal;
  for (const auto &name : file_->parameter_names()) {
    if (std::string_view(name).starts_with(parameter_prefix)) {
      internal.emplace(name, file_->parameter(name));
    }
  }
  file_->clear_parameters();
  for (const auto &[name, value] : internal) file_->set_parameter(name, value);
}

void RecoveryFile::set_parameter(std::string name, std::int32_t value) {
  require_writable();
  set_modified();
  file_->set_parameter(std::move(name), value);
}

void RecoveryFile::close() {
  if (!file_) return;
  try {
    if (!read_only_ && modified_ && !file_->read_only()) {
      save_buffer_map();
      save_free_index_list();
      file_->set_parameter(index_count_parameter, index_count_);
      file_->set_free_indexes(storage_indexes_.free_indexes());
      timestamp_ = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
      store_id(*file_, timestamp_high_parameter, timestamp_low_parameter,
               timestamp_);
      file_->set_parameter(valid_parameter, 1);
      valid_ = true;
    }
    file_->close();
    file_.reset();
  }
  catch (...) {
    abort();
    throw;
  }
}

void RecoveryFile::abort() noexcept {
  if (!file_) return;
  try {
    if (read_only_ || file_->read_only() || !modified_) {
      file_->close();
    }
    else {
      (void)file_->delete_file();
    }
  }
  catch (...) {
  }
  file_.reset();
  valid_ = false;
}

} // namespace llmghidra::db
