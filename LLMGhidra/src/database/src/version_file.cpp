/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/version_file.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <set>
#include <stdexcept>
#include <string_view>

namespace llmghidra::db {

std::int64_t VersionFile::join_id(std::int32_t high,
                                  std::int32_t low) noexcept {
  const auto bits = (static_cast<std::uint64_t>(
                         static_cast<std::uint32_t>(high))
                     << 32) |
                    static_cast<std::uint32_t>(low);
  return std::bit_cast<std::int64_t>(bits);
}

void VersionFile::store_id(LocalBufferFile &file, const char *high_parameter,
                           const char *low_parameter, std::int64_t id) {
  const auto bits = std::bit_cast<std::uint64_t>(id);
  file.set_parameter(high_parameter,
                     std::bit_cast<std::int32_t>(
                         static_cast<std::uint32_t>(bits >> 32)));
  file.set_parameter(low_parameter,
                     std::bit_cast<std::int32_t>(
                         static_cast<std::uint32_t>(bits)));
}

VersionFile::VersionFile(LocalBufferFile &original_file,
                         LocalBufferFile &target_file,
                         std::filesystem::path version_path)
    : VersionFile(original_file, target_file,
                  std::make_unique<LocalBufferFile>(
                      std::move(version_path), original_file.buffer_size())) {}

VersionFile::VersionFile(LocalBufferFile &original_file,
                         LocalBufferFile &target_file,
                         std::unique_ptr<LocalBufferFile> version_file)
    : file_(std::move(version_file)), read_only_(false),
      buffer_size_(original_file.buffer_size()),
      original_buffer_count_(original_file.index_count()),
      target_file_id_(target_file.file_id()),
      original_file_id_(original_file.file_id()),
      free_indexes_(original_file.free_indexes()),
      last_map_buffer_(static_cast<std::size_t>(buffer_size_)) {
  if (!file_) {
    throw std::invalid_argument("VersionFile requires an output buffer file");
  }
  path_ = file_->path();
  if (file_->closed() || file_->read_only() ||
      file_->buffer_size() != buffer_size_ || file_->index_count() != 0) {
    throw std::invalid_argument(
        "VersionFile requires an empty writable output buffer file");
  }
  if (buffer_size_ <
      static_cast<std::int32_t>(first_entry_offset + map_entry_size)) {
    throw std::invalid_argument("VersionFile buffer size is too small");
  }
  file_->set_parameter(magic_parameter, magic_number);
  store_id(*file_, original_id_high_parameter, original_id_low_parameter,
           original_file_id_);
  file_->set_parameter(original_count_parameter, original_buffer_count_);

  last_map_index_ = allocate_storage();
  last_map_buffer_.set_id(last_map_index_);
  last_map_buffer_.put_i32(next_buffer_offset, -1);
  last_map_buffer_.put_i32(first_entry_offset, -1);
  file_->put(last_map_buffer_, last_map_index_);
  file_->set_parameter(map_index_parameter, last_map_index_);

  (std::sort)(free_indexes_.begin(), free_indexes_.end());
  const auto free_list_index = save_free_index_list();
  file_->set_parameter(free_list_index_parameter, free_list_index);
  if (free_indexes_.size() >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::length_error("VersionFile free list is too large");
  }
  file_->set_parameter(free_list_size_parameter,
                       static_cast<std::int32_t>(free_indexes_.size()));

  for (const auto &name : original_file.parameter_names()) {
    file_->set_parameter(name, original_file.parameter(name));
  }
}

VersionFile::VersionFile(std::filesystem::path version_path)
    : path_(std::move(version_path)), read_only_(true) {
  open();
}

VersionFile::VersionFile(std::unique_ptr<LocalBufferFile> version_file)
    : file_(std::move(version_file)), read_only_(true) {
  if (!file_) {
    throw std::invalid_argument("VersionFile requires a buffer file");
  }
  path_ = file_->path();
  if (!file_->read_only() || file_->closed()) {
    throw std::invalid_argument(
        "VersionFile requires an open read-only buffer file");
  }
  buffer_size_ = file_->buffer_size();
  if (buffer_size_ <
      static_cast<std::int32_t>(first_entry_offset + map_entry_size)) {
    throw std::runtime_error("corrupt VersionFile buffer size");
  }
  initial_buffer_count_ = file_->index_count();
  try {
    if (file_->parameter(magic_parameter) != magic_number) {
      throw std::runtime_error("corrupt VersionFile magic");
    }
    parse();
  }
  catch (...) {
    file_->close();
    file_.reset();
    throw;
  }
}

VersionFile::~VersionFile() {
  try {
    close();
  }
  catch (...) {
  }
}

void VersionFile::require_open() const {
  if (!file_) throw std::logic_error("VersionFile is closed");
}

void VersionFile::require_writable() const {
  require_open();
  if (read_only_) throw std::logic_error("VersionFile is read-only");
}

std::int32_t VersionFile::allocate_storage() {
  const auto index = storage_indexes_.allocate();
  if (index != storage_indexes_.index_count() - 1) {
    throw std::logic_error("VersionFile storage unexpectedly reused an index");
  }
  return index;
}

std::int32_t VersionFile::save_free_index_list() {
  auto current_index = allocate_storage();
  const auto first_index = current_index;
  DataBuffer buffer(static_cast<std::size_t>(buffer_size_));
  buffer.set_id(current_index);
  auto offset = first_entry_offset;
  const auto maximum_offset =
      static_cast<std::size_t>(buffer_size_) - free_entry_size;
  for (const auto free_index : free_indexes_) {
    if (offset > maximum_offset) {
      const auto next_index = allocate_storage();
      buffer.put_i32(next_buffer_offset, next_index);
      file_->put(buffer, current_index);
      current_index = next_index;
      buffer.set_id(current_index);
      offset = first_entry_offset;
    }
    offset = buffer.put_i32(offset, free_index);
  }
  if (offset > maximum_offset) {
    const auto next_index = allocate_storage();
    buffer.put_i32(next_buffer_offset, next_index);
    file_->put(buffer, current_index);
    current_index = next_index;
    buffer.set_id(current_index);
    offset = first_entry_offset;
  }
  buffer.put_i32(offset, -1);
  buffer.put_i32(next_buffer_offset, -1);
  file_->put(buffer, current_index);
  return first_index;
}

bool VersionFile::accepts_old_buffer(std::int32_t index) const {
  return index >= 0 && index < original_buffer_count_ &&
         !buffer_map_.contains(index) &&
         !std::binary_search(free_indexes_.begin(), free_indexes_.end(), index);
}

void VersionFile::put_old_buffer(const DataBuffer &buffer,
                                 std::int32_t index) {
  require_writable();
  if (!accepts_old_buffer(index)) return;
  const auto storage_index = allocate_storage();
  file_->put(buffer, storage_index);
  buffer_map_.emplace(index, storage_index);
  pending_map_ids_.push_back(index);
}

void VersionFile::update_buffer_map() {
  require_writable();
  const auto maximum_offset =
      static_cast<std::size_t>(buffer_size_) - map_entry_size;
  for (const auto original_index : pending_map_ids_) {
    const auto stored = buffer_map_.find(original_index);
    if (stored == buffer_map_.end()) {
      throw std::logic_error("VersionFile buffer map lost a pending entry");
    }
    if (next_map_entry_offset_ > maximum_offset) {
      const auto next_index = allocate_storage();
      last_map_buffer_.put_i32(next_buffer_offset, next_index);
      file_->put(last_map_buffer_, last_map_index_);
      last_map_index_ = next_index;
      last_map_buffer_.set_id(last_map_index_);
      next_map_entry_offset_ = first_entry_offset;
    }
    next_map_entry_offset_ =
        last_map_buffer_.put_i32(next_map_entry_offset_, original_index);
    next_map_entry_offset_ =
        last_map_buffer_.put_i32(next_map_entry_offset_, stored->second);
  }
  if (next_map_entry_offset_ > maximum_offset) {
    const auto next_index = allocate_storage();
    last_map_buffer_.put_i32(next_buffer_offset, next_index);
    file_->put(last_map_buffer_, last_map_index_);
    last_map_index_ = next_index;
    last_map_buffer_.set_id(last_map_index_);
    next_map_entry_offset_ = first_entry_offset;
  }
  last_map_buffer_.put_i32(next_map_entry_offset_, -1);
  last_map_buffer_.put_i32(next_buffer_offset, -1);
  file_->put(last_map_buffer_, last_map_index_);
  pending_map_ids_.clear();
}

void VersionFile::close() {
  if (!file_) return;
  if (!read_only_) {
    update_buffer_map();
    store_id(*file_, target_id_high_parameter, target_id_low_parameter,
             target_file_id_);
  }
  file_->close();
  file_.reset();
}

void VersionFile::abort() {
  if (!file_) return;
  if (read_only_) {
    file_->close();
  }
  else if (initial_buffer_count_ > 0) {
    file_->truncate(initial_buffer_count_);
    file_->close();
  }
  else if (!file_->delete_file()) {
    throw std::runtime_error("unable to remove aborted VersionFile");
  }
  file_.reset();
  aborted_ = true;
}

void VersionFile::open() {
  if (file_) return;
  if (aborted_) throw std::logic_error("VersionFile was aborted");
  file_ = std::make_unique<LocalBufferFile>(path_,
                                            LocalBufferFile::OpenMode::read_only);
  read_only_ = true;
  buffer_size_ = file_->buffer_size();
  if (buffer_size_ <
      static_cast<std::int32_t>(first_entry_offset + map_entry_size)) {
    file_->close();
    file_.reset();
    throw std::runtime_error("corrupt VersionFile buffer size");
  }
  initial_buffer_count_ = file_->index_count();
  try {
    if (file_->parameter(magic_parameter) != magic_number) {
      throw std::runtime_error("corrupt VersionFile magic");
    }
    parse();
  }
  catch (...) {
    file_->close();
    file_.reset();
    throw;
  }
}

void VersionFile::parse() {
  original_buffer_count_ = file_->parameter(original_count_parameter);
  if (original_buffer_count_ < 0) {
    throw std::runtime_error("corrupt VersionFile original buffer count");
  }
  original_file_id_ = join_id(file_->parameter(original_id_high_parameter),
                              file_->parameter(original_id_low_parameter));
  target_file_id_ = join_id(file_->parameter(target_id_high_parameter),
                            file_->parameter(target_id_low_parameter));
  read_buffer_map(file_->parameter(map_index_parameter));
  read_free_index_list(file_->parameter(free_list_index_parameter),
                       file_->parameter(free_list_size_parameter));
}

void VersionFile::read_buffer_map(std::int32_t map_index) {
  buffer_map_.clear();
  std::set<std::int32_t> chain;
  auto offset = first_entry_offset;
  const auto maximum_offset =
      static_cast<std::size_t>(buffer_size_) - map_entry_size;
  DataBuffer buffer;
  while (true) {
    if (!chain.insert(map_index).second || map_index < 0 ||
        map_index >= file_->index_count()) {
      throw std::runtime_error("corrupt VersionFile buffer map chain");
    }
    file_->get(buffer, map_index);
    if (buffer.empty()) {
      throw std::runtime_error("corrupt VersionFile buffer map block");
    }
    offset = first_entry_offset;
    while (offset <= maximum_offset) {
      const auto original_index = buffer.get_i32(offset);
      if (original_index < 0) {
        last_map_buffer_ = buffer;
        last_map_index_ = map_index;
        next_map_entry_offset_ = offset;
        return;
      }
      const auto stored_index = buffer.get_i32(offset + 4);
      if (original_index >= original_buffer_count_ || stored_index < 0 ||
          stored_index >= file_->index_count() ||
          !buffer_map_.emplace(original_index, stored_index).second) {
        throw std::runtime_error("corrupt VersionFile buffer map entry");
      }
      offset += map_entry_size;
    }
    map_index = buffer.get_i32(next_buffer_offset);
  }
}

void VersionFile::read_free_index_list(std::int32_t list_index,
                                       std::int32_t size) {
  if (size < 0 || size > original_buffer_count_) {
    throw std::runtime_error("corrupt VersionFile free list size");
  }
  free_indexes_.clear();
  free_indexes_.reserve(static_cast<std::size_t>(size));
  std::set<std::int32_t> chain;
  const auto maximum_offset =
      static_cast<std::size_t>(buffer_size_) - free_entry_size;
  DataBuffer buffer;
  while (true) {
    if (!chain.insert(list_index).second || list_index < 0 ||
        list_index >= file_->index_count()) {
      throw std::runtime_error("corrupt VersionFile free list chain");
    }
    file_->get(buffer, list_index);
    if (buffer.empty()) {
      throw std::runtime_error("corrupt VersionFile free list block");
    }
    auto offset = first_entry_offset;
    while (offset <= maximum_offset) {
      const auto original_index = buffer.get_i32(offset);
      if (original_index < 0) {
        if (free_indexes_.size() != static_cast<std::size_t>(size)) {
          throw std::runtime_error("corrupt VersionFile free list count");
        }
        (std::sort)(free_indexes_.begin(), free_indexes_.end());
        if ((std::adjacent_find)(free_indexes_.begin(), free_indexes_.end()) !=
            free_indexes_.end()) {
          throw std::runtime_error("corrupt VersionFile duplicate free index");
        }
        return;
      }
      if (original_index >= original_buffer_count_ ||
          free_indexes_.size() == static_cast<std::size_t>(size)) {
        throw std::runtime_error("corrupt VersionFile free list entry");
      }
      free_indexes_.push_back(original_index);
      offset += free_entry_size;
    }
    list_index = buffer.get_i32(next_buffer_offset);
  }
}

void VersionFile::set_target_file_id(std::int64_t file_id) {
  require_writable();
  target_file_id_ = file_id;
}

bool VersionFile::get_old_buffer(DataBuffer &buffer, std::int32_t index) {
  require_open();
  const auto found = buffer_map_.find(index);
  if (found == buffer_map_.end()) return false;
  file_->get(buffer, found->second);
  return true;
}

std::vector<std::int32_t> VersionFile::old_buffer_indexes() const {
  std::vector<std::int32_t> result;
  result.reserve(buffer_map_.size());
  for (const auto &[index, storage] : buffer_map_) {
    (void)storage;
    result.push_back(index);
  }
  (std::sort)(result.begin(), result.end());
  return result;
}

std::vector<std::string> VersionFile::old_parameter_names() const {
  require_open();
  std::vector<std::string> result;
  for (const auto &name : file_->parameter_names()) {
    if (!std::string_view(name).starts_with(parameter_prefix)) {
      result.push_back(name);
    }
  }
  return result;
}

std::int32_t VersionFile::old_parameter(const std::string &name) const {
  require_open();
  return file_->parameter(name);
}

} // namespace llmghidra::db
