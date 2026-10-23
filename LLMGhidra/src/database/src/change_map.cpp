/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/change_map.hpp"

#include <algorithm>
#include <bit>
#include <stdexcept>
#include <system_error>

namespace llmghidra::db {
namespace {

std::int32_t high_i32(std::int64_t value) noexcept {
  return std::bit_cast<std::int32_t>(
      static_cast<std::uint32_t>(static_cast<std::uint64_t>(value) >> 32));
}

std::int32_t low_i32(std::int64_t value) noexcept {
  return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value));
}

std::int64_t join_i64(std::int32_t high, std::int32_t low) noexcept {
  const auto bits = (static_cast<std::uint64_t>(
                         std::bit_cast<std::uint32_t>(high))
                     << 32) |
                    std::bit_cast<std::uint32_t>(low);
  return std::bit_cast<std::int64_t>(bits);
}

} // namespace

void ChangeMap::add(std::span<const std::uint8_t> other) {
  const auto count = (std::min)(data_.size(), other.size());
  for (std::size_t index = 0; index < count; ++index) data_[index] |= other[index];
}

void ChangeMap::set(std::int32_t index, bool is_changed) {
  if (index < 0) throw std::invalid_argument("negative ChangeMap index");
  if (!contains(index)) return;
  const auto byte_index = static_cast<std::size_t>(index / 8);
  const auto mask = static_cast<std::uint8_t>(
      1U << static_cast<unsigned>(index % 8));
  if (is_changed) data_[byte_index] |= mask;
  else data_[byte_index] &= static_cast<std::uint8_t>(~mask);
}

void ChangeMap::set_changed(std::span<const std::int32_t> indexes) {
  for (const auto index : indexes) set(index, true);
}

void ChangeMap::set_unchanged(std::span<const std::int32_t> indexes) {
  for (const auto index : indexes) set(index, false);
}

bool ChangeMap::changed(std::int32_t index) const {
  if (index < 0) throw std::invalid_argument("negative ChangeMap index");
  if (!contains(index)) return true;
  const auto mask = static_cast<std::uint8_t>(
      1U << static_cast<unsigned>(index % 8));
  return (data_[static_cast<std::size_t>(index / 8)] & mask) != 0;
}

bool ChangeMap::contains(std::int32_t index) const {
  return index >= 0 && static_cast<std::size_t>(index / 8) < data_.size();
}

ChangeMapFile::ChangeMapFile(std::filesystem::path path,
                             LocalBufferFile &old_file,
                             LocalBufferFile &new_file,
                             std::int32_t old_version)
    : path_(std::move(path)) {
  if (path_.empty()) throw std::invalid_argument("empty ChangeMapFile path");
  if (std::filesystem::exists(path_)) {
    initialize_existing(old_file, &new_file);
  }
  else {
    index_count_ = old_file.index_count();
    if (index_count_ < 0 || new_file.index_count() < index_count_) {
      throw std::invalid_argument("invalid ChangeMapFile buffer counts");
    }
    manager_ = std::make_unique<BufferManager>(
        BufferManager::default_buffer_size, cache_size, 1);
    manager_->set_parameter(magic_parameter, magic_number);
    manager_->set_parameter(initial_version_parameter, old_version);
    manager_->set_parameter(index_count_parameter, index_count_);
    const auto byte_count = index_count_ == 0 ? 1 : (index_count_ - 1) / 8 + 1;
    buffer_ = std::make_unique<ChainedBuffer>(byte_count, *manager_);
    manager_->set_parameter(buffer_id_parameter, buffer_->id());
    if (index_count_ != 0 && index_count_ % 8 != 0) {
      const auto offset = static_cast<std::size_t>((index_count_ - 1) / 8);
      buffer_->put_u8(offset, static_cast<std::uint8_t>(
          0xffU << static_cast<unsigned>(index_count_ % 8)));
    }
  }
  set_target_file_id(new_file.file_id());
}

ChangeMapFile::ChangeMapFile(std::filesystem::path path,
                             LocalBufferFile &target_file)
    : path_(std::move(path)), read_only_(true) {
  if (path_.empty() || !std::filesystem::is_regular_file(path_)) {
    throw std::invalid_argument("ChangeMapFile does not exist");
  }
  initialize_existing(target_file, nullptr);
}

ChangeMapFile::~ChangeMapFile() { abort(); }

void ChangeMapFile::initialize_existing(LocalBufferFile &old_file,
                                        LocalBufferFile *new_file) {
  source_file_ = std::make_shared<LocalBufferFile>(
      path_, LocalBufferFile::OpenMode::read_only);
  if (source_file_->parameter(magic_parameter) != magic_number) {
    throw std::runtime_error("bad ChangeMapFile magic");
  }
  manager_ = std::make_unique<BufferManager>(source_file_, cache_size, 1);
  if (target_file_id() != old_file.file_id()) {
    throw std::runtime_error("ChangeMapFile target identity mismatch");
  }
  index_count_ = manager_->parameter(index_count_parameter);
  if (index_count_ < 0 || old_file.index_count() < index_count_ ||
      (new_file && new_file->index_count() < index_count_)) {
    throw std::runtime_error("ChangeMapFile index count exceeds target");
  }
  buffer_ = std::make_unique<ChainedBuffer>(
      *manager_, manager_->parameter(buffer_id_parameter));
  const auto expected = index_count_ == 0 ? 1 : (index_count_ - 1) / 8 + 1;
  if (buffer_->length() != expected) {
    throw std::runtime_error("ChangeMapFile payload length mismatch");
  }
}

void ChangeMapFile::set_target_file_id(std::int64_t id) {
  require_writable();
  manager_->set_parameter(target_id_high_parameter, high_i32(id));
  manager_->set_parameter(target_id_low_parameter, low_i32(id));
}

std::int64_t ChangeMapFile::target_file_id() const {
  require_open();
  return join_i64(manager_->parameter(target_id_high_parameter),
                  manager_->parameter(target_id_low_parameter));
}

void ChangeMapFile::require_open() const {
  if (!manager_) throw std::logic_error("ChangeMapFile is closed");
}

void ChangeMapFile::require_writable() const {
  require_open();
  if (read_only_) throw std::logic_error("ChangeMapFile is read-only");
}

std::int32_t ChangeMapFile::initial_version() const {
  require_open();
  return manager_->parameter(initial_version_parameter);
}

bool ChangeMapFile::valid_for(const LocalBufferFile &target_file) const {
  return target_file_id() == target_file.file_id();
}

void ChangeMapFile::buffer_changed(std::int32_t index, bool empty) {
  require_writable();
  if (index < 0) throw std::invalid_argument("negative ChangeMapFile index");
  if (index >= index_count_) return;
  const auto offset = static_cast<std::size_t>(index / 8);
  const auto mask = static_cast<std::uint8_t>(
      1U << static_cast<unsigned>(index % 8));
  auto byte = buffer_->get_u8(offset);
  byte = empty ? static_cast<std::uint8_t>(byte & ~mask)
               : static_cast<std::uint8_t>(byte | mask);
  buffer_->put_u8(offset, byte);
}

std::vector<std::uint8_t> ChangeMapFile::modification_data() const {
  require_open();
  return buffer_->get(0, buffer_->size());
}

void ChangeMapFile::close() {
  require_open();
  if (read_only_) {
    abort();
    return;
  }
  auto temporary_path = path_;
  temporary_path += ".tmp";
  std::shared_ptr<LocalBufferFile> temporary;
  try {
    temporary = std::make_shared<LocalBufferFile>(temporary_path,
                                                   manager_->buffer_size());
    manager_->save_as(temporary, true);
    abort();
    std::error_code error;
    std::filesystem::remove(path_, error);
    if (error) throw std::runtime_error("unable to replace ChangeMapFile");
    if (!temporary->rename_to(path_)) {
      throw std::runtime_error("unable to install ChangeMapFile");
    }
    temporary->close();
  }
  catch (...) {
    abort();
    if (temporary && !temporary->closed()) {
      try {
        temporary->close();
      }
      catch (...) {
      }
    }
    std::error_code ignored;
    std::filesystem::remove(temporary_path, ignored);
    throw;
  }
}

void ChangeMapFile::abort() noexcept {
  buffer_.reset();
  manager_.reset();
  source_file_.reset();
}

} // namespace llmghidra::db
