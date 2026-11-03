/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/version_file_handler.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {

VersionFileHandler::VersionFileHandler(VersionOpener opener,
                                       std::int64_t target_file_id,
                                       std::int32_t target_version,
                                       std::int32_t original_version)
    : opener_(std::move(opener)) {
  if (!opener_) {
    throw std::invalid_argument("VersionFileHandler requires an opener");
  }
  if (original_version < 0 || target_version <= original_version) {
    throw std::invalid_argument("invalid VersionFileHandler version range");
  }
  const auto count = static_cast<std::int64_t>(target_version) -
                     static_cast<std::int64_t>(original_version);
  versions_.reserve(static_cast<std::size_t>(count));

  std::int64_t previous_target_id = 0;
  for (auto version = original_version; version < target_version; ++version) {
    auto buffer_file = opener_(version);
    if (!buffer_file) {
      throw std::runtime_error("VersionFileHandler opener returned null");
    }
    VersionFile file(std::move(buffer_file));
    VersionMetadata metadata{version, file.original_file_id(),
                             file.target_file_id(),
                             file.original_buffer_count()};
    if (!versions_.empty() && previous_target_id != metadata.original_file_id) {
      throw std::runtime_error("incorrect VersionFile chain file ID");
    }

    if (versions_.empty()) {
      original_buffer_count_ = metadata.original_buffer_count;
      original_file_id_ = metadata.original_file_id;
      free_indexes_ = file.free_indexes();
      for (const auto &name : file.old_parameter_names()) {
        original_parameters_.emplace(name, file.old_parameter(name));
      }
    }
    maximum_buffer_count_ =
        (std::max)(maximum_buffer_count_, metadata.original_buffer_count);
    const auto file_index = versions_.size();
    for (const auto buffer_index : file.old_buffer_indexes()) {
      // The earliest VersionFile has the oldest bytes and must win.
      buffer_versions_.try_emplace(buffer_index, file_index);
    }
    previous_target_id = metadata.target_file_id;
    versions_.push_back(metadata);
  }
  if (previous_target_id != target_file_id) {
    throw std::runtime_error("incorrect VersionFile chain target ID");
  }
}

VersionFileHandler::~VersionFileHandler() { close(); }

void VersionFileHandler::close() noexcept {
  open_file_.reset();
  open_file_index_ = static_cast<std::size_t>(-1);
}

VersionFile &VersionFileHandler::open_version(std::size_t index) {
  if (index >= versions_.size()) {
    throw std::out_of_range("VersionFileHandler file index is out of range");
  }
  if (open_file_ && open_file_index_ == index) return *open_file_;
  close();
  auto buffer_file = opener_(versions_[index].version);
  if (!buffer_file) {
    throw std::runtime_error("VersionFileHandler opener returned null");
  }
  auto file = std::make_unique<VersionFile>(std::move(buffer_file));
  const auto &expected = versions_[index];
  if (file->original_file_id() != expected.original_file_id ||
      file->target_file_id() != expected.target_file_id ||
      file->original_buffer_count() != expected.original_buffer_count) {
    throw std::runtime_error("VersionFile changed after handler construction");
  }
  open_file_index_ = index;
  open_file_ = std::move(file);
  return *open_file_;
}

bool VersionFileHandler::get_old_buffer(DataBuffer &buffer,
                                        std::int32_t index) {
  const auto found = buffer_versions_.find(index);
  if (found != buffer_versions_.end()) {
    return open_version(found->second).get_old_buffer(buffer, index);
  }
  if (std::binary_search(free_indexes_.begin(), free_indexes_.end(), index)) {
    buffer.set_id(-1);
    buffer.set_empty(true);
    buffer.set_dirty(false);
    return true;
  }
  return false;
}

void VersionFileHandler::set_map_bit(std::vector<std::uint8_t> &map,
                                     std::int32_t index) {
  map[static_cast<std::size_t>(index / 8)] |=
      static_cast<std::uint8_t>(1U << static_cast<unsigned>(index % 8));
}

std::vector<std::uint8_t> VersionFileHandler::modification_map(
    std::int32_t buffer_count, bool discard_larger) const {
  if (buffer_count < 0) {
    throw std::logic_error("negative VersionFileHandler buffer count");
  }
  const auto map_size = static_cast<std::size_t>(buffer_count / 8) +
                        (buffer_count % 8 == 0 ? 0U : 1U);
  std::vector<std::uint8_t> result(map_size, 0);
  const auto excess = buffer_count % 8;
  if (excess != 0) {
    result.back() |= static_cast<std::uint8_t>(0xffU << excess);
  }
  for (const auto &[index, version] : buffer_versions_) {
    (void)version;
    if (index < 0) {
      throw std::logic_error("negative VersionFileHandler buffer index");
    }
    if (index >= buffer_count) {
      if (discard_larger) continue;
      throw std::logic_error("VersionFileHandler buffer index exceeds map");
    }
    set_map_bit(result, index);
  }
  return result;
}

std::vector<std::uint8_t>
VersionFileHandler::reverse_modification_map() const {
  return modification_map(maximum_buffer_count_, false);
}

std::vector<std::uint8_t>
VersionFileHandler::forward_modification_map() const {
  return modification_map(original_buffer_count_, true);
}

std::vector<std::string> VersionFileHandler::old_parameter_names() const {
  std::vector<std::string> names;
  names.reserve(original_parameters_.size());
  for (const auto &[name, value] : original_parameters_) {
    (void)value;
    names.push_back(name);
  }
  return names;
}

std::int32_t
VersionFileHandler::old_parameter(const std::string &name) const {
  const auto found = original_parameters_.find(name);
  if (found == original_parameters_.end()) {
    throw std::out_of_range("VersionFileHandler parameter not found: " + name);
  }
  return found->second;
}

} // namespace llmghidra::db
