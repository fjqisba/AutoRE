/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/version_file.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace llmghidra::db {

// Reconstructs one historical BufferFile view from a consecutive chain of
// VersionFiles.  The opener decouples the handler from a concrete project store
// and permits at most one version file to remain open during buffer reads.
class VersionFileHandler final {
public:
  using VersionOpener =
      std::function<std::unique_ptr<LocalBufferFile>(std::int32_t version)>;

  VersionFileHandler(VersionOpener opener, std::int64_t target_file_id,
                     std::int32_t target_version,
                     std::int32_t original_version);
  ~VersionFileHandler();
  VersionFileHandler(const VersionFileHandler &) = delete;
  VersionFileHandler &operator=(const VersionFileHandler &) = delete;

  void close() noexcept;
  [[nodiscard]] bool get_old_buffer(DataBuffer &buffer, std::int32_t index);

  [[nodiscard]] std::int64_t original_file_id() const noexcept {
    return original_file_id_;
  }
  [[nodiscard]] std::int32_t original_buffer_count() const noexcept {
    return original_buffer_count_;
  }
  [[nodiscard]] const std::vector<std::int32_t> &free_indexes() const noexcept {
    return free_indexes_;
  }
  [[nodiscard]] std::vector<std::uint8_t>
  reverse_modification_map() const;
  [[nodiscard]] std::vector<std::uint8_t>
  forward_modification_map() const;
  [[nodiscard]] std::vector<std::string> old_parameter_names() const;
  [[nodiscard]] std::int32_t old_parameter(const std::string &name) const;

private:
  struct VersionMetadata final {
    std::int32_t version = 0;
    std::int64_t original_file_id = 0;
    std::int64_t target_file_id = 0;
    std::int32_t original_buffer_count = 0;
  };

  [[nodiscard]] VersionFile &open_version(std::size_t index);
  [[nodiscard]] std::vector<std::uint8_t>
  modification_map(std::int32_t buffer_count, bool discard_larger) const;
  static void set_map_bit(std::vector<std::uint8_t> &map,
                          std::int32_t index);

  VersionOpener opener_;
  std::vector<VersionMetadata> versions_;
  std::unordered_map<std::int32_t, std::size_t> buffer_versions_;
  std::vector<std::int32_t> free_indexes_;
  std::map<std::string, std::int32_t> original_parameters_;
  std::unique_ptr<VersionFile> open_file_;
  std::size_t open_file_index_ = static_cast<std::size_t>(-1);
  std::int32_t original_buffer_count_ = 0;
  std::int32_t maximum_buffer_count_ = 0;
  std::int64_t original_file_id_ = 0;
};

} // namespace llmghidra::db
