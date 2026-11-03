/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/index_provider.hpp"
#include "llmghidra/db/local_buffer_file.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace llmghidra::db {

// Disk-compatible native counterpart of db.buffers.VersionFile.  It stores
// the old bytes, free list and file parameters required to reconstruct one
// earlier LocalBufferFile version from its successor.
class VersionFile final {
public:
  static constexpr std::int32_t magic_number = 0x382d3435;
  static constexpr const char *parameter_prefix = "~VF.";

  VersionFile(LocalBufferFile &original_file, LocalBufferFile &target_file,
              std::filesystem::path version_path);
  VersionFile(LocalBufferFile &original_file, LocalBufferFile &target_file,
              std::unique_ptr<LocalBufferFile> version_file);
  explicit VersionFile(std::filesystem::path version_path);
  explicit VersionFile(std::unique_ptr<LocalBufferFile> version_file);
  ~VersionFile();
  VersionFile(const VersionFile &) = delete;
  VersionFile &operator=(const VersionFile &) = delete;

  void close();
  void open();
  void abort();
  [[nodiscard]] bool closed() const noexcept { return !file_; }
  [[nodiscard]] bool read_only() const noexcept { return read_only_; }

  void set_target_file_id(std::int64_t file_id);
  [[nodiscard]] bool accepts_old_buffer(std::int32_t index) const;
  void put_old_buffer(const DataBuffer &buffer, std::int32_t index);
  [[nodiscard]] bool get_old_buffer(DataBuffer &buffer,
                                    std::int32_t index);
  [[nodiscard]] std::vector<std::int32_t> old_buffer_indexes() const;
  [[nodiscard]] const std::vector<std::int32_t> &free_indexes() const noexcept {
    return free_indexes_;
  }
  [[nodiscard]] std::int64_t target_file_id() const noexcept {
    return target_file_id_;
  }
  [[nodiscard]] std::int64_t original_file_id() const noexcept {
    return original_file_id_;
  }
  [[nodiscard]] std::int32_t original_buffer_count() const noexcept {
    return original_buffer_count_;
  }
  [[nodiscard]] std::vector<std::string> old_parameter_names() const;
  [[nodiscard]] std::int32_t old_parameter(const std::string &name) const;
  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }

private:
  static constexpr const char *magic_parameter = "~VF.VersionFile";
  static constexpr const char *original_id_high_parameter = "~VF.OriginalIdHi";
  static constexpr const char *original_id_low_parameter = "~VF.OriginalIdLow";
  static constexpr const char *target_id_high_parameter = "~VF.TargetIdHi";
  static constexpr const char *target_id_low_parameter = "~VF.TargetIdLow";
  static constexpr const char *original_count_parameter = "~VF.OrigBufCnt";
  static constexpr const char *map_index_parameter = "~VF.MapIndex";
  static constexpr const char *free_list_index_parameter = "~VF.FreeListIndex";
  static constexpr const char *free_list_size_parameter = "~VF.FreeListSize";
  static constexpr std::size_t next_buffer_offset = 0;
  static constexpr std::size_t first_entry_offset = 4;
  static constexpr std::size_t map_entry_size = 8;
  static constexpr std::size_t free_entry_size = 4;

  void require_open() const;
  void require_writable() const;
  void parse();
  void update_buffer_map();
  void read_buffer_map(std::int32_t map_index);
  [[nodiscard]] std::int32_t save_free_index_list();
  void read_free_index_list(std::int32_t list_index, std::int32_t size);
  [[nodiscard]] std::int32_t allocate_storage();
  [[nodiscard]] static std::int64_t join_id(std::int32_t high,
                                             std::int32_t low) noexcept;
  static void store_id(LocalBufferFile &file, const char *high_parameter,
                       const char *low_parameter, std::int64_t id);

  std::filesystem::path path_;
  std::unique_ptr<LocalBufferFile> file_;
  bool read_only_ = false;
  bool aborted_ = false;
  std::int32_t buffer_size_ = 0;
  std::int32_t original_buffer_count_ = 0;
  std::int32_t initial_buffer_count_ = 0;
  std::int64_t target_file_id_ = 0;
  std::int64_t original_file_id_ = 0;
  IndexProvider storage_indexes_;
  std::vector<std::int32_t> free_indexes_;
  std::unordered_map<std::int32_t, std::int32_t> buffer_map_;
  std::vector<std::int32_t> pending_map_ids_;
  DataBuffer last_map_buffer_;
  std::int32_t last_map_index_ = -1;
  std::size_t next_map_entry_offset_ = first_entry_offset;
};

} // namespace llmghidra::db
