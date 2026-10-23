/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/index_provider.hpp"
#include "llmghidra/db/local_buffer_file.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace llmghidra::db {

// Disk-compatible native counterpart of db.buffers.RecoveryFile. It stores the
// current unsaved buffers and allocation metadata for one source file identity.
class RecoveryFile final {
public:
  static constexpr std::int32_t magic_number = 0x38de7654;
  static constexpr const char *parameter_prefix = "~RF.";

  // create=true creates an invalid output file; false updates a valid snapshot.
  RecoveryFile(LocalBufferFile &source, std::filesystem::path path, bool create,
               std::shared_ptr<FileOperations> file_operations = {});
  // Opens a recovery snapshot read-only. valid() also requires source identity.
  RecoveryFile(LocalBufferFile &source, std::filesystem::path path,
               std::shared_ptr<FileOperations> file_operations = {});
  ~RecoveryFile();
  RecoveryFile(const RecoveryFile &) = delete;
  RecoveryFile &operator=(const RecoveryFile &) = delete;

  [[nodiscard]] const std::filesystem::path &path() const noexcept { return path_; }
  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] bool read_only() const noexcept { return read_only_; }
  [[nodiscard]] bool closed() const noexcept { return !file_; }
  [[nodiscard]] std::int64_t timestamp() const noexcept { return timestamp_; }
  [[nodiscard]] std::int64_t source_file_id() const noexcept { return source_file_id_; }
  [[nodiscard]] std::int32_t index_count() const noexcept { return index_count_; }

  void set_index_count(std::int32_t count);
  void set_free_indexes(std::span<const std::int32_t> indexes);
  [[nodiscard]] const std::vector<std::int32_t> &free_indexes() const noexcept {
    return free_indexes_;
  }
  void put_buffer(const DataBuffer &buffer);
  void remove_buffer(std::int32_t id);
  [[nodiscard]] bool get_buffer(DataBuffer &buffer, std::int32_t id);
  [[nodiscard]] std::vector<std::int32_t> buffer_indexes() const;

  [[nodiscard]] std::vector<std::string> user_parameter_names() const;
  [[nodiscard]] std::int32_t parameter(const std::string &name) const;
  void clear_parameters();
  void set_parameter(std::string name, std::int32_t value);
  void close();
  // Discards an unfinished writable snapshot.  Read-only instances are simply
  // closed.  This is also the destructor path, so committing is always
  // explicit and a partially populated recovery file can never become valid
  // merely because stack unwinding destroyed the writer.
  void abort() noexcept;

private:
  static constexpr const char *magic_parameter = "~RF.VersionFile";
  static constexpr const char *source_id_high_parameter = "~RF.SrcIdHi";
  static constexpr const char *source_id_low_parameter = "~RF.SrcIdLow";
  static constexpr const char *valid_parameter = "~RF.OrigBufCnt";
  static constexpr const char *timestamp_high_parameter = "~RF.TimestampHi";
  static constexpr const char *timestamp_low_parameter = "~RF.TimestampLow";
  static constexpr const char *map_index_parameter = "~RF.MapIndex";
  static constexpr const char *free_list_index_parameter = "~RF.FreeListIndex";
  static constexpr const char *free_list_size_parameter = "~RF.FreeListSize";
  static constexpr const char *index_count_parameter = "~RF.BufferCount";
  static constexpr std::size_t next_buffer_offset = 0;
  static constexpr std::size_t first_entry_offset = 4;
  static constexpr std::size_t map_entry_size = 8;
  static constexpr std::size_t free_entry_size = 4;

  void require_open() const;
  void require_writable() const;
  void set_modified();
  void parse();
  void read_buffer_map();
  void read_free_index_list();
  void validate_storage_layout();
  void save_buffer_map();
  void save_free_index_list();
  [[nodiscard]] std::int32_t allocate_storage();
  [[nodiscard]] static std::int64_t join_id(std::int32_t high,
                                             std::int32_t low) noexcept;
  static void store_id(LocalBufferFile &file, const char *high_parameter,
                       const char *low_parameter, std::int64_t value);

  std::filesystem::path path_;
  std::unique_ptr<LocalBufferFile> file_;
  IndexProvider storage_indexes_;
  std::map<std::int32_t, std::int32_t> buffer_map_;
  std::vector<std::int32_t> free_indexes_;
  std::vector<std::int32_t> map_block_indexes_;
  std::vector<std::int32_t> free_list_block_indexes_;
  std::int64_t source_file_id_ = 0;
  std::int64_t timestamp_ = 0;
  std::int32_t index_count_ = 0;
  std::int32_t map_index_ = -1;
  std::int32_t free_list_index_ = -1;
  bool read_only_ = false;
  bool valid_ = false;
  bool modified_ = false;
};

} // namespace llmghidra::db
