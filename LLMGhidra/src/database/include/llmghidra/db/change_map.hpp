/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer_manager.hpp"
#include "llmghidra/db/chained_buffer.hpp"
#include "llmghidra/db/local_buffer_file.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace llmghidra::db {

class ChangeMap final {
public:
  explicit ChangeMap(std::vector<std::uint8_t> data)
      : data_(std::move(data)) {}

  [[nodiscard]] const std::vector<std::uint8_t> &data() const noexcept {
    return data_;
  }
  void add(std::span<const std::uint8_t> other);
  void set_changed(std::span<const std::int32_t> indexes);
  void set_unchanged(std::span<const std::int32_t> indexes);
  [[nodiscard]] bool changed(std::int32_t index) const;
  [[nodiscard]] bool contains(std::int32_t index) const;

private:
  void set(std::int32_t index, bool changed);
  std::vector<std::uint8_t> data_;
};

// Persistent Ghidra ChangeMapFile. Its payload is a ChainedBuffer stored in a
// normal LocalBufferFile and committed through a sibling .tmp file.
class ChangeMapFile final {
public:
  static constexpr std::int32_t magic_number = 0x73d9a3bc;
  static constexpr std::int32_t cache_size = 64 * 1024;

  ChangeMapFile(std::filesystem::path path, LocalBufferFile &old_file,
                LocalBufferFile &new_file, std::int32_t old_version);
  ChangeMapFile(std::filesystem::path path, LocalBufferFile &target_file);
  ~ChangeMapFile();
  ChangeMapFile(const ChangeMapFile &) = delete;
  ChangeMapFile &operator=(const ChangeMapFile &) = delete;

  [[nodiscard]] bool read_only() const noexcept { return read_only_; }
  [[nodiscard]] bool closed() const noexcept { return !manager_; }
  [[nodiscard]] std::int32_t index_count() const noexcept {
    return index_count_;
  }
  [[nodiscard]] std::int32_t initial_version() const;
  [[nodiscard]] bool valid_for(const LocalBufferFile &target_file) const;
  void buffer_changed(std::int32_t index, bool empty);
  [[nodiscard]] std::vector<std::uint8_t> modification_data() const;
  void close();
  void abort() noexcept;

private:
  static constexpr const char *magic_parameter = "~MF.ModMapFile";
  static constexpr const char *buffer_id_parameter = "~MF.BufferId";
  static constexpr const char *target_id_high_parameter = "~MF.TargetIdHi";
  static constexpr const char *target_id_low_parameter = "~MF.TargetIdLow";
  static constexpr const char *index_count_parameter = "~MF.IndexCnt";
  static constexpr const char *initial_version_parameter = "~MF.InitialVersion";

  void initialize_existing(LocalBufferFile &old_file,
                           LocalBufferFile *new_file);
  void set_target_file_id(std::int64_t id);
  [[nodiscard]] std::int64_t target_file_id() const;
  void require_open() const;
  void require_writable() const;

  std::filesystem::path path_;
  std::shared_ptr<LocalBufferFile> source_file_;
  std::unique_ptr<BufferManager> manager_;
  std::unique_ptr<ChainedBuffer> buffer_;
  std::int32_t index_count_ = 0;
  bool read_only_ = false;
};

} // namespace llmghidra::db
