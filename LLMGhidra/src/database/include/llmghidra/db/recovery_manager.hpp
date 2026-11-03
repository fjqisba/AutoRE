/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/file_operations.hpp"
#include "llmghidra/task_control.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>

namespace llmghidra::db {

class BufferManager;
class DatabaseChangeSet;
class LocalBufferFile;
class RecoveryFile;

// Native counterpart of db.buffers.RecoveryMgr.  It owns the two alternating
// recovery slots associated with one LocalBufferFile and keeps slot rotation
// state across snapshots during a BufferManager session.
class RecoveryManager final {
public:
  enum class OpenMode { snapshots_only, recover_existing };

  RecoveryManager(BufferManager &buffer_manager, OpenMode mode,
                  const TaskContext &task = {},
                  std::shared_ptr<FileOperations> file_operations = {});
  ~RecoveryManager();
  RecoveryManager(const RecoveryManager &) = delete;
  RecoveryManager &operator=(const RecoveryManager &) = delete;

  [[nodiscard]] bool recovered() const noexcept { return recovered_; }
  [[nodiscard]] bool recovery_has_change_set() const noexcept {
    return recovery_has_change_set_;
  }
  [[nodiscard]] std::optional<std::filesystem::path>
  recovery_change_set_path() const;

  bool
  take_snapshot(const std::optional<std::filesystem::path> &change_set_file,
                const TaskContext &task = {});
  bool take_snapshot(DatabaseChangeSet &change_set,
                     const TaskContext &task = {});
  void read_change_set(DatabaseChangeSet &change_set,
                       const TaskContext &task = {}) const;
  void clear();

  [[nodiscard]] static bool
  can_recover(LocalBufferFile &source,
              std::shared_ptr<FileOperations> file_operations = {});

  [[nodiscard]] const std::filesystem::path &
  snapshot_path(std::size_t index) const {
    return snapshot_paths_.at(index);
  }
  [[nodiscard]] const std::filesystem::path &
  change_path(std::size_t index) const {
    return change_paths_.at(index);
  }
  [[nodiscard]] std::int32_t snapshot_index() const noexcept {
    return snapshot_index_;
  }

private:
  struct Selection {
    std::int32_t index = -1;
    std::unique_ptr<RecoveryFile> file;
  };

  static std::array<std::filesystem::path, 2>
  snapshot_paths_for(const LocalBufferFile &source);
  static std::array<std::filesystem::path, 2>
  change_paths_for(const LocalBufferFile &source);
  static Selection
  select_recovery(LocalBufferFile &source,
                  const std::array<std::filesystem::path, 2> &paths,
                  const std::shared_ptr<FileOperations> &file_operations);
  static bool change_set_required(const RecoveryFile &recovery);
  bool take_snapshot_impl(
      bool has_change_set,
      const std::function<void(const std::filesystem::path &)> &materialize,
      const TaskContext &task);
  void delete_slot(std::size_t index) noexcept;

  BufferManager &buffer_manager_;
  std::shared_ptr<FileOperations> file_operations_;
  std::array<std::filesystem::path, 2> snapshot_paths_;
  std::array<std::filesystem::path, 2> change_paths_;
  std::int32_t snapshot_index_ = -1;
  std::int64_t last_snapshot_time_ = 0;
  bool recovered_ = false;
  bool recovery_has_change_set_ = false;
};

} // namespace llmghidra::db
