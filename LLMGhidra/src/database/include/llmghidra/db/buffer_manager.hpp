/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer.hpp"
#include "llmghidra/db/file_operations.hpp"
#include "llmghidra/db/index_provider.hpp"
#include "llmghidra/db/local_buffer_file.hpp"
#include "llmghidra/task_control.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace llmghidra::db {

class RecoveryFile;
class RecoveryManager;
class DatabaseChangeSet;

// Native low-level buffer manager with the observable transaction semantics of
// db.buffers.BufferMgr. Source buffers are loaded lazily. Checkpoints contain
// copies of the small overlay index while immutable byte arrays remain shared.
class BufferManager final {
public:
  enum class BufferState { out_of_range, free, allocated };

  static constexpr std::int32_t default_buffer_size = 16 * 1024;
  static constexpr std::size_t default_cache_size = 4 * 1024 * 1024;
  static constexpr std::size_t default_undo_count = 10;

  explicit BufferManager(
      std::int32_t requested_buffer_size = default_buffer_size,
      std::size_t approximate_cache_size = default_cache_size,
      std::int32_t maximum_undos =
          static_cast<std::int32_t>(default_undo_count),
      std::shared_ptr<FileOperations> recovery_file_operations = {});
  ~BufferManager();
  explicit BufferManager(
      std::shared_ptr<LocalBufferFile> source_file,
      std::size_t approximate_cache_size = default_cache_size,
      std::int32_t maximum_undos =
          static_cast<std::int32_t>(default_undo_count),
      std::shared_ptr<FileOperations> recovery_file_operations = {});

  BufferManager(const BufferManager &) = delete;
  BufferManager &operator=(const BufferManager &) = delete;
  BufferManager(BufferManager &&) = delete;
  BufferManager &operator=(BufferManager &&) = delete;

  [[nodiscard]] std::int32_t buffer_size() const noexcept {
    return buffer_size_;
  }
  [[nodiscard]] std::shared_ptr<LocalBufferFile> source_file() const;

  [[nodiscard]] std::shared_ptr<DataBuffer> get_buffer(std::int32_t id);
  [[nodiscard]] std::shared_ptr<DataBuffer> create_buffer();
  void release_buffer(const std::shared_ptr<DataBuffer> &buffer);
  void delete_buffer(std::int32_t id);

  [[nodiscard]] std::size_t lock_count() const;
  [[nodiscard]] std::int32_t allocated_buffer_count() const;
  [[nodiscard]] std::size_t free_buffer_count() const;
  [[nodiscard]] BufferState buffer_state(std::int32_t id) const;
  [[nodiscard]] std::vector<std::int32_t> allocated_buffer_ids() const;
  [[nodiscard]] std::uint8_t inspect_u8(std::int32_t id,
                                        std::size_t offset) const;
  [[nodiscard]] std::uint64_t modification_count() const;

  [[nodiscard]] bool at_checkpoint() const;
  [[nodiscard]] bool is_changed() const;
  [[nodiscard]] bool has_undo_checkpoints() const;
  [[nodiscard]] bool has_redo_checkpoints() const;
  [[nodiscard]] std::size_t available_undo_count() const;
  [[nodiscard]] std::size_t available_redo_count() const;
  bool checkpoint(const TaskContext &task = {});
  bool undo(bool redoable);
  bool redo();
  void set_max_undos(std::int32_t maximum_undos);
  [[nodiscard]] std::size_t max_undos() const;
  void clear_checkpoints();

  [[nodiscard]] bool modified_since_snapshot() const;
  void mark_snapshot_complete();

  // Recovery snapshots are stored beside the associated LocalBufferFile in
  // Ghidra's snapshotA/B.grf and changeA/B.grf layout.  change_set_file is an
  // opaque, already serialized change-set artifact whose presence is required
  // before that snapshot can be selected for recovery.
  bool take_recovery_snapshot(const std::optional<std::filesystem::path>
                                  &change_set_file = std::nullopt,
                              const TaskContext &task = {});
  bool take_recovery_snapshot(DatabaseChangeSet &change_set,
                              const TaskContext &task = {});
  bool recover(const TaskContext &task = {});
  void clear_recovery_files();
  [[nodiscard]] bool can_recover() const;
  [[nodiscard]] std::optional<std::filesystem::path>
  recovery_change_set_path() const;
  void read_recovery_change_set(DatabaseChangeSet &change_set,
                                const TaskContext &task = {});

  [[nodiscard]] std::int32_t parameter(const std::string &name) const;
  void set_parameter(std::string name, std::int32_t value);
  [[nodiscard]] std::vector<std::string> parameter_names() const;

  // Persist through a LocalManagedBufferFile source, mirroring BufferMgr.save.
  // The committed managed output becomes the new lazy source on success.
  [[nodiscard]] bool can_save() const;
  void save(const std::string &comment = {}, const TaskContext &task = {});
  void save(const std::string &comment, DatabaseChangeSet &change_set,
            const TaskContext &task = {});

  // The destination must be a newly created, empty file of the same buffer
  // size. It is made read-only on success. Association rebases history and
  // makes the destination the new lazy source.
  void save_as(const std::shared_ptr<LocalBufferFile> &destination,
               bool associate_with_new_file, const TaskContext &task = {});

  void set_corrupted_state() noexcept;
  [[nodiscard]] bool corrupted() const;

private:
  friend class RecoveryManager;
  using ImmutableBytes = std::shared_ptr<const std::vector<std::uint8_t>>;

  struct State {
    IndexProvider indexes;
    std::unordered_map<std::int32_t, ImmutableBytes> overlay;
    std::uint64_t revision = 0;
  };

  struct LockEntry {
    std::shared_ptr<DataBuffer> buffer;
    bool newly_created = false;
  };

  void initialize_history();
  void require_healthy_locked() const;
  void require_no_locks_locked(const char *operation) const;
  [[nodiscard]] std::vector<std::uint8_t>
  resolve_bytes_locked(std::int32_t id) const;
  void start_change_locked();
  void trim_history_locked();
  void checkpoint_locked();
  void rebaseline_locked(std::shared_ptr<LocalBufferFile> new_source);
  void write_to_destination_locked(
      const std::shared_ptr<LocalBufferFile> &destination, bool make_read_only,
      const TaskContext &task, std::string_view operation);
  void write_recovery_snapshot(RecoveryFile &recovery,
                               const TaskContext &task) const;
  void apply_recovery(RecoveryFile &recovery, std::int32_t recovery_index,
                      const TaskContext &task);

  mutable std::mutex mutex_;
  mutable std::mutex recovery_mutex_;
  std::shared_ptr<LocalBufferFile> source_file_;
  std::int32_t source_index_count_ = 0;
  std::int32_t buffer_size_ = 0;
  std::size_t max_undos_ = default_undo_count;
  State working_state_;
  std::vector<State> history_;
  std::vector<State> redo_history_;
  std::unordered_map<std::int32_t, LockEntry> locked_;
  std::map<std::string, std::int32_t> parameters_;
  std::uint64_t next_revision_ = 1;
  std::uint64_t modification_count_ = 0;
  bool working_dirty_ = false;
  bool modified_since_snapshot_ = false;
  bool corrupted_ = false;
  std::shared_ptr<FileOperations> recovery_file_operations_;
  std::unique_ptr<RecoveryManager> recovery_manager_;
};

} // namespace llmghidra::db
