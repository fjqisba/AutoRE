/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/index_table.hpp"
#include "llmghidra/db/master_table.hpp"
#include "llmghidra/task_control.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace llmghidra::db {

class DatabaseChangeSet;
class Buffer;
class ChainedBuffer;

class NoTransactionError : public std::logic_error {
public:
  NoTransactionError() : std::logic_error("no active database transaction") {}
};

class TerminatedTransactionError : public std::logic_error {
public:
  TerminatedTransactionError()
      : std::logic_error("database transaction was terminated") {}
};

class ClosedDatabaseError : public std::logic_error {
public:
  ClosedDatabaseError() : std::logic_error("database is closed") {}
};

class ReadOnlyDatabaseError : public std::logic_error {
public:
  ReadOnlyDatabaseError() : std::logic_error("database is read-only") {}
};

// Native transaction and catalog owner corresponding to db.DBHandle.
class DatabaseHandle final {
public:
  explicit DatabaseHandle(
      std::int32_t requested_buffer_size = BufferManager::default_buffer_size,
      std::size_t approximate_cache_size = BufferManager::default_cache_size,
      std::int32_t maximum_undos =
          static_cast<std::int32_t>(BufferManager::default_undo_count));
  explicit DatabaseHandle(
      std::shared_ptr<LocalBufferFile> source_file,
      std::size_t approximate_cache_size = BufferManager::default_cache_size,
      std::int32_t maximum_undos =
          static_cast<std::int32_t>(BufferManager::default_undo_count),
      bool read_only = false);
  ~DatabaseHandle();
  DatabaseHandle(const DatabaseHandle &) = delete;
  DatabaseHandle &operator=(const DatabaseHandle &) = delete;

  [[nodiscard]] std::int64_t start_transaction();
  [[nodiscard]] bool end_transaction(std::int64_t id, bool commit);
  void terminate_transaction(std::int64_t id, bool commit);
  void check_transaction() const;
  [[nodiscard]] bool transaction_active() const;
  [[nodiscard]] bool has_uncommitted_changes() const;

  [[nodiscard]] bool can_undo() const;
  [[nodiscard]] bool can_redo() const;
  [[nodiscard]] bool undo();
  [[nodiscard]] bool redo();
  [[nodiscard]] std::size_t available_undo_count() const;
  [[nodiscard]] std::size_t available_redo_count() const;
  void set_max_undos(std::int32_t maximum_undos);

  [[nodiscard]] std::shared_ptr<Table> get_table(const std::string &name) const;
  [[nodiscard]] std::vector<std::shared_ptr<Table>> tables() const;
  [[nodiscard]] std::size_t table_count() const;
  [[nodiscard]] bool consistent(const TaskContext &task = {});
  [[nodiscard]] StorageGraphAudit
  audit_storage(const TaskContext &task = {},
                const StorageAuditOptions &options = {});
  [[nodiscard]] bool rebuild(const TaskContext &task = {});
  [[nodiscard]] std::shared_ptr<Table>
  create_table(std::string name, std::shared_ptr<const Schema> schema,
               const std::vector<std::size_t> &indexed_columns = {});
  [[nodiscard]] std::shared_ptr<FieldIndexTable>
  create_index(const std::string &table_name, std::size_t column_index);
  [[nodiscard]] std::shared_ptr<FieldIndexTable>
  get_index(const std::string &table_name, std::size_t column_index) const;
  [[nodiscard]] bool remove_index(const std::string &table_name,
                                  std::size_t column_index);
  [[nodiscard]] bool rename_table(const std::string &old_name,
                                  const std::string &new_name);
  [[nodiscard]] bool delete_table(const std::string &name);

  [[nodiscard]] std::int64_t database_id() const;
  // Reset the DBParms database identity in an existing writable buffer file.
  // This is the native equivalent of DBHandle.resetDatabaseId(File), used
  // when importing a packed database into a project as a distinct item.
  [[nodiscard]] static std::int64_t reset_database_id(LocalBufferFile &file);
  [[nodiscard]] DatabaseHandle &scratch_database();
  void close_scratch_database() noexcept;

  // A logical read-only handle may export an unassociated snapshot, but may
  // not re-associate itself with a new writable backing file.
  void save_as(const std::shared_ptr<LocalBufferFile> &destination,
               bool associate_with_new_file = false,
               const TaskContext &task = {});
  [[nodiscard]] bool can_save() const;
  void save(std::string comment = {}, const TaskContext &task = {});
  void save(std::string comment, DatabaseChangeSet &change_set,
            const TaskContext &task = {});
  bool take_recovery_snapshot(DatabaseChangeSet &change_set,
                              const TaskContext &task = {});
  void read_recovery_change_set(DatabaseChangeSet &change_set,
                                const TaskContext &task = {});
  [[nodiscard]] const BufferManager &buffer_manager() const;
  [[nodiscard]] std::shared_ptr<DataBuffer>
  get_data_buffer(std::int32_t buffer_id);
  [[nodiscard]] std::shared_ptr<DataBuffer> create_data_buffer();
  [[nodiscard]] std::unique_ptr<ChainedBuffer>
  create_chained_buffer(std::int32_t size, bool enable_obfuscation = false);
  [[nodiscard]] std::unique_ptr<ChainedBuffer>
  create_layered_chained_buffer(std::int32_t size,
                                const Buffer &uninitialized_source,
                                std::size_t source_offset = 0);
  [[nodiscard]] std::unique_ptr<ChainedBuffer>
  open_chained_buffer(std::int32_t first_buffer_id);
  [[nodiscard]] std::unique_ptr<ChainedBuffer>
  open_layered_chained_buffer(std::int32_t first_buffer_id,
                              const Buffer &uninitialized_source,
                              std::size_t source_offset = 0);
  void release_data_buffer(const std::shared_ptr<DataBuffer> &buffer);
  void delete_data_buffer(std::int32_t buffer_id);
  [[nodiscard]] bool closed() const noexcept;
  [[nodiscard]] bool read_only() const noexcept;
  void close() noexcept;

private:
  void initialize_new();
  void initialize_existing();
  void require_open_locked() const;
  void read_database_id();
  void write_database_id(std::int64_t id);
  void load_tables();
  void reload_tables();
  [[nodiscard]] bool end_transaction_locked(std::int64_t id, bool commit);
  [[nodiscard]] std::shared_ptr<FieldIndexTable>
  create_index_locked(const std::shared_ptr<Table> &table,
                      std::size_t column_index);
  [[nodiscard]] bool remove_index_locked(const std::shared_ptr<Table> &table,
                                         std::size_t column_index);

  // Ghidra serializes DBHandle and associated Table operations on the same
  // re-entrant monitor.  Sharing ownership keeps that monitor alive while an
  // invalidated Table handle is still held by a caller after close/reload.
  mutable std::shared_ptr<std::recursive_mutex> mutex_ =
      std::make_shared<std::recursive_mutex>();
  std::unique_ptr<BufferManager> buffers_;
  std::unique_ptr<DatabaseParameters> parameters_;
  std::unique_ptr<MasterTable> master_table_;
  std::unordered_map<std::string, std::shared_ptr<Table>> tables_;
  std::unordered_map<std::int64_t, std::shared_ptr<FieldIndexTable>> indexes_;
  std::unique_ptr<DatabaseHandle> scratch_database_;
  std::int64_t database_id_ = 0;
  std::int64_t last_transaction_id_ = 0;
  bool transaction_active_ = false;
  bool waiting_for_new_transaction_ = false;
  bool read_only_ = false;
  bool closed_ = false;
};

using DBHandle = DatabaseHandle;

} // namespace llmghidra::db
