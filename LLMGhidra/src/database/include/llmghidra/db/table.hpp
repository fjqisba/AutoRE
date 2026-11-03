/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/node_manager.hpp"
#include "llmghidra/db/storage_integrity.hpp"
#include "llmghidra/db/table_iterators.hpp"
#include "llmghidra/db/table_record.hpp"
#include "llmghidra/db/table_statistics.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace llmghidra::db {

class IndexTable;

// Native primary-table implementation. Secondary index attachment and public
// iterator facades are layered on this class in the next C4 work packages.
class Table final : public std::enable_shared_from_this<Table> {
public:
  Table(BufferManager &buffers, std::shared_ptr<TableRecord> metadata,
        std::function<void()> mutation_guard = {},
        std::shared_ptr<std::recursive_mutex> database_monitor = {});
  Table(const Table &) = delete;
  Table &operator=(const Table &) = delete;

  [[nodiscard]] const Schema &schema() const {
    std::scoped_lock lock(*mutex_);
    check_valid();
    return *schema_;
  }
  [[nodiscard]] const std::shared_ptr<const Schema> &schema_handle() const {
    std::scoped_lock lock(*mutex_);
    check_valid();
    return schema_;
  }
  [[nodiscard]] std::shared_ptr<const TableRecord> metadata() const {
    std::scoped_lock lock(*mutex_);
    check_valid();
    return metadata_;
  }
  [[nodiscard]] const BufferManager &buffer_manager() const {
    std::scoped_lock lock(*mutex_);
    check_valid();
    return buffers_;
  }
  [[nodiscard]] const std::function<void()> &mutation_guard() const noexcept {
    return mutation_guard_;
  }
  [[nodiscard]] bool use_long_keys() const noexcept {
    std::scoped_lock lock(*mutex_);
    return valid_ && metadata_ && metadata_->valid() &&
           schema_->use_long_key_nodes();
  }
  [[nodiscard]] bool use_fixed_keys() const noexcept {
    std::scoped_lock lock(*mutex_);
    return valid_ && metadata_ && metadata_->valid() &&
           schema_->use_fixed_key_nodes();
  }
  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::string name() const;
  [[nodiscard]] std::int64_t table_number() const;
  [[nodiscard]] std::int32_t root_buffer_id() const;
  [[nodiscard]] std::int32_t record_count() const;
  [[nodiscard]] std::int64_t maximum_key() const;
  [[nodiscard]] std::int64_t next_long_key() const;
  [[nodiscard]] std::uint64_t modification_count() const noexcept;

  [[nodiscard]] bool has_record(std::int64_t key);
  [[nodiscard]] bool has_record(const Field &key);
  [[nodiscard]] std::unique_ptr<Record> record(std::int64_t key);
  [[nodiscard]] std::unique_ptr<Record> record(const Field &key);
  [[nodiscard]] std::unique_ptr<Record> record_before(std::int64_t key);
  [[nodiscard]] std::unique_ptr<Record> record_before(const Field &key);
  [[nodiscard]] std::unique_ptr<Record> record_after(std::int64_t key);
  [[nodiscard]] std::unique_ptr<Record> record_after(const Field &key);
  [[nodiscard]] std::unique_ptr<Record> record_at_or_before(std::int64_t key);
  [[nodiscard]] std::unique_ptr<Record> record_at_or_before(const Field &key);
  [[nodiscard]] std::unique_ptr<Record> record_at_or_after(std::int64_t key);
  [[nodiscard]] std::unique_ptr<Record> record_at_or_after(const Field &key);
  [[nodiscard]] std::unique_ptr<Record> first_record();
  [[nodiscard]] std::unique_ptr<Record> last_record();

  [[nodiscard]] std::unique_ptr<RecordIterator> iterator();
  [[nodiscard]] std::unique_ptr<RecordIterator>
  iterator(std::int64_t start_key);
  [[nodiscard]] std::unique_ptr<RecordIterator>
  iterator(std::int64_t minimum_key, std::int64_t maximum_key,
           std::int64_t start_key);
  [[nodiscard]] std::unique_ptr<RecordIterator>
  iterator(const Field &start_key);
  [[nodiscard]] std::unique_ptr<RecordIterator>
  iterator(const Field *minimum_key, const Field *maximum_key,
           const Field *start_key);
  [[nodiscard]] std::unique_ptr<LongKeyIterator> long_key_iterator();
  [[nodiscard]] std::unique_ptr<LongKeyIterator>
  long_key_iterator(std::int64_t start_key);
  [[nodiscard]] std::unique_ptr<LongKeyIterator>
  long_key_iterator(std::int64_t minimum_key, std::int64_t maximum_key,
                    std::int64_t start_key);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator> field_key_iterator();
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  field_key_iterator(const Field &start_key);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  field_key_iterator(const Field *minimum_key, const Field *maximum_key,
                     const Field *start_key);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  field_key_iterator(const Field *minimum_key, const Field *maximum_key,
                     bool before);

  void put_record(Record &record);
  [[nodiscard]] bool delete_record(std::int64_t key);
  [[nodiscard]] bool delete_record(const Field &key);
  [[nodiscard]] bool delete_records(std::int64_t start_key,
                                    std::int64_t end_key);
  [[nodiscard]] bool delete_records(const Field &start_key,
                                    const Field &end_key);
  void delete_all();
  [[nodiscard]] bool consistent(const TaskContext &task = {});
  [[nodiscard]] StorageGraphAudit
  audit_storage(const TaskContext &task = {}, bool verify_record_count = true);
  void rebuild(const TaskContext &task = {});
  [[nodiscard]] TableStatistics statistics();
  [[nodiscard]] std::vector<std::size_t> indexed_columns() const;
  // Refresh cached root/count/max state after an internal catalog update.
  // The public metadata view is const, so this cannot create a new mutation.
  void metadata_changed();

private:
  friend class DatabaseHandle;
  friend class FieldIndexTable;
  friend class IndexTable;
  friend class MasterTable;
  class NodeSession;

  [[nodiscard]] std::shared_ptr<BTreeNode> open_root();
  [[nodiscard]] std::shared_ptr<LongKeyNode> open_long_root();
  [[nodiscard]] std::shared_ptr<FixedKeyNode> open_fixed_root();
  [[nodiscard]] std::shared_ptr<VariableKeyNode> open_variable_root();
  void require_long_key_schema() const;
  void require_field_key(const Field &key) const;
  void update_root(const std::shared_ptr<BTreeNode> &root);
  void apply_record_delta(std::int64_t delta);
  void check_mutation() const;
  void check_valid() const;
  [[nodiscard]] BufferManager &mutable_buffer_manager() const {
    std::scoped_lock lock(*mutex_);
    check_valid();
    return buffers_;
  }
  [[nodiscard]] const std::shared_ptr<std::recursive_mutex> &
  database_monitor() const noexcept {
    return mutex_;
  }
  void attach_index(const std::shared_ptr<IndexTable> &index);
  void detach_index(std::size_t column_index);
  void clear_indexes();
  void invalidate() noexcept;
  [[nodiscard]] std::vector<std::shared_ptr<IndexTable>> live_indexes();

  BufferManager &buffers_;
  std::shared_ptr<TableRecord> metadata_;
  std::shared_ptr<const Schema> schema_;
  NodeManager nodes_;
  // Associated primary/index Tables share the DBHandle monitor, matching the
  // upstream synchronized(db) contract and eliminating split-lock inversion.
  mutable std::shared_ptr<std::recursive_mutex> mutex_;
  std::int32_t root_buffer_id_ = -1;
  std::int32_t record_count_ = 0;
  std::int64_t maximum_key_ = TableRecord::initial_maximum_key;
  std::uint64_t modification_count_ = 0;
  std::function<void()> mutation_guard_;
  std::vector<std::weak_ptr<IndexTable>> indexes_;
  bool valid_ = true;
};

} // namespace llmghidra::db
