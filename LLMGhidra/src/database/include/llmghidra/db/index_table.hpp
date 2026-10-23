/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/table.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace llmghidra::db {

class IndexTable : public std::enable_shared_from_this<IndexTable> {
public:
  virtual ~IndexTable() = default;
  IndexTable(const IndexTable &) = delete;
  IndexTable &operator=(const IndexTable &) = delete;

  [[nodiscard]] std::int64_t table_number() const;
  [[nodiscard]] std::size_t column_index() const noexcept {
    return column_index_;
  }
  [[nodiscard]] bool sparse() const noexcept { return sparse_; }
  [[nodiscard]] Table &primary_table() noexcept { return primary_table_; }
  [[nodiscard]] const Table &primary_table() const noexcept {
    return primary_table_;
  }
  [[nodiscard]] Table &storage_table() noexcept { return *index_table_; }
  [[nodiscard]] const Table &storage_table() const noexcept {
    return *index_table_;
  }
  [[nodiscard]] TableStatistics statistics();
  [[nodiscard]] bool consistent(const TaskContext &task = {});
  [[nodiscard]] bool has_record(const Field &index_value);
  [[nodiscard]] virtual std::vector<std::unique_ptr<Field>>
  find_primary_keys(const Field &index_value, const TaskContext &task = {}) = 0;
  [[nodiscard]] std::size_t key_count(const Field &index_value);

  virtual void add_entry(const Record &record) = 0;
  virtual void delete_entry(const Record &record) = 0;
  virtual void update_entry(const Record &old_record,
                            const Record &new_record) = 0;
  virtual void delete_all();

protected:
  IndexTable(Table &primary_table, std::shared_ptr<TableRecord> index_metadata);
  [[nodiscard]] const std::shared_ptr<std::recursive_mutex> &
  database_monitor() const noexcept {
    return primary_table_.database_monitor();
  }

  Table &primary_table_;
  // Database-owned indexes retain their primary Table so an outstanding
  // iterator can fail safely after DBHandle close instead of dereferencing a
  // destroyed Table. Standalone stack Tables keep normal caller-owned lifetime.
  std::shared_ptr<Table> primary_keep_alive_;
  std::shared_ptr<TableRecord> metadata_;
  std::unique_ptr<Table> index_table_;
  std::size_t column_index_ = 0;
  bool sparse_ = false;
};

class FieldIndexTable final : public IndexTable {
public:
  [[nodiscard]] static std::shared_ptr<FieldIndexTable>
  create(Table &primary_table, std::int64_t table_number,
         std::size_t column_index);
  [[nodiscard]] static std::shared_ptr<FieldIndexTable>
  open(Table &primary_table, std::shared_ptr<TableRecord> metadata);
  [[nodiscard]] static std::shared_ptr<Schema>
  index_schema(const Table &primary_table, std::size_t column_index);

  [[nodiscard]] std::vector<std::unique_ptr<Field>>
  find_primary_keys(const Field &index_value,
                    const TaskContext &task = {}) override;
  void add_entry(const Record &record) override;
  void delete_entry(const Record &record) override;
  void update_entry(const Record &old_record,
                    const Record &new_record) override;
  [[nodiscard]] const IndexField &index_key_type() const;

  [[nodiscard]] std::unique_ptr<FieldKeyIterator> index_iterator();
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  index_iterator(const Field *minimum_value, const Field *maximum_value,
                 bool before);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  index_iterator(const Field *minimum_value, const Field *maximum_value,
                 const Field &start_value, bool before);

  [[nodiscard]] std::unique_ptr<FieldKeyIterator> key_iterator();
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  key_iterator_before(const Field &start_value);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  key_iterator_after(const Field &start_value);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  key_iterator_before(const Field &start_value, const Field &primary_key);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  key_iterator_after(const Field &start_value, const Field &primary_key);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  key_iterator(const Field *minimum_value, const Field *maximum_value,
               bool before);
  [[nodiscard]] std::unique_ptr<FieldKeyIterator>
  key_iterator(const Field *minimum_value, const Field *maximum_value,
               const Field *start_value, bool before);

private:
  FieldIndexTable(Table &primary_table, std::shared_ptr<TableRecord> metadata);
  void require_primary_record(const Record &record) const;
};

} // namespace llmghidra::db
