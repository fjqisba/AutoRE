/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/database_parameters.hpp"
#include "llmghidra/db/table.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace llmghidra::db {

// Native counterpart of db.MasterTable.  The catalog itself is a normal
// Ghidra Table whose root is stored in DBParms buffer 0.
class MasterTable final {
public:
  MasterTable(BufferManager &buffers, DatabaseParameters &parameters,
              std::function<void()> mutation_guard,
              std::shared_ptr<std::recursive_mutex> database_monitor = {});
  MasterTable(const MasterTable &) = delete;
  MasterTable &operator=(const MasterTable &) = delete;

  [[nodiscard]] const std::vector<std::shared_ptr<TableRecord>> &
  records() const noexcept {
    return records_;
  }
  [[nodiscard]] std::shared_ptr<TableRecord>
  create_record(std::string name, std::shared_ptr<const Schema> schema,
                std::int32_t indexed_column);
  void delete_record(std::int64_t table_number);
  [[nodiscard]] const std::vector<std::shared_ptr<TableRecord>> &refresh();
  void flush();
  void change_name(const std::string &old_name, const std::string &new_name);
  [[nodiscard]] bool dirty() const;
  [[nodiscard]] std::int32_t root_buffer_id() const;
  [[nodiscard]] StorageGraphAudit
  audit_storage(const TaskContext &task = {}, bool verify_record_count = true) {
    return table_->audit_storage(task, verify_record_count);
  }
  [[nodiscard]] std::int64_t next_table_number() const noexcept {
    return next_table_number_;
  }
  void invalidate() noexcept;

private:
  [[nodiscard]] std::vector<std::unique_ptr<Record>> read_catalog_records();
  void update_catalog_metadata(std::size_t count, std::int64_t maximum_key);
  void synchronize_root_parameter();
  void check_mutation() const;

  BufferManager &buffers_;
  DatabaseParameters &parameters_;
  std::shared_ptr<TableRecord> master_record_;
  std::unique_ptr<Table> table_;
  std::vector<std::shared_ptr<TableRecord>> records_;
  std::int64_t next_table_number_ = 0;
  std::function<void()> mutation_guard_;
};

} // namespace llmghidra::db
