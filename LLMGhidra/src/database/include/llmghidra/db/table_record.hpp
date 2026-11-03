/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/record.hpp"

#include <cstdint>
#include <limits>
#include <memory>
#include <string>

namespace llmghidra::db {

class BufferManager;

// Native counterpart of db.TableRecord. The underlying Record uses the exact
// nine-column master-table schema from the fixed Ghidra baseline.
class TableRecord final {
public:
  static constexpr std::int32_t primary_table_index_column = -1;
  static constexpr std::int64_t initial_maximum_key =
      std::numeric_limits<std::int64_t>::min();

  TableRecord(std::int64_t table_number, std::string name,
              std::shared_ptr<const Schema> table_schema,
              std::int32_t indexed_column = primary_table_index_column);
  TableRecord(BufferManager &buffers, std::unique_ptr<Record> stored_record);

  [[nodiscard]] static const std::shared_ptr<const Schema> &storage_schema();
  [[nodiscard]] const Schema &table_schema() const {
    require_valid();
    return *table_schema_;
  }
  [[nodiscard]] const std::shared_ptr<const Schema> &table_schema_handle()
      const {
    require_valid();
    return table_schema_;
  }
  [[nodiscard]] Record &record() {
    require_valid();
    return *record_;
  }
  [[nodiscard]] const Record &record() const {
    require_valid();
    return *record_;
  }
  [[nodiscard]] std::unique_ptr<Record> clone_record() const {
    require_valid();
    return record_->clone();
  }

  // Replace the persisted catalog record without changing this object's
  // identity.  Existing Table handles therefore observe undo/redo refreshes.
  void replace_record(BufferManager &buffers,
                      std::unique_ptr<Record> stored_record);
  void invalidate() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }

  [[nodiscard]] std::int64_t table_number() const;
  [[nodiscard]] std::string name() const;
  void set_name(std::string name);
  [[nodiscard]] std::int32_t root_buffer_id() const;
  void set_root_buffer_id(std::int32_t id);
  [[nodiscard]] std::int64_t maximum_key() const;
  void set_maximum_key(std::int64_t key);
  [[nodiscard]] std::int32_t record_count() const;
  void set_record_count(std::int32_t count);
  [[nodiscard]] std::int32_t indexed_column() const;

private:
  enum Column : std::size_t {
    name_column = 0,
    version_column = 1,
    buffer_id_column = 2,
    key_type_column = 3,
    field_types_column = 4,
    field_names_column = 5,
    indexed_column_column = 6,
    maximum_key_column = 7,
    record_count_column = 8,
  };

  static std::shared_ptr<Schema>
  parse_table_schema(BufferManager &buffers, const Record &record);
  void require_valid() const;

  std::unique_ptr<Record> record_;
  std::shared_ptr<const Schema> table_schema_;
  bool valid_ = true;
};

} // namespace llmghidra::db
