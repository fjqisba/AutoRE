/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/table_record.hpp"

#include "llmghidra/db/buffer_manager.hpp"
#include "llmghidra/db/node_manager.hpp"

#include <stdexcept>
#include <utility>
#include <vector>

namespace llmghidra::db {
namespace {

std::shared_ptr<const Schema> make_storage_schema() {
  std::vector<std::unique_ptr<Field>> fields;
  fields.push_back(std::make_unique<StringField>());
  fields.push_back(std::make_unique<IntegerField>(FieldType::int32));
  fields.push_back(std::make_unique<IntegerField>(FieldType::int32));
  fields.push_back(std::make_unique<IntegerField>(FieldType::byte));
  fields.push_back(std::make_unique<BinaryField>());
  fields.push_back(std::make_unique<StringField>());
  fields.push_back(std::make_unique<IntegerField>(FieldType::int32));
  fields.push_back(std::make_unique<IntegerField>(FieldType::int64));
  fields.push_back(std::make_unique<IntegerField>(FieldType::int32));
  return std::make_shared<Schema>(
      0, std::make_unique<IntegerField>(FieldType::int64), "TableNum",
      std::move(fields),
      std::vector<std::string>{"TableName", "SchemaVersion", "RootBufferId",
                               "KeyType", "FieldTypes", "FieldNames",
                               "IndexColumn", "MaxKey", "RecordCount"});
}

} // namespace

const std::shared_ptr<const Schema> &TableRecord::storage_schema() {
  static const auto value = make_storage_schema();
  return value;
}

TableRecord::TableRecord(std::int64_t table_number, std::string name,
                         std::shared_ptr<const Schema> table_schema,
                         std::int32_t indexed_column_value)
    : table_schema_(std::move(table_schema)) {
  if (!table_schema_) {
    throw std::invalid_argument("TableRecord requires a table schema");
  }
  record_ = storage_schema()->create_record(table_number);
  record_->set_string(name_column, std::move(name));
  record_->set_integer(version_column, table_schema_->version());
  record_->set_integer(buffer_id_column, -1);
  record_->set_integer(key_type_column, table_schema_->encoded_key_type());
  record_->set_bytes(field_types_column,
                     table_schema_->encoded_field_types());
  record_->set_string(field_names_column, table_schema_->packed_names());
  record_->set_integer(indexed_column_column, indexed_column_value);
  record_->set_integer(maximum_key_column, initial_maximum_key);
  record_->set_integer(record_count_column, 0);
}

TableRecord::TableRecord(BufferManager &buffers,
                         std::unique_ptr<Record> stored_record)
    : record_(std::move(stored_record)) {
  if (!record_ || !record_->has_same_schema(*storage_schema())) {
    throw std::invalid_argument("invalid stored TableRecord schema");
  }
  table_schema_ = parse_table_schema(buffers, *record_);
}

void TableRecord::require_valid() const {
  if (!valid_ || !record_ || !table_schema_) {
    throw std::logic_error("TableRecord is invalid");
  }
}

void TableRecord::replace_record(BufferManager &buffers,
                                 std::unique_ptr<Record> stored_record) {
  require_valid();
  if (!stored_record || !stored_record->has_same_schema(*storage_schema())) {
    throw std::invalid_argument("invalid replacement TableRecord schema");
  }
  if (stored_record->key().as_integer() != table_number()) {
    throw std::invalid_argument("replacement TableRecord number differs");
  }
  auto parsed_schema = parse_table_schema(buffers, *stored_record);
  if (!parsed_schema->equals(*table_schema_)) {
    throw std::runtime_error("replacement TableRecord schema differs");
  }
  record_ = std::move(stored_record);
  table_schema_ = std::move(parsed_schema);
}

void TableRecord::invalidate() noexcept {
  valid_ = false;
  record_.reset();
  table_schema_.reset();
}

std::shared_ptr<Schema>
TableRecord::parse_table_schema(BufferManager &buffers, const Record &record) {
  const auto encoded_fields = record.field(field_types_column).as_bytes();
  const auto packed_names = record.field(field_names_column).as_string();
  if (!encoded_fields || !packed_names) {
    throw std::runtime_error("stored TableRecord has null schema metadata");
  }
  auto result = std::make_shared<Schema>(
      static_cast<int>(record.field(version_column).as_integer()),
      static_cast<std::uint8_t>(record.field(key_type_column).as_integer()),
      *encoded_fields, *packed_names);
  const auto root_id =
      static_cast<std::int32_t>(record.field(buffer_id_column).as_integer());
  if (root_id < 0 || result->key_type().variable_length() ||
      result->key_type().type() == FieldType::int64 ||
      dynamic_cast<const IndexField *>(&result->key_type()) != nullptr ||
      result->key_type().type() == FieldType::fixed10) {
    return result;
  }
  if (NodeManager::is_variable_key_node(buffers, root_id)) {
    result->force_variable_key_nodes();
  }
  return result;
}

std::int64_t TableRecord::table_number() const {
  require_valid();
  return record_->key().as_integer();
}

std::string TableRecord::name() const {
  require_valid();
  const auto value = record_->field(name_column).as_string();
  if (!value) throw std::runtime_error("TableRecord name is null");
  return *value;
}

void TableRecord::set_name(std::string name_value) {
  require_valid();
  record_->set_string(name_column, std::move(name_value));
}

std::int32_t TableRecord::root_buffer_id() const {
  require_valid();
  return static_cast<std::int32_t>(
      record_->field(buffer_id_column).as_integer());
}

void TableRecord::set_root_buffer_id(std::int32_t id) {
  require_valid();
  record_->set_integer(buffer_id_column, id);
}

std::int64_t TableRecord::maximum_key() const {
  require_valid();
  return record_->field(maximum_key_column).as_integer();
}

void TableRecord::set_maximum_key(std::int64_t key) {
  require_valid();
  record_->set_integer(maximum_key_column, key);
}

std::int32_t TableRecord::record_count() const {
  require_valid();
  return static_cast<std::int32_t>(
      record_->field(record_count_column).as_integer());
}

void TableRecord::set_record_count(std::int32_t count) {
  require_valid();
  if (count < 0) throw std::invalid_argument("negative TableRecord count");
  record_->set_integer(record_count_column, count);
}

std::int32_t TableRecord::indexed_column() const {
  require_valid();
  return static_cast<std::int32_t>(
      record_->field(indexed_column_column).as_integer());
}

} // namespace llmghidra::db
