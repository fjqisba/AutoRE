/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/record.hpp"

#include <set>
#include <stdexcept>

namespace llmghidra::db {
namespace {

std::vector<std::unique_ptr<Field>> make_empty_fields(const Schema &schema) {
  std::vector<std::unique_ptr<Field>> fields;
  fields.reserve(schema.field_count());
  for (std::size_t index = 0; index < schema.field_count(); ++index) {
    auto value = schema.field_type(index).empty();
    if (schema.is_sparse(index)) value->set_null();
    fields.push_back(std::move(value));
  }
  return fields;
}

} // namespace

Record::Record(std::shared_ptr<const Schema> schema,
               std::unique_ptr<Field> key)
    : schema_(std::move(schema)), key_(std::move(key)) {
  if (!schema_) throw std::invalid_argument("record schema is required");
  if (!key_ || !key_->same_type(schema_->key_type())) {
    throw std::invalid_argument("record key type differs");
  }
  fields_ = make_empty_fields(*schema_);
}

Record::Record(const Schema &schema, std::unique_ptr<Field> key)
    : Record(std::make_shared<Schema>(schema), std::move(key)) {}

void Record::set_key(std::unique_ptr<Field> key) {
  if (!key || !key_->same_type(*key)) {
    throw std::invalid_argument("record key type differs");
  }
  key_ = std::move(key);
}

void Record::set_key(std::int64_t key) {
  if (key_->type() != FieldType::int64 ||
      dynamic_cast<const IndexField *>(key_.get())) {
    throw std::logic_error("record does not use a long key");
  }
  key_ = std::make_unique<IntegerField>(FieldType::int64, key);
}

std::unique_ptr<Field> Record::field_copy(std::size_t index) const {
  return fields_.at(index)->clone();
}

void Record::set_field(std::size_t index, std::unique_ptr<Field> value) {
  auto &existing = fields_.at(index);
  if (!value) {
    if (!schema_->is_sparse(index)) {
      throw std::invalid_argument("null Field is only valid for sparse columns");
    }
    value = schema_->field_type(index).empty();
    value->set_null();
  }
  if (existing->encoded_type() != value->encoded_type()) {
    throw std::invalid_argument("record field type differs");
  }
  invalidate_length();
  existing = std::move(value);
  // Matches DBRecord.setField: replacing the object alone does not set dirty.
}

void Record::set_integer(std::size_t index, std::int64_t value) {
  const bool size_changes =
      schema_->is_sparse(index) && fields_.at(index)->is_null();
  dirty_ = true;
  mutable_field(index).set_integer(value);
  if (size_changes) invalidate_length();
}

void Record::set_boolean(std::size_t index, bool value) {
  const bool size_changes =
      schema_->is_sparse(index) && fields_.at(index)->is_null();
  dirty_ = true;
  mutable_field(index).set_boolean(value);
  if (size_changes) invalidate_length();
}

void Record::set_bytes(
    std::size_t index, std::optional<std::vector<std::uint8_t>> value) {
  const bool old_null = fields_.at(index)->is_null();
  const bool new_null = !value;
  dirty_ = true;
  if (fields_[index]->variable_length() ||
      (schema_->is_sparse(index) && old_null != new_null)) {
    invalidate_length();
  }
  mutable_field(index).set_bytes(std::move(value));
}

void Record::set_string(std::size_t index,
                        std::optional<std::string> value) {
  dirty_ = true;
  invalidate_length();
  mutable_field(index).set_string(std::move(value));
}

void Record::set_null(std::size_t index) {
  const bool size_changes =
      fields_.at(index)->variable_length() ||
      (schema_->is_sparse(index) && !fields_[index]->is_null());
  dirty_ = true;
  if (size_changes) invalidate_length();
  mutable_field(index).set_null();
}

bool Record::field_equals(std::size_t index, const Field &value) const {
  return fields_.at(index)->equals(value);
}

int Record::compare_field(std::size_t index, const Field &value) const {
  return fields_.at(index)->compare(value);
}

bool Record::has_same_schema(const Record &other) const noexcept {
  if (fields_.size() != other.fields_.size()) return false;
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    if (fields_[index]->encoded_type() != other.fields_[index]->encoded_type()) {
      return false;
    }
  }
  return true;
}

bool Record::has_same_schema(const Schema &other) const noexcept {
  if (fields_.size() != other.field_count() ||
      !key_->same_type(other.key_type())) {
    return false;
  }
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    if (!fields_[index]->same_type(other.field_type(index))) return false;
  }
  return true;
}

std::unique_ptr<Record> Record::clone() const {
  auto result = std::make_unique<Record>(schema_, key_->clone());
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    result->set_field(index, fields_[index]->clone());
  }
  return result;
}

std::size_t Record::storage_length() const {
  if (cached_length_) return *cached_length_;
  std::size_t result = schema_->has_sparse_columns() ? 1 : 0;
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    if (!schema_->is_sparse(index)) {
      result += fields_[index]->storage_length();
    }
    else if (!fields_[index]->is_null()) {
      result += 1 + fields_[index]->storage_length();
    }
  }
  cached_length_ = result;
  return result;
}

std::size_t Record::write(Buffer &buffer, std::size_t offset) {
  std::vector<std::size_t> sparse;
  sparse.reserve(schema_->sparse_columns().size());
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    if (schema_->is_sparse(index)) {
      if (!fields_[index]->is_null()) sparse.push_back(index);
    }
    else {
      offset = fields_[index]->write(buffer, offset);
    }
  }
  if (schema_->has_sparse_columns()) {
    if (sparse.size() > 127) {
      throw std::length_error("sparse field count exceeds signed byte range");
    }
    offset = buffer.put_u8(offset, static_cast<std::uint8_t>(sparse.size()));
    for (const auto index : sparse) {
      offset = buffer.put_u8(offset, static_cast<std::uint8_t>(index));
      offset = fields_[index]->write(buffer, offset);
    }
  }
  dirty_ = false;
  return offset;
}

std::size_t Record::read(const Buffer &buffer, std::size_t offset) {
  auto new_fields = make_empty_fields(*schema_);
  for (std::size_t index = 0; index < new_fields.size(); ++index) {
    if (!schema_->is_sparse(index)) {
      offset = new_fields[index]->read(buffer, offset);
    }
  }
  if (schema_->has_sparse_columns()) {
    const auto raw_count = buffer.get_u8(offset++);
    if (raw_count > 127 || raw_count > schema_->sparse_columns().size()) {
      throw std::invalid_argument("invalid sparse field count");
    }
    std::set<std::size_t> seen;
    for (std::size_t item = 0; item < raw_count; ++item) {
      const auto index = static_cast<std::size_t>(buffer.get_u8(offset++));
      if (index >= new_fields.size() || !schema_->is_sparse(index) ||
          !seen.insert(index).second) {
        throw std::invalid_argument("invalid sparse column index");
      }
      offset = new_fields[index]->read(buffer, offset);
    }
  }
  fields_ = std::move(new_fields);
  invalidate_length();
  dirty_ = false;
  return offset;
}

bool Record::equals(const Record &other) const {
  if (!key_->equals(*other.key_) || fields_.size() != other.fields_.size()) {
    return false;
  }
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    if (!fields_[index]->equals(*other.fields_[index])) return false;
  }
  return true;
}

} // namespace llmghidra::db
