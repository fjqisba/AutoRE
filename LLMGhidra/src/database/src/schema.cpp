/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/record.hpp"

#include <iterator>
#include <stdexcept>
#include <string_view>

namespace llmghidra::db {
namespace {

std::vector<std::unique_ptr<Field>> clone_fields(
    const std::vector<std::unique_ptr<Field>> &fields) {
  std::vector<std::unique_ptr<Field>> result;
  result.reserve(fields.size());
  for (const auto &field : fields) result.push_back(field->clone());
  return result;
}

void parse_packed_names(std::string_view packed,
                        std::string &key_name,
                        std::vector<std::string> &field_names) {
  std::vector<std::string> tokens;
  std::size_t start = 0;
  while (start <= packed.size()) {
    const auto end = packed.find(';', start);
    const auto token = packed.substr(
        start, end == std::string_view::npos ? packed.size() - start
                                             : end - start);
    // java.util.StringTokenizer ignores empty tokens and the trailing separator.
    if (!token.empty()) tokens.emplace_back(token);
    if (end == std::string_view::npos) break;
    start = end + 1;
  }
  if (tokens.empty()) {
    throw std::invalid_argument("packed schema names contain no key name");
  }
  key_name = std::move(tokens.front());
  field_names.assign(std::make_move_iterator(tokens.begin() + 1),
                     std::make_move_iterator(tokens.end()));
}

} // namespace

Schema::Schema(int version, std::unique_ptr<Field> key_type,
               std::string key_name,
               std::vector<std::unique_ptr<Field>> fields,
               std::vector<std::string> field_names,
               std::set<std::size_t> sparse_columns)
    : version_(version), key_type_(std::move(key_type)),
      key_name_(std::move(key_name)), fields_(std::move(fields)),
      field_names_(std::move(field_names)),
      sparse_columns_(std::move(sparse_columns)) {
  validate_and_measure();
}

Schema::Schema(int version, std::uint8_t encoded_key_type,
               const std::vector<std::uint8_t> &encoded_field_types,
               std::string packed_names)
    : version_(version), key_type_(make_field(encoded_key_type)) {
  parse_packed_names(packed_names, key_name_, field_names_);

  std::size_t offset = 0;
  while (offset < encoded_field_types.size() &&
         encoded_field_types[offset] != field_extension_indicator) {
    fields_.push_back(make_field(encoded_field_types[offset++]));
  }

  bool saw_sparse_extension = false;
  while (offset < encoded_field_types.size()) {
    if (encoded_field_types[offset] == field_extension_indicator) ++offset;
    if (offset == encoded_field_types.size()) break;

    const auto extension = encoded_field_types[offset++];
    if (extension != sparse_field_list_extension) {
      throw std::invalid_argument("unsupported schema field extension");
    }
    if (saw_sparse_extension) {
      throw std::invalid_argument("duplicate sparse field extension");
    }
    saw_sparse_extension = true;
    while (offset < encoded_field_types.size() &&
           encoded_field_types[offset] != field_extension_indicator) {
      const auto raw_column = encoded_field_types[offset++];
      if (raw_column > 127) {
        throw std::invalid_argument("sparse column entry is a negative Java byte");
      }
      if (!sparse_columns_.insert(raw_column).second) {
        throw std::invalid_argument("sparse column set contains duplicate entry");
      }
    }
  }
  validate_and_measure();
}

Schema::Schema(const Schema &other)
    : version_(other.version_), key_type_(other.key_type_->clone()),
      key_name_(other.key_name_), fields_(clone_fields(other.fields_)),
      field_names_(other.field_names_), sparse_columns_(other.sparse_columns_),
      variable_length_(other.variable_length_), fixed_length_(other.fixed_length_),
      force_variable_key_nodes_(other.force_variable_key_nodes_) {}

Schema &Schema::operator=(const Schema &other) {
  if (this == &other) return *this;
  Schema copy(other);
  *this = std::move(copy);
  return *this;
}

void Schema::validate_and_measure() {
  if (!key_type_) throw std::invalid_argument("schema key type is required");
  if (fields_.size() != field_names_.size()) {
    throw std::invalid_argument("field names and types differ");
  }

  variable_length_ = !sparse_columns_.empty();
  fixed_length_ = 0;
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    if (!fields_[index]) {
      throw std::invalid_argument("null schema field type");
    }
    if (field_names_[index].find(';') != std::string::npos) {
      throw std::invalid_argument("field name contains separator");
    }
    variable_length_ = variable_length_ || fields_[index]->variable_length();
    fixed_length_ += fields_[index]->storage_length();
  }
  for (const auto column : sparse_columns_) {
    if (column >= fields_.size() || column > 127) {
      throw std::invalid_argument("sparse column out of range");
    }
  }
  if (variable_length_) fixed_length_ = 0;
}

bool Schema::is_sparse(std::size_t index) const noexcept {
  return sparse_columns_.contains(index);
}

std::vector<std::uint8_t> Schema::encoded_field_types() const {
  std::vector<std::uint8_t> result;
  result.reserve(fields_.size() +
                 (sparse_columns_.empty() ? 0 : sparse_columns_.size() + 2));
  for (const auto &field : fields_) result.push_back(field->encoded_type());
  if (!sparse_columns_.empty()) {
    result.push_back(field_extension_indicator);
    result.push_back(sparse_field_list_extension);
    for (const auto column : sparse_columns_) {
      result.push_back(static_cast<std::uint8_t>(column));
    }
  }
  return result;
}

std::string Schema::packed_names() const {
  std::string result = key_name_;
  result.push_back(';');
  for (const auto &name : field_names_) {
    result += name;
    result.push_back(';');
  }
  return result;
}

bool Schema::use_long_key_nodes() const noexcept {
  return !force_variable_key_nodes_ &&
         key_type_->type() == FieldType::int64 &&
         dynamic_cast<const IndexField *>(key_type_.get()) == nullptr;
}

bool Schema::use_variable_key_nodes() const noexcept {
  return force_variable_key_nodes_ || key_type_->variable_length();
}

bool Schema::use_fixed_key_nodes() const noexcept {
  return !use_variable_key_nodes() && !use_long_key_nodes();
}

bool Schema::equals(const Schema &other) const noexcept {
  if (version_ != other.version_ ||
      key_type_->encoded_type() != other.key_type_->encoded_type() ||
      fields_.size() != other.fields_.size() ||
      sparse_columns_ != other.sparse_columns_) {
    return false;
  }
  for (std::size_t index = 0; index < fields_.size(); ++index) {
    if (fields_[index]->encoded_type() != other.fields_[index]->encoded_type()) {
      return false;
    }
  }
  return true;
}

std::unique_ptr<Record> Schema::create_record(std::unique_ptr<Field> key) const {
  return std::make_unique<Record>(std::make_shared<Schema>(*this), std::move(key));
}

std::unique_ptr<Record> Schema::create_record(std::int64_t key) const {
  if (key_type_->type() != FieldType::int64 ||
      dynamic_cast<const IndexField *>(key_type_.get())) {
    throw std::invalid_argument("schema does not use a long key");
  }
  return create_record(std::make_unique<IntegerField>(FieldType::int64, key));
}

} // namespace llmghidra::db
