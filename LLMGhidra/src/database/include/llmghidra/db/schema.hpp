/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/field.hpp"

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace llmghidra::db {

class Record;

class Schema {
public:
  static constexpr std::uint8_t field_extension_indicator = 0xff;
  static constexpr std::uint8_t sparse_field_list_extension = 1;

  Schema(int version, std::unique_ptr<Field> key_type, std::string key_name,
         std::vector<std::unique_ptr<Field>> fields, std::vector<std::string> field_names,
         std::set<std::size_t> sparse_columns = {});
  Schema(int version, std::uint8_t encoded_key_type,
         const std::vector<std::uint8_t> &encoded_field_types, std::string packed_names);
  Schema(const Schema &other);
  Schema &operator=(const Schema &other);
  Schema(Schema &&) noexcept = default;
  Schema &operator=(Schema &&) noexcept = default;

  [[nodiscard]] int version() const noexcept { return version_; }
  [[nodiscard]] const Field &key_type() const noexcept { return *key_type_; }
  [[nodiscard]] const std::string &key_name() const noexcept { return key_name_; }
  [[nodiscard]] std::size_t field_count() const noexcept { return fields_.size(); }
  [[nodiscard]] const Field &field_type(std::size_t index) const { return *fields_.at(index); }
  [[nodiscard]] const std::string &field_name(std::size_t index) const { return field_names_.at(index); }
  [[nodiscard]] bool is_sparse(std::size_t index) const noexcept;
  [[nodiscard]] bool has_sparse_columns() const noexcept {
    return !sparse_columns_.empty();
  }
  [[nodiscard]] const std::set<std::size_t> &sparse_columns() const noexcept {
    return sparse_columns_;
  }
  [[nodiscard]] bool variable_length() const noexcept { return variable_length_; }
  [[nodiscard]] std::size_t fixed_length() const noexcept { return fixed_length_; }
  [[nodiscard]] std::uint8_t encoded_key_type() const noexcept {
    return key_type_->encoded_type();
  }
  [[nodiscard]] std::vector<std::uint8_t> encoded_field_types() const;
  [[nodiscard]] std::string packed_names() const;
  [[nodiscard]] bool use_long_key_nodes() const noexcept;
  [[nodiscard]] bool use_variable_key_nodes() const noexcept;
  [[nodiscard]] bool use_fixed_key_nodes() const noexcept;
  void force_variable_key_nodes() noexcept { force_variable_key_nodes_ = true; }
  [[nodiscard]] bool equals(const Schema &other) const noexcept;
  [[nodiscard]] std::unique_ptr<Record> create_record(std::unique_ptr<Field> key) const;
  [[nodiscard]] std::unique_ptr<Record> create_record(std::int64_t key) const;

private:
  void validate_and_measure();
  int version_;
  std::unique_ptr<Field> key_type_;
  std::string key_name_;
  std::vector<std::unique_ptr<Field>> fields_;
  std::vector<std::string> field_names_;
  std::set<std::size_t> sparse_columns_;
  bool variable_length_ = false;
  std::size_t fixed_length_ = 0;
  bool force_variable_key_nodes_ = false;
};

} // namespace llmghidra::db
