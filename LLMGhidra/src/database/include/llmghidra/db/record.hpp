/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/schema.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {

class Record {
public:
  Record(std::shared_ptr<const Schema> schema, std::unique_ptr<Field> key);
  Record(const Schema &schema, std::unique_ptr<Field> key);

  [[nodiscard]] const Schema &schema() const noexcept { return *schema_; }
  [[nodiscard]] const Field &key() const noexcept { return *key_; }
  void set_key(std::unique_ptr<Field> key);
  void set_key(std::int64_t key);

  [[nodiscard]] std::size_t column_count() const noexcept {
    return fields_.size();
  }
  [[nodiscard]] const Field &field(std::size_t index) const {
    return *fields_.at(index);
  }
  [[nodiscard]] std::unique_ptr<Field> field_copy(std::size_t index) const;
  void set_field(std::size_t index, std::unique_ptr<Field> value);
  void set_integer(std::size_t index, std::int64_t value);
  void set_boolean(std::size_t index, bool value);
  void set_bytes(
      std::size_t index, std::optional<std::vector<std::uint8_t>> value);
  void set_string(std::size_t index, std::optional<std::string> value);
  void set_null(std::size_t index);

  [[nodiscard]] bool field_equals(
      std::size_t index, const Field &value) const;
  [[nodiscard]] int compare_field(
      std::size_t index, const Field &value) const;
  [[nodiscard]] bool has_same_schema(const Record &other) const noexcept;
  [[nodiscard]] bool has_same_schema(const Schema &other) const noexcept;
  [[nodiscard]] std::unique_ptr<Record> clone() const;

  [[nodiscard]] std::size_t storage_length() const;
  std::size_t write(Buffer &buffer, std::size_t offset);
  std::size_t read(const Buffer &buffer, std::size_t offset);
  [[nodiscard]] bool dirty() const noexcept { return dirty_; }
  [[nodiscard]] std::int32_t hash_code() const { return key_->hash_code(); }
  [[nodiscard]] bool equals(const Record &other) const;
  [[nodiscard]] int compare(const Record &other) const {
    return key_->compare(*other.key_);
  }

private:
  void invalidate_length() noexcept { cached_length_.reset(); }
  [[nodiscard]] Field &mutable_field(std::size_t index) {
    return *fields_.at(index);
  }

  std::shared_ptr<const Schema> schema_;
  std::unique_ptr<Field> key_;
  std::vector<std::unique_ptr<Field>> fields_;
  mutable std::optional<std::size_t> cached_length_;
  bool dirty_ = false;
};

} // namespace llmghidra::db
