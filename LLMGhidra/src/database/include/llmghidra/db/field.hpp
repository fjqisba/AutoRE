/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {

enum class FieldType : std::uint8_t {
  byte = 0,
  int16 = 1,
  int32 = 2,
  int64 = 3,
  string = 4,
  binary = 5,
  boolean = 6,
  fixed10 = 7,
};

class Field {
public:
  static constexpr std::uint8_t field_type_mask = 0x0f;
  static constexpr std::uint8_t legacy_index_long_type = 8;
  static constexpr std::size_t maximum_index_field_length = 64;

  virtual ~Field() = default;
  [[nodiscard]] virtual FieldType type() const noexcept = 0;
  [[nodiscard]] std::uint8_t encoded_type() const noexcept {
    return static_cast<std::uint8_t>(type());
  }
  [[nodiscard]] virtual bool same_type(const Field &other) const noexcept;
  [[nodiscard]] virtual bool variable_length() const noexcept { return false; }
  [[nodiscard]] virtual bool is_null() const noexcept = 0;
  virtual void set_null() = 0;
  [[nodiscard]] virtual std::size_t storage_length() const noexcept = 0;
  virtual std::size_t write(Buffer &buffer, std::size_t offset) const = 0;
  virtual std::size_t read(const Buffer &buffer, std::size_t offset) = 0;
  [[nodiscard]] virtual std::size_t read_length(
      const Buffer &buffer, std::size_t offset) const;
  virtual void truncate(std::size_t total_storage_length);
  [[nodiscard]] virtual std::unique_ptr<Field> clone() const = 0;
  [[nodiscard]] virtual std::unique_ptr<Field> empty() const = 0;
  [[nodiscard]] virtual int compare(const Field &other) const = 0;
  [[nodiscard]] virtual int compare_stored(
      const DataBuffer &buffer, std::size_t offset) const;
  [[nodiscard]] virtual bool equals(const Field &other) const;
  [[nodiscard]] virtual std::int32_t hash_code() const = 0;
  [[nodiscard]] virtual std::string value_string() const = 0;
  [[nodiscard]] virtual std::unique_ptr<Field> minimum() const;
  [[nodiscard]] virtual std::unique_ptr<Field> maximum() const;

  [[nodiscard]] virtual std::int64_t as_integer() const;
  virtual void set_integer(std::int64_t value);
  [[nodiscard]] virtual bool as_boolean() const;
  virtual void set_boolean(bool value);
  [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>> as_bytes() const;
  virtual void set_bytes(std::optional<std::vector<std::uint8_t>> value);
  [[nodiscard]] virtual std::optional<std::string> as_string() const;
  virtual void set_string(std::optional<std::string> value);
};

class IntegerField final : public Field {
public:
  explicit IntegerField(FieldType type, std::int64_t value = 0);
  [[nodiscard]] FieldType type() const noexcept override { return type_; }
  [[nodiscard]] bool same_type(const Field &other) const noexcept override;
  [[nodiscard]] bool is_null() const noexcept override { return null_; }
  void set_null() override;
  [[nodiscard]] std::size_t storage_length() const noexcept override;
  std::size_t write(Buffer &buffer, std::size_t offset) const override;
  std::size_t read(const Buffer &buffer, std::size_t offset) override;
  [[nodiscard]] std::unique_ptr<Field> clone() const override;
  [[nodiscard]] std::unique_ptr<Field> empty() const override;
  [[nodiscard]] int compare(const Field &other) const override;
  [[nodiscard]] int compare_stored(
      const DataBuffer &buffer, std::size_t offset) const override;
  [[nodiscard]] std::int32_t hash_code() const override;
  [[nodiscard]] std::string value_string() const override;
  [[nodiscard]] std::unique_ptr<Field> minimum() const override;
  [[nodiscard]] std::unique_ptr<Field> maximum() const override;
  [[nodiscard]] std::int64_t as_integer() const override { return value_; }
  void set_integer(std::int64_t value) override;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> as_bytes() const override;
  void set_bytes(std::optional<std::vector<std::uint8_t>> value) override;

private:
  FieldType type_;
  std::int64_t value_;
  bool null_ = false;
};

class BooleanField final : public Field {
public:
  explicit BooleanField(bool value = false) : value_(value ? 1 : 0) {}
  [[nodiscard]] FieldType type() const noexcept override { return FieldType::boolean; }
  [[nodiscard]] bool is_null() const noexcept override { return null_; }
  void set_null() override;
  [[nodiscard]] std::size_t storage_length() const noexcept override { return 1; }
  std::size_t write(Buffer &buffer, std::size_t offset) const override;
  std::size_t read(const Buffer &buffer, std::size_t offset) override;
  [[nodiscard]] std::unique_ptr<Field> clone() const override;
  [[nodiscard]] std::unique_ptr<Field> empty() const override;
  [[nodiscard]] int compare(const Field &other) const override;
  [[nodiscard]] int compare_stored(
      const DataBuffer &buffer, std::size_t offset) const override;
  [[nodiscard]] std::int32_t hash_code() const override { return value_; }
  [[nodiscard]] std::string value_string() const override;
  [[nodiscard]] std::unique_ptr<Field> minimum() const override;
  [[nodiscard]] std::unique_ptr<Field> maximum() const override;
  [[nodiscard]] std::int64_t as_integer() const override { return value_; }
  [[nodiscard]] bool as_boolean() const override { return value_ != 0; }
  void set_boolean(bool value) override;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> as_bytes() const override;
  void set_bytes(std::optional<std::vector<std::uint8_t>> value) override;

private:
  std::int8_t value_ = 0;
  bool null_ = false;
};

class BinaryField : public Field {
public:
  BinaryField() = default;
  explicit BinaryField(std::optional<std::vector<std::uint8_t>> value)
      : value_(std::move(value)) {}
  [[nodiscard]] FieldType type() const noexcept override { return FieldType::binary; }
  [[nodiscard]] bool variable_length() const noexcept override { return true; }
  [[nodiscard]] bool is_null() const noexcept override { return !value_.has_value(); }
  void set_null() override { value_.reset(); }
  [[nodiscard]] std::size_t storage_length() const noexcept override;
  std::size_t write(Buffer &buffer, std::size_t offset) const override;
  std::size_t read(const Buffer &buffer, std::size_t offset) override;
  [[nodiscard]] std::size_t read_length(
      const Buffer &buffer, std::size_t offset) const override;
  void truncate(std::size_t total_storage_length) override;
  [[nodiscard]] std::unique_ptr<Field> clone() const override;
  [[nodiscard]] std::unique_ptr<Field> empty() const override;
  [[nodiscard]] int compare(const Field &other) const override;
  [[nodiscard]] int compare_stored(
      const DataBuffer &buffer, std::size_t offset) const override;
  [[nodiscard]] std::int32_t hash_code() const override;
  [[nodiscard]] std::string value_string() const override;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> as_bytes() const override {
    return value_;
  }
  void set_bytes(std::optional<std::vector<std::uint8_t>> value) override {
    value_ = std::move(value);
  }

protected:
  std::optional<std::vector<std::uint8_t>> value_;
};

class StringField final : public Field {
public:
  StringField() = default;
  explicit StringField(std::optional<std::string> value);
  [[nodiscard]] FieldType type() const noexcept override { return FieldType::string; }
  [[nodiscard]] bool variable_length() const noexcept override { return true; }
  [[nodiscard]] bool is_null() const noexcept override { return !bytes_.has_value(); }
  void set_null() override;
  [[nodiscard]] std::size_t storage_length() const noexcept override;
  std::size_t write(Buffer &buffer, std::size_t offset) const override;
  std::size_t read(const Buffer &buffer, std::size_t offset) override;
  [[nodiscard]] std::size_t read_length(
      const Buffer &buffer, std::size_t offset) const override;
  void truncate(std::size_t total_storage_length) override;
  [[nodiscard]] std::unique_ptr<Field> clone() const override;
  [[nodiscard]] std::unique_ptr<Field> empty() const override;
  [[nodiscard]] int compare(const Field &other) const override;
  [[nodiscard]] int compare_stored(
      const DataBuffer &buffer, std::size_t offset) const override;
  [[nodiscard]] std::int32_t hash_code() const override;
  [[nodiscard]] std::string value_string() const override;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> as_bytes() const override {
    return bytes_;
  }
  void set_bytes(std::optional<std::vector<std::uint8_t>> value) override;
  [[nodiscard]] std::optional<std::string> as_string() const override { return value_; }
  void set_string(std::optional<std::string> value) override;

private:
  std::optional<std::string> value_;
  std::optional<std::vector<std::uint8_t>> bytes_;
};

class Fixed10Field final : public Field {
public:
  Fixed10Field();
  explicit Fixed10Field(std::vector<std::uint8_t> value);
  [[nodiscard]] FieldType type() const noexcept override { return FieldType::fixed10; }
  [[nodiscard]] bool is_null() const noexcept override { return null_; }
  void set_null() override;
  [[nodiscard]] std::size_t storage_length() const noexcept override { return 10; }
  std::size_t write(Buffer &buffer, std::size_t offset) const override;
  std::size_t read(const Buffer &buffer, std::size_t offset) override;
  [[nodiscard]] std::unique_ptr<Field> clone() const override;
  [[nodiscard]] std::unique_ptr<Field> empty() const override;
  [[nodiscard]] int compare(const Field &other) const override;
  [[nodiscard]] int compare_stored(
      const DataBuffer &buffer, std::size_t offset) const override;
  [[nodiscard]] std::int32_t hash_code() const override;
  [[nodiscard]] std::string value_string() const override;
  [[nodiscard]] std::unique_ptr<Field> minimum() const override;
  [[nodiscard]] std::unique_ptr<Field> maximum() const override;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> as_bytes() const override {
    return value_;
  }
  void set_bytes(std::optional<std::vector<std::uint8_t>> value) override;

private:
  std::vector<std::uint8_t> value_;
  bool null_ = false;
};

class IndexField : public Field {
public:
  IndexField(const Field &indexed_field, const Field &primary_key);
  [[nodiscard]] FieldType type() const noexcept override;
  [[nodiscard]] bool same_type(const Field &other) const noexcept override;
  [[nodiscard]] bool variable_length() const noexcept override;
  [[nodiscard]] bool is_null() const noexcept override { return false; }
  void set_null() override;
  [[nodiscard]] std::size_t storage_length() const noexcept override;
  std::size_t write(Buffer &buffer, std::size_t offset) const override;
  std::size_t read(const Buffer &buffer, std::size_t offset) override;
  [[nodiscard]] std::size_t read_length(
      const Buffer &buffer, std::size_t offset) const override;
  [[nodiscard]] std::unique_ptr<Field> clone() const override;
  [[nodiscard]] std::unique_ptr<Field> empty() const override;
  [[nodiscard]] int compare(const Field &other) const override;
  [[nodiscard]] int compare_stored(
      const DataBuffer &buffer, std::size_t offset) const override;
  [[nodiscard]] bool equals(const Field &other) const override;
  [[nodiscard]] std::int32_t hash_code() const override;
  [[nodiscard]] std::string value_string() const override;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> as_bytes() const override;
  void set_bytes(std::optional<std::vector<std::uint8_t>> value) override;

  [[nodiscard]] const Field &indexed_field() const noexcept { return *indexed_field_; }
  [[nodiscard]] const Field &primary_key() const noexcept { return *primary_key_; }
  [[nodiscard]] bool uses_truncated_value() const noexcept { return truncated_; }
  [[nodiscard]] bool has_same_index_value(const IndexField &other) const;
  [[nodiscard]] virtual std::unique_ptr<IndexField> new_index_field(
      const Field &indexed_value, const Field &key) const;

  [[nodiscard]] static std::uint8_t encoded_index_type(
      const Field &indexed_field, const Field &primary_key);

protected:
  IndexField(std::unique_ptr<Field> indexed_field,
             std::unique_ptr<Field> primary_key, bool apply_truncation);

  std::unique_ptr<Field> indexed_field_;
  std::unique_ptr<Field> primary_key_;
  bool truncated_ = false;
};

class LegacyIndexField final : public IndexField {
public:
  explicit LegacyIndexField(const Field &indexed_field);
  LegacyIndexField(const Field &indexed_field, const Field &primary_key);
  [[nodiscard]] FieldType type() const noexcept override;
  [[nodiscard]] bool variable_length() const noexcept override { return true; }
  [[nodiscard]] std::unique_ptr<Field> clone() const override;
  [[nodiscard]] std::unique_ptr<Field> empty() const override;
  [[nodiscard]] std::unique_ptr<IndexField> new_index_field(
      const Field &indexed_value, const Field &key) const override;
};

[[nodiscard]] std::unique_ptr<Field> make_field(FieldType type);
[[nodiscard]] std::unique_ptr<Field> make_field(std::uint8_t encoded_type);
[[nodiscard]] bool can_index(const Field *field) noexcept;

} // namespace llmghidra::db
