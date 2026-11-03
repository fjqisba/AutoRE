/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/field.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {

enum class BinaryCodedType : std::uint8_t {
  byte_array = 0,
  float32 = 1,
  float64 = 2,
  int16_array = 3,
  int32_array = 4,
  int64_array = 5,
  float32_array = 6,
  float64_array = 7,
  string_array = 8,
};

// Typed payload helper stored through the ordinary BinaryField schema type.
// Its wire encoding is byte-for-byte compatible with db.BinaryCodedField.
class BinaryCodedField final : public BinaryField {
public:
  BinaryCodedField() = default;
  explicit BinaryCodedField(const BinaryField &field);
  explicit BinaryCodedField(float value);
  explicit BinaryCodedField(double value);

  [[nodiscard]] static BinaryCodedField from_byte_array(
      std::optional<std::vector<std::uint8_t>> values);
  [[nodiscard]] static BinaryCodedField from_int16_array(
      std::optional<std::vector<std::int16_t>> values);
  [[nodiscard]] static BinaryCodedField from_int32_array(
      std::optional<std::vector<std::int32_t>> values);
  [[nodiscard]] static BinaryCodedField from_int64_array(
      std::optional<std::vector<std::int64_t>> values);
  [[nodiscard]] static BinaryCodedField from_float32_array(
      std::optional<std::vector<float>> values);
  [[nodiscard]] static BinaryCodedField from_float64_array(
      std::optional<std::vector<double>> values);
  [[nodiscard]] static BinaryCodedField from_string_array(
      std::optional<std::vector<std::optional<std::string>>> values);

  [[nodiscard]] BinaryCodedType data_type() const;
  [[nodiscard]] float float32_value() const;
  [[nodiscard]] double float64_value() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> byte_array() const;
  [[nodiscard]] std::optional<std::vector<std::int16_t>> int16_array() const;
  [[nodiscard]] std::optional<std::vector<std::int32_t>> int32_array() const;
  [[nodiscard]] std::optional<std::vector<std::int64_t>> int64_array() const;
  [[nodiscard]] std::optional<std::vector<float>> float32_array() const;
  [[nodiscard]] std::optional<std::vector<double>> float64_array() const;
  [[nodiscard]] std::optional<std::vector<std::optional<std::string>>>
      string_array() const;

private:
  explicit BinaryCodedField(std::vector<std::uint8_t> encoded, int);
  [[nodiscard]] const std::vector<std::uint8_t> &require_encoded(
      BinaryCodedType expected) const;
};

} // namespace llmghidra::db
