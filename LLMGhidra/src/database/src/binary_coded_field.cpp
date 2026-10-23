/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/binary_coded_field.hpp"

#include <bit>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace llmghidra::db {
namespace {

void append_u16(std::vector<std::uint8_t> &output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 8));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t> &output, std::uint32_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 24));
  output.push_back(static_cast<std::uint8_t>(value >> 16));
  output.push_back(static_cast<std::uint8_t>(value >> 8));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

std::uint16_t read_u16(
    std::span<const std::uint8_t> input, std::size_t offset) {
  if (offset > input.size() || input.size() - offset < 2) {
    throw std::invalid_argument("truncated BinaryCodedField short");
  }
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(input[offset]) << 8) | input[offset + 1]);
}

std::uint32_t read_u32(
    std::span<const std::uint8_t> input, std::size_t offset) {
  if (offset > input.size() || input.size() - offset < 4) {
    throw std::invalid_argument("truncated BinaryCodedField integer");
  }
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value = (value << 8) | input[offset + index];
  }
  return value;
}

std::uint64_t read_u64(
    std::span<const std::uint8_t> input, std::size_t offset) {
  if (offset > input.size() || input.size() - offset < 8) {
    throw std::invalid_argument("truncated BinaryCodedField long");
  }
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8) | input[offset + index];
  }
  return value;
}

std::uint32_t java_float_bits(float value) {
  return std::isnan(value) ? 0x7fc00000u : std::bit_cast<std::uint32_t>(value);
}

std::uint64_t java_double_bits(double value) {
  return std::isnan(value) ? 0x7ff8000000000000ULL
                           : std::bit_cast<std::uint64_t>(value);
}

std::vector<std::uint8_t> array_prefix(
    BinaryCodedType type, bool has_value, std::size_t payload_size) {
  if (payload_size > std::numeric_limits<std::size_t>::max() - 2) {
    throw std::length_error("BinaryCodedField array is too large");
  }
  std::vector<std::uint8_t> output;
  output.reserve(payload_size + 2);
  output.push_back(static_cast<std::uint8_t>(type));
  output.push_back(has_value ? 0 : 0xff);
  return output;
}

bool array_is_null(std::span<const std::uint8_t> encoded) {
  if (encoded.size() < 2) {
    throw std::invalid_argument("truncated BinaryCodedField array marker");
  }
  return std::bit_cast<std::int8_t>(encoded[1]) < 0;
}

} // namespace

BinaryCodedField::BinaryCodedField(const BinaryField &field)
    : BinaryField(field.as_bytes()) {}

BinaryCodedField::BinaryCodedField(float value) {
  value_ = std::vector<std::uint8_t>{
      static_cast<std::uint8_t>(BinaryCodedType::float32)};
  append_u32(*value_, java_float_bits(value));
}

BinaryCodedField::BinaryCodedField(double value) {
  value_ = std::vector<std::uint8_t>{
      static_cast<std::uint8_t>(BinaryCodedType::float64)};
  append_u64(*value_, java_double_bits(value));
}

BinaryCodedField::BinaryCodedField(
    std::vector<std::uint8_t> encoded, int)
    : BinaryField(std::move(encoded)) {}

BinaryCodedField BinaryCodedField::from_byte_array(
    std::optional<std::vector<std::uint8_t>> values) {
  auto encoded = array_prefix(BinaryCodedType::byte_array, values.has_value(),
                              values ? values->size() : 0);
  if (values) encoded.insert(encoded.end(), values->begin(), values->end());
  return BinaryCodedField(std::move(encoded), 0);
}

BinaryCodedField BinaryCodedField::from_int16_array(
    std::optional<std::vector<std::int16_t>> values) {
  auto encoded = array_prefix(BinaryCodedType::int16_array, values.has_value(),
                              values ? values->size() * 2 : 0);
  if (values) {
    for (const auto value : *values) {
      append_u16(encoded, std::bit_cast<std::uint16_t>(value));
    }
  }
  return BinaryCodedField(std::move(encoded), 0);
}

BinaryCodedField BinaryCodedField::from_int32_array(
    std::optional<std::vector<std::int32_t>> values) {
  auto encoded = array_prefix(BinaryCodedType::int32_array, values.has_value(),
                              values ? values->size() * 4 : 0);
  if (values) {
    for (const auto value : *values) {
      append_u32(encoded, std::bit_cast<std::uint32_t>(value));
    }
  }
  return BinaryCodedField(std::move(encoded), 0);
}

BinaryCodedField BinaryCodedField::from_int64_array(
    std::optional<std::vector<std::int64_t>> values) {
  auto encoded = array_prefix(BinaryCodedType::int64_array, values.has_value(),
                              values ? values->size() * 8 : 0);
  if (values) {
    for (const auto value : *values) {
      append_u64(encoded, std::bit_cast<std::uint64_t>(value));
    }
  }
  return BinaryCodedField(std::move(encoded), 0);
}

BinaryCodedField BinaryCodedField::from_float32_array(
    std::optional<std::vector<float>> values) {
  auto encoded = array_prefix(BinaryCodedType::float32_array, values.has_value(),
                              values ? values->size() * 4 : 0);
  if (values) {
    for (const auto value : *values) append_u32(encoded, java_float_bits(value));
  }
  return BinaryCodedField(std::move(encoded), 0);
}

BinaryCodedField BinaryCodedField::from_float64_array(
    std::optional<std::vector<double>> values) {
  auto encoded = array_prefix(BinaryCodedType::float64_array, values.has_value(),
                              values ? values->size() * 8 : 0);
  if (values) {
    for (const auto value : *values) append_u64(encoded, java_double_bits(value));
  }
  return BinaryCodedField(std::move(encoded), 0);
}

BinaryCodedField BinaryCodedField::from_string_array(
    std::optional<std::vector<std::optional<std::string>>> values) {
  std::vector<std::vector<std::uint8_t>> strings;
  std::size_t payload_size = 0;
  if (values) {
    strings.reserve(values->size());
    for (const auto &value : *values) {
      payload_size += 4;
      if (value) {
        StringField string_field(value);
        auto bytes = *string_field.as_bytes();
        payload_size += bytes.size();
        strings.push_back(std::move(bytes));
      }
      else {
        strings.emplace_back();
      }
    }
  }

  auto encoded = array_prefix(BinaryCodedType::string_array,
                              values.has_value(), payload_size);
  if (values) {
    for (std::size_t index = 0; index < values->size(); ++index) {
      if (!(*values)[index]) {
        append_u32(encoded, 0xffffffffu);
      }
      else {
        if (strings[index].size() >
            static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
          throw std::length_error("BinaryCodedField string is too large");
        }
        append_u32(encoded, static_cast<std::uint32_t>(strings[index].size()));
        encoded.insert(encoded.end(), strings[index].begin(), strings[index].end());
      }
    }
  }
  return BinaryCodedField(std::move(encoded), 0);
}

const std::vector<std::uint8_t> &BinaryCodedField::require_encoded(
    BinaryCodedType expected) const {
  if (!value_ || value_->empty()) {
    throw std::logic_error("BinaryCodedField has no encoded value");
  }
  if (value_->front() != static_cast<std::uint8_t>(expected)) {
    throw std::logic_error("BinaryCodedField data type differs");
  }
  return *value_;
}

BinaryCodedType BinaryCodedField::data_type() const {
  if (!value_ || value_->empty() || value_->front() >
                                          static_cast<std::uint8_t>(
                                              BinaryCodedType::string_array)) {
    throw std::logic_error("BinaryCodedField has an invalid data type");
  }
  return static_cast<BinaryCodedType>(value_->front());
}

float BinaryCodedField::float32_value() const {
  const auto &encoded = require_encoded(BinaryCodedType::float32);
  return std::bit_cast<float>(read_u32(encoded, 1));
}

double BinaryCodedField::float64_value() const {
  const auto &encoded = require_encoded(BinaryCodedType::float64);
  return std::bit_cast<double>(read_u64(encoded, 1));
}

std::optional<std::vector<std::uint8_t>> BinaryCodedField::byte_array() const {
  const auto &encoded = require_encoded(BinaryCodedType::byte_array);
  if (array_is_null(encoded)) return std::nullopt;
  return std::vector<std::uint8_t>(encoded.begin() + 2, encoded.end());
}

std::optional<std::vector<std::int16_t>> BinaryCodedField::int16_array() const {
  const auto &encoded = require_encoded(BinaryCodedType::int16_array);
  if (array_is_null(encoded)) return std::nullopt;
  std::vector<std::int16_t> result;
  result.reserve((encoded.size() - 2) / 2);
  for (std::size_t offset = 2; offset + 2 <= encoded.size(); offset += 2) {
    result.push_back(std::bit_cast<std::int16_t>(read_u16(encoded, offset)));
  }
  return result;
}

std::optional<std::vector<std::int32_t>> BinaryCodedField::int32_array() const {
  const auto &encoded = require_encoded(BinaryCodedType::int32_array);
  if (array_is_null(encoded)) return std::nullopt;
  std::vector<std::int32_t> result;
  result.reserve((encoded.size() - 2) / 4);
  for (std::size_t offset = 2; offset + 4 <= encoded.size(); offset += 4) {
    result.push_back(std::bit_cast<std::int32_t>(read_u32(encoded, offset)));
  }
  return result;
}

std::optional<std::vector<std::int64_t>> BinaryCodedField::int64_array() const {
  const auto &encoded = require_encoded(BinaryCodedType::int64_array);
  if (array_is_null(encoded)) return std::nullopt;
  std::vector<std::int64_t> result;
  result.reserve((encoded.size() - 2) / 8);
  for (std::size_t offset = 2; offset + 8 <= encoded.size(); offset += 8) {
    result.push_back(std::bit_cast<std::int64_t>(read_u64(encoded, offset)));
  }
  return result;
}

std::optional<std::vector<float>> BinaryCodedField::float32_array() const {
  const auto &encoded = require_encoded(BinaryCodedType::float32_array);
  if (array_is_null(encoded)) return std::nullopt;
  std::vector<float> result;
  result.reserve((encoded.size() - 2) / 4);
  for (std::size_t offset = 2; offset + 4 <= encoded.size(); offset += 4) {
    result.push_back(std::bit_cast<float>(read_u32(encoded, offset)));
  }
  return result;
}

std::optional<std::vector<double>> BinaryCodedField::float64_array() const {
  const auto &encoded = require_encoded(BinaryCodedType::float64_array);
  if (array_is_null(encoded)) return std::nullopt;
  std::vector<double> result;
  result.reserve((encoded.size() - 2) / 8);
  for (std::size_t offset = 2; offset + 8 <= encoded.size(); offset += 8) {
    result.push_back(std::bit_cast<double>(read_u64(encoded, offset)));
  }
  return result;
}

std::optional<std::vector<std::optional<std::string>>>
BinaryCodedField::string_array() const {
  const auto &encoded = require_encoded(BinaryCodedType::string_array);
  if (array_is_null(encoded)) return std::nullopt;
  std::vector<std::optional<std::string>> result;
  std::size_t offset = 2;
  while (offset < encoded.size()) {
    const auto length_bits = read_u32(encoded, offset);
    offset += 4;
    const auto length = std::bit_cast<std::int32_t>(length_bits);
    if (length < 0) {
      result.emplace_back(std::nullopt);
      continue;
    }
    const auto count = static_cast<std::size_t>(length);
    if (offset > encoded.size() || count > encoded.size() - offset) {
      throw std::invalid_argument("truncated BinaryCodedField string array");
    }
    StringField field;
    field.set_bytes(std::vector<std::uint8_t>(
        encoded.begin() + static_cast<std::ptrdiff_t>(offset),
        encoded.begin() + static_cast<std::ptrdiff_t>(offset + count)));
    result.push_back(field.as_string());
    offset += count;
  }
  return result;
}

} // namespace llmghidra::db
