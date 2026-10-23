/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/field.hpp"

#include <algorithm>
#include <bit>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <typeinfo>

namespace llmghidra::db {
namespace {

[[noreturn]] void unsupported() {
  throw std::logic_error("unsupported field access");
}

void require_same(const Field &left, const Field &right) {
  if (!left.same_type(right)) {
    throw std::invalid_argument("field types differ");
  }
}

std::size_t integer_width(FieldType type) {
  switch (type) {
  case FieldType::byte: return 1;
  case FieldType::int16: return 2;
  case FieldType::int32: return 4;
  case FieldType::int64: return 8;
  default: throw std::invalid_argument("not an integer field type");
  }
}

std::int64_t narrow_integer(FieldType type, std::int64_t value) {
  const auto bits = std::bit_cast<std::uint64_t>(value);
  switch (type) {
  case FieldType::byte:
    return std::bit_cast<std::int8_t>(static_cast<std::uint8_t>(bits));
  case FieldType::int16:
    return std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(bits));
  case FieldType::int32:
    return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(bits));
  case FieldType::int64: return value;
  default: throw std::invalid_argument("not an integer field type");
  }
}

std::vector<std::uint16_t> decode_utf8(std::span<const std::uint8_t> input) {
  std::vector<std::uint16_t> output;
  output.reserve(input.size());
  std::size_t offset = 0;
  while (offset < input.size()) {
    const auto first = input[offset];
    std::uint32_t code_point = 0;
    std::size_t length = 0;
    if (first < 0x80) {
      code_point = first;
      length = 1;
    }
    else if (first >= 0xc2 && first <= 0xdf) {
      code_point = first & 0x1f;
      length = 2;
    }
    else if (first >= 0xe0 && first <= 0xef) {
      code_point = first & 0x0f;
      length = 3;
    }
    else if (first >= 0xf0 && first <= 0xf4) {
      code_point = first & 0x07;
      length = 4;
    }
    else {
      output.push_back(0xfffd);
      ++offset;
      continue;
    }

    bool valid = offset + length <= input.size();
    for (std::size_t index = 1; valid && index < length; ++index) {
      const auto next = input[offset + index];
      if ((next & 0xc0) != 0x80) valid = false;
      else code_point = (code_point << 6) | (next & 0x3f);
    }
    if (valid && ((length == 3 && code_point < 0x800) ||
                  (length == 4 && code_point < 0x10000) ||
                  code_point > 0x10ffff ||
                  (code_point >= 0xd800 && code_point <= 0xdfff))) {
      valid = false;
    }
    if (!valid) {
      output.push_back(0xfffd);
      ++offset;
      continue;
    }

    if (code_point <= 0xffff) {
      output.push_back(static_cast<std::uint16_t>(code_point));
    }
    else {
      code_point -= 0x10000;
      output.push_back(static_cast<std::uint16_t>(0xd800 + (code_point >> 10)));
      output.push_back(static_cast<std::uint16_t>(0xdc00 + (code_point & 0x3ff)));
    }
    offset += length;
  }
  return output;
}

std::vector<std::uint8_t> encode_utf16(
    std::span<const std::uint16_t> input) {
  std::vector<std::uint8_t> output;
  output.reserve(input.size());
  for (std::size_t index = 0; index < input.size(); ++index) {
    std::uint32_t code_point = input[index];
    if (code_point >= 0xd800 && code_point <= 0xdbff) {
      if (index + 1 < input.size() && input[index + 1] >= 0xdc00 &&
          input[index + 1] <= 0xdfff) {
        code_point = 0x10000 + ((code_point - 0xd800) << 10) +
                     (input[++index] - 0xdc00);
      }
      else {
        // CharsetEncoder's default replacement for an isolated Java surrogate.
        output.push_back('?');
        continue;
      }
    }
    else if (code_point >= 0xdc00 && code_point <= 0xdfff) {
      output.push_back('?');
      continue;
    }

    if (code_point < 0x80) {
      output.push_back(static_cast<std::uint8_t>(code_point));
    }
    else if (code_point < 0x800) {
      output.push_back(static_cast<std::uint8_t>(0xc0 | (code_point >> 6)));
      output.push_back(static_cast<std::uint8_t>(0x80 | (code_point & 0x3f)));
    }
    else if (code_point < 0x10000) {
      output.push_back(static_cast<std::uint8_t>(0xe0 | (code_point >> 12)));
      output.push_back(static_cast<std::uint8_t>(0x80 | ((code_point >> 6) & 0x3f)));
      output.push_back(static_cast<std::uint8_t>(0x80 | (code_point & 0x3f)));
    }
    else {
      output.push_back(static_cast<std::uint8_t>(0xf0 | (code_point >> 18)));
      output.push_back(static_cast<std::uint8_t>(0x80 | ((code_point >> 12) & 0x3f)));
      output.push_back(static_cast<std::uint8_t>(0x80 | ((code_point >> 6) & 0x3f)));
      output.push_back(static_cast<std::uint8_t>(0x80 | (code_point & 0x3f)));
    }
  }
  return output;
}

std::string bytes_to_string(std::span<const std::uint8_t> bytes) {
  return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

std::string normalized_utf8(std::span<const std::uint8_t> bytes) {
  const auto utf16 = decode_utf8(bytes);
  const auto encoded = encode_utf16(utf16);
  return bytes_to_string(encoded);
}

std::vector<std::uint8_t> string_bytes(const std::string &value) {
  return {reinterpret_cast<const std::uint8_t *>(value.data()),
          reinterpret_cast<const std::uint8_t *>(value.data()) + value.size()};
}

int compare_utf16(const std::string &left, const std::string &right) {
  const auto lhs = decode_utf8(string_bytes(left));
  const auto rhs = decode_utf8(string_bytes(right));
  const auto count = (std::min)(lhs.size(), rhs.size());
  for (std::size_t index = 0; index < count; ++index) {
    if (lhs[index] != rhs[index]) {
      return static_cast<int>(lhs[index]) - static_cast<int>(rhs[index]);
    }
  }
  if (lhs.size() == rhs.size()) return 0;
  return lhs.size() < rhs.size() ? -static_cast<int>(rhs.size() - lhs.size())
                                 : static_cast<int>(lhs.size() - rhs.size());
}

std::string hex_integer(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::nouppercase << value;
  return stream.str();
}

std::string binary_value_string(std::span<const std::uint8_t> bytes) {
  std::ostringstream stream;
  stream << std::hex << std::nouppercase << std::setfill('0');
  const auto count = (std::min)(std::size_t{24}, bytes.size());
  for (std::size_t index = 0; index < count; ++index) {
    stream << std::setw(2) << static_cast<unsigned>(bytes[index]) << ' ';
  }
  if (count < bytes.size()) stream << "...";
  return stream.str();
}

std::int32_t finish_hash(std::uint32_t value) {
  return std::bit_cast<std::int32_t>(value);
}

} // namespace

bool Field::same_type(const Field &other) const noexcept {
  return typeid(*this) == typeid(other);
}

std::size_t Field::read_length(const Buffer &, std::size_t) const {
  return storage_length();
}

void Field::truncate(std::size_t) { unsupported(); }

int Field::compare_stored(const DataBuffer &buffer, std::size_t offset) const {
  auto stored = empty();
  stored->read(buffer, offset);
  return compare(*stored);
}

bool Field::equals(const Field &other) const {
  return same_type(other) && compare(other) == 0;
}

std::unique_ptr<Field> Field::minimum() const { unsupported(); }
std::unique_ptr<Field> Field::maximum() const { unsupported(); }
std::int64_t Field::as_integer() const { unsupported(); }
void Field::set_integer(std::int64_t) { unsupported(); }
bool Field::as_boolean() const { unsupported(); }
void Field::set_boolean(bool) { unsupported(); }
std::optional<std::vector<std::uint8_t>> Field::as_bytes() const { unsupported(); }
void Field::set_bytes(std::optional<std::vector<std::uint8_t>>) { unsupported(); }
std::optional<std::string> Field::as_string() const { unsupported(); }
void Field::set_string(std::optional<std::string>) { unsupported(); }

IntegerField::IntegerField(FieldType type, std::int64_t value)
    : type_(type), value_(narrow_integer(type, value)) {
  (void)integer_width(type_);
}

bool IntegerField::same_type(const Field &other) const noexcept {
  const auto *integer = dynamic_cast<const IntegerField *>(&other);
  return integer && integer->type_ == type_;
}

void IntegerField::set_null() {
  null_ = true;
  value_ = 0;
}

std::size_t IntegerField::storage_length() const noexcept {
  switch (type_) {
  case FieldType::byte: return 1;
  case FieldType::int16: return 2;
  case FieldType::int32: return 4;
  case FieldType::int64: return 8;
  default: return 0;
  }
}

std::size_t IntegerField::write(Buffer &buffer, std::size_t offset) const {
  switch (type_) {
  case FieldType::byte:
    return buffer.put_u8(offset, static_cast<std::uint8_t>(value_));
  case FieldType::int16:
    return buffer.put_i16(offset, static_cast<std::int16_t>(value_));
  case FieldType::int32:
    return buffer.put_i32(offset, static_cast<std::int32_t>(value_));
  case FieldType::int64: return buffer.put_i64(offset, value_);
  default: throw std::logic_error("invalid integer field");
  }
}

std::size_t IntegerField::read(const Buffer &buffer, std::size_t offset) {
  switch (type_) {
  case FieldType::byte:
    value_ = std::bit_cast<std::int8_t>(buffer.get_u8(offset));
    break;
  case FieldType::int16: value_ = buffer.get_i16(offset); break;
  case FieldType::int32: value_ = buffer.get_i32(offset); break;
  case FieldType::int64: value_ = buffer.get_i64(offset); break;
  default: throw std::logic_error("invalid integer field");
  }
  null_ = false;
  return offset + storage_length();
}

std::unique_ptr<Field> IntegerField::clone() const {
  return std::make_unique<IntegerField>(*this);
}

std::unique_ptr<Field> IntegerField::empty() const {
  return std::make_unique<IntegerField>(type_);
}

int IntegerField::compare(const Field &other) const {
  require_same(*this, other);
  const auto rhs = other.as_integer();
  return (value_ > rhs) - (value_ < rhs);
}

int IntegerField::compare_stored(
    const DataBuffer &buffer, std::size_t offset) const {
  IntegerField stored(type_);
  stored.read(buffer, offset);
  return compare(stored);
}

std::int32_t IntegerField::hash_code() const {
  if (type_ != FieldType::int64) return static_cast<std::int32_t>(value_);
  const auto bits = std::bit_cast<std::uint64_t>(value_);
  return finish_hash(static_cast<std::uint32_t>(bits ^ (bits >> 32)));
}

std::string IntegerField::value_string() const {
  switch (type_) {
  case FieldType::byte:
    return hex_integer(static_cast<std::uint8_t>(value_));
  case FieldType::int16:
    return hex_integer(static_cast<std::uint16_t>(value_));
  case FieldType::int32:
    return hex_integer(static_cast<std::uint32_t>(value_));
  case FieldType::int64:
    return hex_integer(static_cast<std::uint64_t>(value_));
  default: unsupported();
  }
}

std::unique_ptr<Field> IntegerField::minimum() const {
  switch (type_) {
  case FieldType::byte:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int8_t>::min());
  case FieldType::int16:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int16_t>::min());
  case FieldType::int32:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int32_t>::min());
  case FieldType::int64:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int64_t>::min());
  default: unsupported();
  }
}

std::unique_ptr<Field> IntegerField::maximum() const {
  switch (type_) {
  case FieldType::byte:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int8_t>::max());
  case FieldType::int16:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int16_t>::max());
  case FieldType::int32:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int32_t>::max());
  case FieldType::int64:
    return std::make_unique<IntegerField>(type_,
                                           std::numeric_limits<std::int64_t>::max());
  default: unsupported();
  }
}

void IntegerField::set_integer(std::int64_t value) {
  value_ = narrow_integer(type_, value);
  null_ = false;
}

std::optional<std::vector<std::uint8_t>> IntegerField::as_bytes() const {
  DataBuffer buffer(storage_length());
  write(buffer, 0);
  return buffer.bytes();
}

void IntegerField::set_bytes(
    std::optional<std::vector<std::uint8_t>> value) {
  if (!value) {
    set_null();
    return;
  }
  if (value->size() != storage_length()) {
    throw std::invalid_argument("integer binary width differs");
  }
  read(DataBuffer(std::move(*value)), 0);
}

void BooleanField::set_null() {
  value_ = 0;
  null_ = true;
}

std::size_t BooleanField::write(Buffer &buffer, std::size_t offset) const {
  return buffer.put_u8(offset, std::bit_cast<std::uint8_t>(value_));
}

std::size_t BooleanField::read(const Buffer &buffer, std::size_t offset) {
  value_ = std::bit_cast<std::int8_t>(buffer.get_u8(offset));
  null_ = false;
  return offset + 1;
}

std::unique_ptr<Field> BooleanField::clone() const {
  return std::make_unique<BooleanField>(*this);
}

std::unique_ptr<Field> BooleanField::empty() const {
  return std::make_unique<BooleanField>();
}

int BooleanField::compare(const Field &other) const {
  require_same(*this, other);
  const auto rhs = other.as_integer();
  return (value_ > rhs) - (value_ < rhs);
}

int BooleanField::compare_stored(
    const DataBuffer &buffer, std::size_t offset) const {
  const auto rhs = std::bit_cast<std::int8_t>(buffer.get_u8(offset));
  return (value_ > rhs) - (value_ < rhs);
}

std::string BooleanField::value_string() const {
  return value_ == 0 ? "false" : "true";
}

std::unique_ptr<Field> BooleanField::minimum() const {
  return std::make_unique<BooleanField>(false);
}

std::unique_ptr<Field> BooleanField::maximum() const {
  return std::make_unique<BooleanField>(true);
}

void BooleanField::set_boolean(bool value) {
  value_ = value ? 1 : 0;
  null_ = false;
}

std::optional<std::vector<std::uint8_t>> BooleanField::as_bytes() const {
  return std::vector<std::uint8_t>{std::bit_cast<std::uint8_t>(value_)};
}

void BooleanField::set_bytes(
    std::optional<std::vector<std::uint8_t>> value) {
  if (!value) {
    set_null();
    return;
  }
  if (value->size() != 1) {
    throw std::invalid_argument("boolean binary width differs");
  }
  value_ = std::bit_cast<std::int8_t>(value->front());
  null_ = false;
}

std::size_t BinaryField::storage_length() const noexcept {
  return 4 + (value_ ? value_->size() : 0);
}

std::size_t BinaryField::write(Buffer &buffer, std::size_t offset) const {
  if (!value_) return buffer.put_i32(offset, -1);
  if (value_->size() >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::length_error("binary field exceeds Ghidra length limit");
  }
  offset = buffer.put_i32(offset, static_cast<std::int32_t>(value_->size()));
  return buffer.put(offset, *value_);
}

std::size_t BinaryField::read(const Buffer &buffer, std::size_t offset) {
  const auto length = buffer.get_i32(offset);
  offset += 4;
  if (length < 0) {
    value_.reset();
  }
  else {
    value_ = buffer.get(offset, static_cast<std::size_t>(length));
    offset += static_cast<std::size_t>(length);
  }
  return offset;
}

std::size_t BinaryField::read_length(
    const Buffer &buffer, std::size_t offset) const {
  const auto length = buffer.get_i32(offset);
  return 4 + (length < 0 ? 0 : static_cast<std::size_t>(length));
}

void BinaryField::truncate(std::size_t total_storage_length) {
  if (total_storage_length < 4) {
    throw std::invalid_argument("binary field truncation length is below prefix size");
  }
  const auto maximum_data_length = total_storage_length - 4;
  if (value_ && value_->size() > maximum_data_length) {
    value_->resize(maximum_data_length);
  }
}

std::unique_ptr<Field> BinaryField::clone() const {
  return std::make_unique<BinaryField>(*this);
}

std::unique_ptr<Field> BinaryField::empty() const {
  return std::make_unique<BinaryField>();
}

int BinaryField::compare(const Field &other) const {
  require_same(*this, other);
  const auto rhs = other.as_bytes();
  if (!value_) return rhs ? -1 : 0;
  if (!rhs) return 1;
  const auto count = (std::min)(value_->size(), rhs->size());
  for (std::size_t index = 0; index < count; ++index) {
    const int difference = static_cast<int>((*value_)[index]) -
                           static_cast<int>((*rhs)[index]);
    if (difference != 0) return difference;
  }
  if (value_->size() == rhs->size()) return 0;
  return value_->size() < rhs->size()
             ? -static_cast<int>(rhs->size() - value_->size())
             : static_cast<int>(value_->size() - rhs->size());
}

int BinaryField::compare_stored(
    const DataBuffer &buffer, std::size_t offset) const {
  const auto stored_length = buffer.get_i32(offset);
  if (!value_) return stored_length < 0 ? 0 : -1;
  if (stored_length < 0) return 1;
  return -buffer.unsigned_compare_to(
      *value_, offset + 4, static_cast<std::size_t>(stored_length));
}

std::int32_t BinaryField::hash_code() const {
  std::uint32_t hash = 0;
  if (value_) {
    for (const auto byte : *value_) hash = 31u * hash + byte;
  }
  return finish_hash(hash);
}

std::string BinaryField::value_string() const {
  if (!value_) return "null";
  return "{" + binary_value_string(*value_) + "}";
}

StringField::StringField(std::optional<std::string> value) {
  set_string(std::move(value));
}

void StringField::set_null() {
  value_.reset();
  bytes_.reset();
}

std::size_t StringField::storage_length() const noexcept {
  return 4 + (bytes_ ? bytes_->size() : 0);
}

std::size_t StringField::write(Buffer &buffer, std::size_t offset) const {
  if (!bytes_) return buffer.put_i32(offset, -1);
  if (bytes_->size() >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::length_error("string field exceeds Ghidra length limit");
  }
  offset = buffer.put_i32(offset, static_cast<std::int32_t>(bytes_->size()));
  return buffer.put(offset, *bytes_);
}

std::size_t StringField::read(const Buffer &buffer, std::size_t offset) {
  const auto length = buffer.get_i32(offset);
  offset += 4;
  if (length < 0) {
    set_null();
  }
  else {
    bytes_ = buffer.get(offset, static_cast<std::size_t>(length));
    value_ = normalized_utf8(*bytes_);
    offset += static_cast<std::size_t>(length);
  }
  return offset;
}

std::size_t StringField::read_length(
    const Buffer &buffer, std::size_t offset) const {
  const auto length = buffer.get_i32(offset);
  return 4 + (length < 0 ? 0 : static_cast<std::size_t>(length));
}

void StringField::truncate(std::size_t total_storage_length) {
  if (total_storage_length < 4) {
    throw std::invalid_argument("string field truncation length is below prefix size");
  }
  if (!value_) return;
  auto utf16 = decode_utf8(string_bytes(*value_));
  const auto maximum_character_length = total_storage_length - 4;
  if (utf16.size() > maximum_character_length) {
    utf16.resize(maximum_character_length);
    const auto encoded = encode_utf16(utf16);
    bytes_ = encoded;
    value_ = bytes_to_string(encoded);
  }
}

std::unique_ptr<Field> StringField::clone() const {
  return std::make_unique<StringField>(*this);
}

std::unique_ptr<Field> StringField::empty() const {
  return std::make_unique<StringField>();
}

int StringField::compare(const Field &other) const {
  require_same(*this, other);
  const auto rhs = other.as_string();
  if (!value_) return rhs ? -1 : 0;
  if (!rhs) return 1;
  return compare_utf16(*value_, *rhs);
}

int StringField::compare_stored(
    const DataBuffer &buffer, std::size_t offset) const {
  StringField stored;
  stored.read(buffer, offset);
  return compare(stored);
}

std::int32_t StringField::hash_code() const {
  if (!value_) throw std::logic_error("null StringField has no Java hashCode");
  std::uint32_t hash = 0;
  for (const auto unit : decode_utf8(string_bytes(*value_))) {
    hash = 31u * hash + unit;
  }
  return finish_hash(hash);
}

std::string StringField::value_string() const {
  return value_ ? '"' + *value_ + '"' : "null";
}

void StringField::set_bytes(
    std::optional<std::vector<std::uint8_t>> value) {
  bytes_ = std::move(value);
  if (bytes_) value_ = normalized_utf8(*bytes_);
  else value_.reset();
}

void StringField::set_string(std::optional<std::string> value) {
  if (!value) {
    set_null();
    return;
  }
  const auto utf16 = decode_utf8(string_bytes(*value));
  bytes_ = encode_utf16(utf16);
  value_ = bytes_to_string(*bytes_);
}

Fixed10Field::Fixed10Field() : value_(10) {}

Fixed10Field::Fixed10Field(std::vector<std::uint8_t> value)
    : value_(std::move(value)) {
  if (value_.size() != 10) {
    throw std::invalid_argument("fixed10 field requires 10 bytes");
  }
}

void Fixed10Field::set_null() {
  std::fill(value_.begin(), value_.end(), std::uint8_t{0});
  null_ = true;
}

std::size_t Fixed10Field::write(Buffer &buffer, std::size_t offset) const {
  return buffer.put(offset, value_);
}

std::size_t Fixed10Field::read(const Buffer &buffer, std::size_t offset) {
  value_ = buffer.get(offset, 10);
  null_ = false;
  return offset + 10;
}

std::unique_ptr<Field> Fixed10Field::clone() const {
  return std::make_unique<Fixed10Field>(*this);
}

std::unique_ptr<Field> Fixed10Field::empty() const {
  return std::make_unique<Fixed10Field>();
}

int Fixed10Field::compare(const Field &other) const {
  require_same(*this, other);
  const auto rhs = other.as_bytes();
  if (!rhs || rhs->size() != 10) {
    throw std::invalid_argument("invalid fixed10 comparison field");
  }
  for (std::size_t index = 0; index < value_.size(); ++index) {
    if (value_[index] != (*rhs)[index]) {
      return value_[index] < (*rhs)[index] ? -1 : 1;
    }
  }
  return 0;
}

int Fixed10Field::compare_stored(
    const DataBuffer &buffer, std::size_t offset) const {
  const auto stored = buffer.get(offset, 10);
  for (std::size_t index = 0; index < value_.size(); ++index) {
    if (value_[index] != stored[index]) {
      return value_[index] < stored[index] ? -1 : 1;
    }
  }
  return 0;
}

std::int32_t Fixed10Field::hash_code() const {
  std::uint64_t high = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    high = (high << 8) | value_[index];
  }
  const auto low_bits = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(value_[8]) << 8) | value_[9]);
  const auto low = std::bit_cast<std::int16_t>(low_bits);
  std::uint32_t hash = static_cast<std::uint32_t>(high ^ (high >> 32));
  hash = 31u * hash + static_cast<std::uint32_t>(static_cast<std::int32_t>(low));
  return finish_hash(hash);
}

std::string Fixed10Field::value_string() const {
  return "{" + binary_value_string(value_) + "}";
}

std::unique_ptr<Field> Fixed10Field::minimum() const {
  return std::make_unique<Fixed10Field>(std::vector<std::uint8_t>(10, 0));
}

std::unique_ptr<Field> Fixed10Field::maximum() const {
  return std::make_unique<Fixed10Field>(std::vector<std::uint8_t>(10, 0xff));
}

void Fixed10Field::set_bytes(
    std::optional<std::vector<std::uint8_t>> value) {
  if (!value) {
    set_null();
    return;
  }
  if (value->size() != 10) {
    throw std::invalid_argument("fixed10 field requires 10 bytes");
  }
  value_ = std::move(*value);
  null_ = false;
}

IndexField::IndexField(const Field &indexed_field, const Field &primary_key)
    : IndexField(indexed_field.clone(), primary_key.clone(), true) {}

IndexField::IndexField(std::unique_ptr<Field> indexed_field,
                       std::unique_ptr<Field> primary_key,
                       bool apply_truncation)
    : indexed_field_(std::move(indexed_field)),
      primary_key_(std::move(primary_key)) {
  if (!indexed_field_ || !primary_key_) {
    throw std::invalid_argument("IndexField requires two field values");
  }
  if (primary_key_->variable_length()) {
    throw std::invalid_argument("variable-length primary key is unsupported");
  }
  (void)encoded_index_type(*indexed_field_, *primary_key_);
  if (apply_truncation && indexed_field_->variable_length() &&
      indexed_field_->storage_length() >= maximum_index_field_length) {
    indexed_field_->truncate(maximum_index_field_length);
    truncated_ = true;
  }
}

FieldType IndexField::type() const noexcept {
  return static_cast<FieldType>(
      encoded_index_type(*indexed_field_, *primary_key_));
}

bool IndexField::same_type(const Field &other) const noexcept {
  const auto *index = dynamic_cast<const IndexField *>(&other);
  return index && indexed_field_->same_type(*index->indexed_field_) &&
         primary_key_->same_type(*index->primary_key_);
}

bool IndexField::variable_length() const noexcept {
  return indexed_field_->variable_length();
}

void IndexField::set_null() {
  throw std::logic_error("IndexField cannot be set null");
}

std::size_t IndexField::storage_length() const noexcept {
  return indexed_field_->storage_length() + primary_key_->storage_length();
}

std::size_t IndexField::write(Buffer &buffer, std::size_t offset) const {
  offset = indexed_field_->write(buffer, offset);
  return primary_key_->write(buffer, offset);
}

std::size_t IndexField::read(const Buffer &buffer, std::size_t offset) {
  offset = indexed_field_->read(buffer, offset);
  return primary_key_->read(buffer, offset);
}

std::size_t IndexField::read_length(
    const Buffer &buffer, std::size_t offset) const {
  return indexed_field_->read_length(buffer, offset) +
         primary_key_->storage_length();
}

std::unique_ptr<Field> IndexField::clone() const {
  return std::make_unique<IndexField>(*indexed_field_, *primary_key_);
}

std::unique_ptr<Field> IndexField::empty() const {
  return std::make_unique<IndexField>(*indexed_field_->empty(),
                                      *primary_key_->empty());
}

int IndexField::compare(const Field &other) const {
  const auto *index = dynamic_cast<const IndexField *>(&other);
  if (!index || !same_type(other)) {
    throw std::invalid_argument("IndexField types differ");
  }
  const auto indexed_result = indexed_field_->compare(*index->indexed_field_);
  return indexed_result != 0
             ? indexed_result
             : primary_key_->compare(*index->primary_key_);
}

int IndexField::compare_stored(
    const DataBuffer &buffer, std::size_t offset) const {
  const auto indexed_result = indexed_field_->compare_stored(buffer, offset);
  if (indexed_result != 0) return indexed_result;
  return primary_key_->compare_stored(
      buffer, offset + indexed_field_->read_length(buffer, offset));
}

bool IndexField::equals(const Field &other) const {
  return typeid(*this) == typeid(other) && same_type(other) && compare(other) == 0;
}

std::int32_t IndexField::hash_code() const {
  const auto left = static_cast<std::uint32_t>(indexed_field_->hash_code());
  const auto right = static_cast<std::uint32_t>(primary_key_->hash_code());
  return finish_hash(left * 31u + right);
}

std::string IndexField::value_string() const {
  return indexed_field_->value_string() + " / " + primary_key_->value_string();
}

std::optional<std::vector<std::uint8_t>> IndexField::as_bytes() const {
  const auto indexed = indexed_field_->as_bytes();
  const auto primary = primary_key_->as_bytes();
  if (!indexed || !primary) {
    throw std::logic_error("null IndexField component has no binary form");
  }
  std::vector<std::uint8_t> result;
  result.reserve(indexed->size() + primary->size());
  result.insert(result.end(), indexed->begin(), indexed->end());
  result.insert(result.end(), primary->begin(), primary->end());
  return result;
}

void IndexField::set_bytes(
    std::optional<std::vector<std::uint8_t>> value) {
  if (variable_length()) {
    throw std::logic_error("binary assignment is unsupported for variable IndexField");
  }
  if (!value || value->size() != storage_length()) {
    throw std::invalid_argument("IndexField binary width differs");
  }
  DataBuffer buffer(std::move(*value));
  read(buffer, 0);
}

bool IndexField::has_same_index_value(const IndexField &other) const {
  return indexed_field_->equals(*other.indexed_field_);
}

std::unique_ptr<IndexField> IndexField::new_index_field(
    const Field &indexed_value, const Field &key) const {
  if (!indexed_value.same_type(*indexed_field_) ||
      !key.same_type(*primary_key_)) {
    throw std::invalid_argument("incorrect index value or key type");
  }
  return std::make_unique<IndexField>(indexed_value, key);
}

std::uint8_t IndexField::encoded_index_type(
    const Field &indexed_field, const Field &primary_key) {
  if (dynamic_cast<const IndexField *>(&indexed_field) ||
      dynamic_cast<const IndexField *>(&primary_key)) {
    throw std::invalid_argument("nested IndexField is unsupported");
  }
  const auto primary = primary_key.encoded_type();
  const auto indexed = indexed_field.encoded_type();
  if (primary > static_cast<std::uint8_t>(FieldType::fixed10) ||
      indexed > static_cast<std::uint8_t>(FieldType::fixed10) || primary == 0) {
    throw std::invalid_argument("unsupported IndexField component type");
  }
  return static_cast<std::uint8_t>((primary << 4) | indexed);
}

LegacyIndexField::LegacyIndexField(const Field &indexed_field)
    : IndexField(indexed_field,
                 IntegerField(FieldType::int64)) {}

LegacyIndexField::LegacyIndexField(const Field &indexed_field,
                                   const Field &primary_key)
    : IndexField(indexed_field, primary_key) {
  if (primary_key.type() != FieldType::int64 ||
      dynamic_cast<const IndexField *>(&primary_key)) {
    throw std::invalid_argument("LegacyIndexField requires a long primary key");
  }
}

FieldType LegacyIndexField::type() const noexcept {
  return static_cast<FieldType>(
      (legacy_index_long_type << 4) | indexed_field_->encoded_type());
}

std::unique_ptr<Field> LegacyIndexField::clone() const {
  return std::make_unique<LegacyIndexField>(*indexed_field_, *primary_key_);
}

std::unique_ptr<Field> LegacyIndexField::empty() const {
  return std::make_unique<LegacyIndexField>(*indexed_field_->empty(),
                                            *primary_key_->empty());
}

std::unique_ptr<IndexField> LegacyIndexField::new_index_field(
    const Field &indexed_value, const Field &key) const {
  if (!indexed_value.same_type(*indexed_field_) ||
      key.type() != FieldType::int64 || dynamic_cast<const IndexField *>(&key)) {
    throw std::invalid_argument("incorrect legacy index value or key type");
  }
  return std::make_unique<LegacyIndexField>(indexed_value, key);
}

std::unique_ptr<Field> make_field(FieldType type) {
  return make_field(static_cast<std::uint8_t>(type));
}

std::unique_ptr<Field> make_field(std::uint8_t encoded_type) {
  if (encoded_type == 0x88) {
    throw std::invalid_argument("reserved Ghidra field encoding 0x88");
  }
  const auto indexed_type = encoded_type & Field::field_type_mask;
  const auto primary_type = encoded_type >> 4;
  if (indexed_type > static_cast<std::uint8_t>(FieldType::fixed10)) {
    throw std::invalid_argument("unsupported Ghidra field base type");
  }
  if (primary_type != 0) {
    auto indexed = make_field(static_cast<std::uint8_t>(indexed_type));
    if (primary_type == Field::legacy_index_long_type) {
      return std::make_unique<LegacyIndexField>(*indexed);
    }
    if (primary_type == 0x0f ||
        primary_type > static_cast<std::uint8_t>(FieldType::fixed10)) {
      throw std::invalid_argument("unsupported Ghidra index primary key type");
    }
    auto primary = make_field(static_cast<std::uint8_t>(primary_type));
    return std::make_unique<IndexField>(*indexed, *primary);
  }

  const auto type = static_cast<FieldType>(indexed_type);
  switch (type) {
  case FieldType::byte:
  case FieldType::int16:
  case FieldType::int32:
  case FieldType::int64: return std::make_unique<IntegerField>(type);
  case FieldType::string: return std::make_unique<StringField>();
  case FieldType::binary: return std::make_unique<BinaryField>();
  case FieldType::boolean: return std::make_unique<BooleanField>();
  case FieldType::fixed10: return std::make_unique<Fixed10Field>();
  }
  throw std::invalid_argument("unsupported Ghidra field type");
}

bool can_index(const Field *field) noexcept {
  if (!field || dynamic_cast<const IndexField *>(field)) return false;
  return field->type() != FieldType::boolean && field->type() != FieldType::byte;
}

} // namespace llmghidra::db
