/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/buffer.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

#include "zlib.h"

namespace llmghidra::db {
namespace {

void append_i32(std::vector<std::uint8_t> &output, std::int32_t value) {
  const auto bits = std::bit_cast<std::uint32_t>(value);
  output.push_back(static_cast<std::uint8_t>(bits >> 24));
  output.push_back(static_cast<std::uint8_t>(bits >> 16));
  output.push_back(static_cast<std::uint8_t>(bits >> 8));
  output.push_back(static_cast<std::uint8_t>(bits));
}

std::int32_t read_i32(std::span<const std::uint8_t> input, std::size_t &offset) {
  if (offset > input.size() || input.size() - offset < 4) {
    throw DataBufferSerializationError("truncated DataBuffer integer");
  }
  std::uint32_t bits = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    bits = (bits << 8) | input[offset++];
  }
  return std::bit_cast<std::int32_t>(bits);
}

bool read_boolean(std::span<const std::uint8_t> input, std::size_t &offset) {
  if (offset == input.size()) {
    throw DataBufferSerializationError("truncated DataBuffer boolean");
  }
  return input[offset++] != 0;
}

std::optional<std::vector<std::uint8_t>> deflate_raw(
    std::span<const std::uint8_t> input) {
  if (input.empty() || input.size() > std::numeric_limits<uInt>::max()) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> compressed(input.size());
  z_stream stream{};
  if (deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, -MAX_WBITS, 8,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    throw DataBufferSerializationError("unable to initialize DataBuffer compression");
  }

  stream.next_in = const_cast<Bytef *>(input.data());
  stream.avail_in = static_cast<uInt>(input.size());
  stream.next_out = compressed.data();
  stream.avail_out = static_cast<uInt>(compressed.size());

  int result = Z_OK;
  while (result == Z_OK && stream.avail_out != 0) {
    result = deflate(&stream, Z_FINISH);
  }
  const auto output_size = stream.total_out;
  deflateEnd(&stream);

  if (result != Z_STREAM_END || output_size >= input.size()) {
    return std::nullopt;
  }
  compressed.resize(output_size);
  return compressed;
}

std::vector<std::uint8_t> inflate_raw(
    std::span<const std::uint8_t> compressed, std::size_t expected_size) {
  // Java's implementation cannot accept a compressed zero-length target: its
  // inflate loop is skipped and finished() remains false.
  if (expected_size == 0 ||
      compressed.size() > std::numeric_limits<uInt>::max() ||
      expected_size > std::numeric_limits<uInt>::max()) {
    throw DataBufferSerializationError("DataBuffer inflate size error");
  }

  std::vector<std::uint8_t> output(expected_size);
  z_stream stream{};
  if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
    throw DataBufferSerializationError("unable to initialize DataBuffer inflation");
  }

  stream.next_in = const_cast<Bytef *>(compressed.data());
  stream.avail_in = static_cast<uInt>(compressed.size());
  stream.next_out = output.data();
  stream.avail_out = static_cast<uInt>(output.size());

  int result = Z_OK;
  while (result == Z_OK && stream.avail_out != 0) {
    const auto previous_in = stream.total_in;
    const auto previous_out = stream.total_out;
    result = inflate(&stream, Z_NO_FLUSH);
    if (result == Z_OK && previous_in == stream.total_in &&
        previous_out == stream.total_out) {
      result = Z_BUF_ERROR;
    }
  }
  const auto output_size = stream.total_out;
  inflateEnd(&stream);

  if (result != Z_STREAM_END || output_size != expected_size) {
    throw DataBufferSerializationError("DataBuffer inflation failed or size mismatch");
  }
  return output;
}

} // namespace

DataBuffer::DataBuffer(std::size_t size)
    : data_(std::vector<std::uint8_t>(size)) {}
DataBuffer::DataBuffer(std::vector<std::uint8_t> data)
    : data_(std::move(data)) {}

const std::vector<std::uint8_t> &DataBuffer::require_data() const {
  if (!data_) throw std::logic_error("DataBuffer has no backing data");
  return *data_;
}

std::vector<std::uint8_t> &DataBuffer::require_data() {
  if (!data_) throw std::logic_error("DataBuffer has no backing data");
  return *data_;
}

std::size_t DataBuffer::size() const { return require_data().size(); }

const std::vector<std::uint8_t> &DataBuffer::bytes() const {
  return require_data();
}

void DataBuffer::set_data(std::optional<std::vector<std::uint8_t>> data) {
  data_ = std::move(data);
}

void DataBuffer::require(std::size_t offset, std::size_t length) const {
  const auto &data = require_data();
  if (offset > data.size() || length > data.size() - offset) {
    throw std::out_of_range("database buffer access out of bounds");
  }
}

std::uint8_t DataBuffer::get_u8(std::size_t offset) const {
  require(offset, 1);
  return (*data_)[offset];
}

std::int16_t DataBuffer::get_i16(std::size_t offset) const {
  require(offset, 2);
  const auto value = static_cast<std::uint16_t>(((*data_)[offset] << 8) |
                                                 (*data_)[offset + 1]);
  return std::bit_cast<std::int16_t>(value);
}

std::int32_t DataBuffer::get_i32(std::size_t offset) const {
  require(offset, 4);
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value = (value << 8) | (*data_)[offset + index];
  }
  return std::bit_cast<std::int32_t>(value);
}

std::int64_t DataBuffer::get_i64(std::size_t offset) const {
  require(offset, 8);
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8) | (*data_)[offset + index];
  }
  return std::bit_cast<std::int64_t>(value);
}

std::vector<std::uint8_t> DataBuffer::get(
    std::size_t offset, std::size_t length) const {
  require(offset, length);
  const auto &data = *data_;
  return {data.begin() + static_cast<std::ptrdiff_t>(offset),
          data.begin() + static_cast<std::ptrdiff_t>(offset + length)};
}

std::size_t DataBuffer::put_u8(std::size_t offset, std::uint8_t value) {
  require(offset, 1);
  dirty_ = true;
  (*data_)[offset] = value;
  return offset + 1;
}

std::size_t DataBuffer::put_i16(std::size_t offset, std::int16_t value) {
  require(offset, 2);
  dirty_ = true;
  const auto bits = std::bit_cast<std::uint16_t>(value);
  (*data_)[offset] = static_cast<std::uint8_t>(bits >> 8);
  (*data_)[offset + 1] = static_cast<std::uint8_t>(bits);
  return offset + 2;
}

std::size_t DataBuffer::put_i32(std::size_t offset, std::int32_t value) {
  require(offset, 4);
  dirty_ = true;
  const auto bits = std::bit_cast<std::uint32_t>(value);
  for (std::size_t index = 0; index < 4; ++index) {
    (*data_)[offset + index] =
        static_cast<std::uint8_t>(bits >> ((3 - index) * 8));
  }
  return offset + 4;
}

std::size_t DataBuffer::put_i64(std::size_t offset, std::int64_t value) {
  require(offset, 8);
  dirty_ = true;
  const auto bits = std::bit_cast<std::uint64_t>(value);
  for (std::size_t index = 0; index < 8; ++index) {
    (*data_)[offset + index] =
        static_cast<std::uint8_t>(bits >> ((7 - index) * 8));
  }
  return offset + 8;
}

std::size_t DataBuffer::put(
    std::size_t offset, std::span<const std::uint8_t> value) {
  require(offset, value.size());
  dirty_ = true;
  if (!value.empty()) {
    std::memmove(require_data().data() + offset, value.data(), value.size());
  }
  return offset + value.size();
}

void DataBuffer::clear() {
  auto &data = require_data();
  std::fill(data.begin(), data.end(), std::uint8_t{0});
}

void DataBuffer::move(std::size_t source_offset,
                      std::size_t destination_offset, std::size_t length) {
  require(source_offset, length);
  require(destination_offset, length);
  dirty_ = true;
  if (length != 0) {
    auto &data = require_data();
    std::memmove(data.data() + destination_offset,
                 data.data() + source_offset, length);
  }
}

void DataBuffer::copy(std::size_t destination_offset,
                      const DataBuffer &source, std::size_t source_offset,
                      std::size_t length) {
  source.require(source_offset, length);
  require(destination_offset, length);
  dirty_ = true;
  if (length != 0) {
    std::memmove(require_data().data() + destination_offset,
                 source.require_data().data() + source_offset, length);
  }
}

int DataBuffer::unsigned_compare_to(std::span<const std::uint8_t> other,
                                    std::size_t offset,
                                    std::size_t length) const {
  require(offset, length);
  const auto &data = *data_;
  const auto common_length = std::min(length, other.size());
  for (std::size_t index = 0; index < common_length; ++index) {
    const int difference = static_cast<int>(data[offset + index]) -
                           static_cast<int>(other[index]);
    if (difference != 0) return difference;
  }
  if (length == other.size()) return 0;
  return length < other.size() ? -static_cast<int>(other.size() - length)
                               : static_cast<int>(length - other.size());
}

std::vector<std::uint8_t> DataBuffer::write_external(
    bool compression_enabled) const {
  if (data_ && data_->size() >
                   static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw DataBufferSerializationError("DataBuffer is too large to serialize");
  }

  std::optional<std::vector<std::uint8_t>> compressed;
  if (compression_enabled && !empty_ && data_) {
    compressed = deflate_raw(*data_);
  }

  std::vector<std::uint8_t> output;
  output.reserve(15 + (data_ ? data_->size() : 0));
  append_i32(output, external_format_version);
  output.push_back(compressed ? 1 : 0);
  append_i32(output, id_);
  output.push_back(dirty_ ? 1 : 0);
  output.push_back(empty_ ? 1 : 0);
  append_i32(output, data_ ? static_cast<std::int32_t>(data_->size()) : -1);

  if (data_) {
    if (compressed) {
      append_i32(output, static_cast<std::int32_t>(compressed->size()));
      output.insert(output.end(), compressed->begin(), compressed->end());
    }
    else {
      output.insert(output.end(), data_->begin(), data_->end());
    }
  }
  return output;
}

std::size_t DataBuffer::read_external(
    std::span<const std::uint8_t> serialized) {
  std::size_t offset = 0;
  if (read_i32(serialized, offset) != external_format_version) {
    throw DataBufferSerializationError("unsupported DataBuffer serialization");
  }
  const bool compressed = read_boolean(serialized, offset);
  const auto new_id = read_i32(serialized, offset);
  const bool new_dirty = read_boolean(serialized, offset);
  const bool new_empty = read_boolean(serialized, offset);
  const auto signed_length = read_i32(serialized, offset);

  std::optional<std::vector<std::uint8_t>> new_data;
  if (signed_length >= 0) {
    const auto length = static_cast<std::size_t>(signed_length);
    if (compressed) {
      const auto signed_compressed_length = read_i32(serialized, offset);
      if (signed_compressed_length < 0) {
        throw DataBufferSerializationError("negative DataBuffer compressed length");
      }
      const auto compressed_length =
          static_cast<std::size_t>(signed_compressed_length);
      if (offset > serialized.size() ||
          compressed_length > serialized.size() - offset) {
        throw DataBufferSerializationError("truncated compressed DataBuffer");
      }
      new_data = inflate_raw(serialized.subspan(offset, compressed_length), length);
      offset += compressed_length;
    }
    else {
      if (offset > serialized.size() || length > serialized.size() - offset) {
        throw DataBufferSerializationError("truncated DataBuffer data");
      }
      new_data.emplace(serialized.begin() + static_cast<std::ptrdiff_t>(offset),
                       serialized.begin() +
                           static_cast<std::ptrdiff_t>(offset + length));
      offset += length;
    }
  }

  // Commit state only after the complete payload validates.
  id_ = new_id;
  dirty_ = new_dirty;
  empty_ = new_empty;
  data_ = std::move(new_data);
  return offset;
}

} // namespace llmghidra::db
