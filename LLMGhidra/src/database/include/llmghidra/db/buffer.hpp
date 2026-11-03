/*
 * Copyright 2026
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace llmghidra::db {

class Buffer {
public:
  virtual ~Buffer() = default;

  [[nodiscard]] virtual std::int32_t id() const noexcept = 0;
  [[nodiscard]] virtual std::size_t size() const = 0;

  [[nodiscard]] virtual std::uint8_t get_u8(std::size_t offset) const = 0;
  [[nodiscard]] virtual std::int16_t get_i16(std::size_t offset) const = 0;
  [[nodiscard]] virtual std::int32_t get_i32(std::size_t offset) const = 0;
  [[nodiscard]] virtual std::int64_t get_i64(std::size_t offset) const = 0;
  [[nodiscard]] virtual std::vector<std::uint8_t> get(
      std::size_t offset, std::size_t length) const = 0;

  virtual std::size_t put_u8(std::size_t offset, std::uint8_t value) = 0;
  virtual std::size_t put_i16(std::size_t offset, std::int16_t value) = 0;
  virtual std::size_t put_i32(std::size_t offset, std::int32_t value) = 0;
  virtual std::size_t put_i64(std::size_t offset, std::int64_t value) = 0;
  virtual std::size_t put(
      std::size_t offset, std::span<const std::uint8_t> value) = 0;
};

class DataBufferSerializationError final : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// Native counterpart of db.buffers.DataBuffer. A default-constructed instance
// deliberately has no backing data, matching the Java de-serialization and
// empty-buffer state.
class DataBuffer final : public Buffer {
public:
  static constexpr std::int32_t external_format_version = 0xEA;

  DataBuffer() = default;
  explicit DataBuffer(std::size_t size);
  explicit DataBuffer(std::vector<std::uint8_t> data);

  [[nodiscard]] std::int32_t id() const noexcept override { return id_; }
  void set_id(std::int32_t value) noexcept { id_ = value; }

  [[nodiscard]] bool dirty() const noexcept { return dirty_; }
  void set_dirty(bool value) noexcept { dirty_ = value; }

  [[nodiscard]] bool empty() const noexcept { return empty_; }
  void set_empty(bool value) noexcept { empty_ = value; }

  [[nodiscard]] bool has_data() const noexcept { return data_.has_value(); }
  [[nodiscard]] std::size_t size() const override;
  [[nodiscard]] const std::vector<std::uint8_t> &bytes() const;
  void set_data(std::optional<std::vector<std::uint8_t>> data);

  [[nodiscard]] std::uint8_t get_u8(std::size_t offset) const override;
  [[nodiscard]] std::int16_t get_i16(std::size_t offset) const override;
  [[nodiscard]] std::int32_t get_i32(std::size_t offset) const override;
  [[nodiscard]] std::int64_t get_i64(std::size_t offset) const override;
  [[nodiscard]] std::vector<std::uint8_t> get(
      std::size_t offset, std::size_t length) const override;

  std::size_t put_u8(std::size_t offset, std::uint8_t value) override;
  std::size_t put_i16(std::size_t offset, std::int16_t value) override;
  std::size_t put_i32(std::size_t offset, std::int32_t value) override;
  std::size_t put_i64(std::size_t offset, std::int64_t value) override;
  std::size_t put(
      std::size_t offset, std::span<const std::uint8_t> value) override;

  // Java DataBuffer.clear() intentionally does not change the dirty flag.
  void clear();
  void move(std::size_t source_offset, std::size_t destination_offset,
            std::size_t length);
  void copy(std::size_t destination_offset, const DataBuffer &source,
            std::size_t source_offset, std::size_t length);

  [[nodiscard]] int unsigned_compare_to(
      std::span<const std::uint8_t> other, std::size_t offset,
      std::size_t length) const;

  // This is the canonical content written by DataBuffer.writeExternal, using
  // big-endian DataOutput integer encoding and raw DEFLATE when effective.
  [[nodiscard]] std::vector<std::uint8_t> write_external(
      bool compression_enabled = true) const;

  // Reads one external payload and returns the first unconsumed byte offset.
  // Trailing data is allowed so callers can decode framed streams.
  std::size_t read_external(std::span<const std::uint8_t> serialized);

private:
  [[nodiscard]] const std::vector<std::uint8_t> &require_data() const;
  [[nodiscard]] std::vector<std::uint8_t> &require_data();
  void require(std::size_t offset, std::size_t length) const;

  std::int32_t id_ = 0;
  std::optional<std::vector<std::uint8_t>> data_;
  bool dirty_ = false;
  bool empty_ = false;
};

} // namespace llmghidra::db
