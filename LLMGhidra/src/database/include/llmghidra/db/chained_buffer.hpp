/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer.hpp"
#include "llmghidra/db/buffer_manager.hpp"
#include "llmghidra/db/storage_integrity.hpp"

#include <cstddef>
#include <cstdint>
#include <istream>
#include <memory>
#include <mutex>
#include <span>
#include <vector>

namespace llmghidra::db {

// Disk-compatible native counterpart of db.ChainedBuffer. Large logical byte
// arrays are represented by Ghidra type-8 index nodes and type-9 data nodes.
class ChainedBuffer final : public Buffer {
public:
  static constexpr std::uint8_t index_node_type = 8;
  static constexpr std::uint8_t data_node_type = 9;
  static constexpr std::size_t node_type_offset = 0;
  static constexpr std::size_t data_length_offset = 1;
  static constexpr std::size_t next_index_id_offset = 5;
  static constexpr std::size_t index_base_offset = 9;
  static constexpr std::size_t nonindexed_data_base_offset = 5;
  static constexpr std::size_t indexed_data_base_offset = 1;

  ChainedBuffer(std::int32_t size, bool enable_obfuscation,
                const Buffer *uninitialized_data_source,
                std::size_t uninitialized_data_source_offset,
                BufferManager &buffer_manager);
  ChainedBuffer(std::int32_t size, bool enable_obfuscation,
                BufferManager &buffer_manager);
  explicit ChainedBuffer(std::int32_t size, BufferManager &buffer_manager);
  ChainedBuffer(BufferManager &buffer_manager, std::int32_t buffer_id,
                const Buffer *uninitialized_data_source,
                std::size_t uninitialized_data_source_offset);
  ChainedBuffer(BufferManager &buffer_manager, std::int32_t buffer_id);

  ChainedBuffer(const ChainedBuffer &) = delete;
  ChainedBuffer &operator=(const ChainedBuffer &) = delete;
  ChainedBuffer(ChainedBuffer &&) = delete;
  ChainedBuffer &operator=(ChainedBuffer &&) = delete;

  [[nodiscard]] std::int32_t id() const noexcept override {
    return first_buffer_id_;
  }
  [[nodiscard]] std::size_t size() const override;
  [[nodiscard]] std::int32_t length() const noexcept { return size_; }
  [[nodiscard]] bool has_obfuscated_storage() const noexcept {
    return use_xor_mask_;
  }
  [[nodiscard]] std::size_t buffer_count() const;
  [[nodiscard]] std::vector<std::int32_t> storage_buffer_ids() const;
  void set_read_only() noexcept { read_only_ = true; }

  [[nodiscard]] std::uint8_t get_u8(std::size_t offset) const override;
  [[nodiscard]] std::int16_t get_i16(std::size_t offset) const override;
  [[nodiscard]] std::int32_t get_i32(std::size_t offset) const override;
  [[nodiscard]] std::int64_t get_i64(std::size_t offset) const override;
  [[nodiscard]] std::vector<std::uint8_t>
  get(std::size_t offset, std::size_t length) const override;

  std::size_t put_u8(std::size_t offset, std::uint8_t value) override;
  std::size_t put_i16(std::size_t offset, std::int16_t value) override;
  std::size_t put_i32(std::size_t offset, std::int32_t value) override;
  std::size_t put_i64(std::size_t offset, std::int64_t value) override;
  std::size_t put(std::size_t offset,
                  std::span<const std::uint8_t> value) override;

  void get(std::size_t offset, std::span<std::uint8_t> destination) const;
  void fill(std::size_t start_offset, std::size_t end_offset,
            std::uint8_t value);
  void fill(std::istream &input);
  void set_size(std::int32_t size, bool preserve_data);
  [[nodiscard]] std::unique_ptr<ChainedBuffer> split(std::int32_t offset);
  void append(ChainedBuffer &other);
  void remove();

private:
  [[nodiscard]] std::int32_t encoded_length() const noexcept;
  [[nodiscard]] std::uint8_t xor_byte(std::size_t buffer_offset,
                                      std::uint8_t value) const noexcept;
  void set_uninitialized_source(const Buffer *source,
                                std::size_t source_offset);
  void require_valid_locked() const;
  void require_writable_locked() const;
  void require_range_locked(std::size_t offset, std::size_t length) const;

  void allocate_index(const DataBuffer &sample);
  void create_index(std::shared_ptr<DataBuffer> index_buffer);
  void build_index(std::shared_ptr<DataBuffer> index_buffer);
  void validate_data_buffers();
  [[nodiscard]] std::shared_ptr<DataBuffer>
  append_index_buffer(std::shared_ptr<DataBuffer> index_buffer);
  [[nodiscard]] std::shared_ptr<DataBuffer>
  get_or_allocate_data_buffer(std::size_t index);
  void initialize_allocated_buffer(std::size_t index, DataBuffer &buffer);
  void add_data_buffer(std::size_t index, DataBuffer &buffer);

  void grow(std::int32_t new_size, bool preserve_data);
  void shrink(std::int32_t new_size, bool preserve_data);
  [[nodiscard]] bool shrink_to_single_buffer(bool preserve_data);

  void get_locked(std::size_t offset,
                  std::span<std::uint8_t> destination) const;
  void put_locked(std::size_t offset, std::span<const std::uint8_t> source);

  BufferManager &buffer_manager_;
  std::int32_t size_ = 0;
  std::int32_t first_buffer_id_ = -1;
  bool use_xor_mask_ = false;
  bool read_only_ = false;
  const Buffer *uninitialized_data_source_ = nullptr;
  std::size_t uninitialized_data_source_offset_ = 0;
  std::vector<std::int32_t> index_buffer_ids_;
  std::vector<std::int32_t> data_buffer_ids_;
  std::size_t indexes_per_buffer_ = 0;
  std::size_t data_base_offset_ = 0;
  std::size_t data_space_ = 0;
  mutable std::recursive_mutex mutex_;
};

} // namespace llmghidra::db
