/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/chained_buffer.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

namespace llmghidra::db {
namespace {

constexpr std::array<std::uint8_t, 128> xor_mask_bytes{
    0x59, 0xea, 0x67, 0x23, 0xda, 0xb8, 0x00, 0xb8, 0xc3, 0x48, 0xdd, 0x8b,
    0x21, 0xd6, 0x94, 0x78, 0x35, 0xab, 0x2b, 0x7e, 0xb2, 0x4f, 0x82, 0x4e,
    0x0e, 0x16, 0xc4, 0x57, 0x12, 0x8e, 0x7e, 0xe6, 0xb6, 0xbd, 0x56, 0x91,
    0x57, 0x72, 0xe6, 0x91, 0xdc, 0x52, 0x2e, 0xf2, 0x1a, 0xb7, 0xd6, 0x6f,
    0xda, 0xde, 0xe8, 0x48, 0xb1, 0xbb, 0x50, 0x6f, 0xf4, 0xdd, 0x11, 0xee,
    0xf2, 0x67, 0xfe, 0x48, 0x8d, 0xae, 0x69, 0x1a, 0xe0, 0x26, 0x8c, 0x24,
    0x8e, 0x17, 0x76, 0x51, 0xe2, 0x60, 0xd7, 0xe6, 0x83, 0x65, 0xd5, 0xf0,
    0x7f, 0xf2, 0xa0, 0xd6, 0x4b, 0xbd, 0x24, 0xd8, 0xab, 0xea, 0x9e, 0xa6,
    0x48, 0x94, 0x3e, 0x7b, 0x2c, 0xf4, 0xce, 0xdc, 0x69, 0x11, 0xf8, 0x3c,
    0xa7, 0x3f, 0x5d, 0x77, 0x94, 0x3f, 0xe4, 0x8e, 0x48, 0x20, 0xdb, 0x56,
    0x32, 0xc1, 0x87, 0x01, 0x2e, 0xe3, 0x7f, 0x40};

template <typename Operation>
void release_after(BufferManager &manager,
                   const std::shared_ptr<DataBuffer> &buffer,
                   Operation operation) {
  try {
    operation(*buffer);
  } catch (...) {
    try {
      manager.release_buffer(buffer);
    } catch (...) {
    }
    throw;
  }
  manager.release_buffer(buffer);
}

} // namespace

ChainedBuffer::ChainedBuffer(std::int32_t size, bool enable_obfuscation,
                             const Buffer *uninitialized_data_source,
                             std::size_t uninitialized_data_source_offset,
                             BufferManager &buffer_manager)
    : buffer_manager_(buffer_manager), size_(size),
      use_xor_mask_(enable_obfuscation) {
  if (size <= 0) {
    throw std::invalid_argument("zero or negative ChainedBuffer size");
  }
  if (uninitialized_data_source) {
    set_uninitialized_source(uninitialized_data_source,
                             uninitialized_data_source_offset);
  }

  auto first = buffer_manager_.create_buffer();
  first_buffer_id_ = first->id();
  data_base_offset_ = nonindexed_data_base_offset;
  data_space_ = static_cast<std::size_t>(buffer_manager_.buffer_size()) -
                data_base_offset_;

  if (static_cast<std::size_t>(size_) <= data_space_) {
    data_buffer_ids_ = {first_buffer_id_};
    release_after(buffer_manager_, first, [&](DataBuffer &buffer) {
      initialize_allocated_buffer(0, buffer);
      buffer.put_u8(node_type_offset, data_node_type);
      buffer.put_i32(data_length_offset, encoded_length());
    });
  } else {
    create_index(std::move(first));
  }
}

ChainedBuffer::ChainedBuffer(std::int32_t size, bool enable_obfuscation,
                             BufferManager &buffer_manager)
    : ChainedBuffer(size, enable_obfuscation, nullptr, 0, buffer_manager) {}

ChainedBuffer::ChainedBuffer(std::int32_t size, BufferManager &buffer_manager)
    : ChainedBuffer(size, false, nullptr, 0, buffer_manager) {}

ChainedBuffer::ChainedBuffer(BufferManager &buffer_manager,
                             std::int32_t buffer_id,
                             const Buffer *uninitialized_data_source,
                             std::size_t uninitialized_data_source_offset)
    : buffer_manager_(buffer_manager), first_buffer_id_(buffer_id) {
  auto first = buffer_manager_.get_buffer(buffer_id);
  try {
    const auto stored_length = first->get_i32(data_length_offset);
    const auto bits = std::bit_cast<std::uint32_t>(stored_length);
    use_xor_mask_ = (bits & 0x80000000U) != 0;
    const auto logical_size = bits & 0x7fffffffU;
    if (logical_size >
        static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())) {
      throw std::runtime_error("invalid ChainedBuffer length");
    }
    size_ = static_cast<std::int32_t>(logical_size);
    if (size_ <= 0) {
      throw StorageIntegrityError(
          StorageIntegrityCode::chained_buffer_invalid_length, buffer_id,
          "chained-buffer:" + std::to_string(buffer_id));
    }

    const auto type = first->get_u8(node_type_offset);
    if (type == index_node_type) {
      build_index(first);
      first.reset();
    } else if (type == data_node_type) {
      data_base_offset_ = nonindexed_data_base_offset;
      data_space_ = static_cast<std::size_t>(buffer_manager_.buffer_size()) -
                    data_base_offset_;
      data_buffer_ids_ = {buffer_id};
      if (static_cast<std::size_t>(size_) > data_space_) {
        throw StorageIntegrityError(
            StorageIntegrityCode::chained_buffer_truncated, buffer_id,
            "chained-buffer:" + std::to_string(buffer_id),
            "single data node is shorter than the logical length");
      }
      buffer_manager_.release_buffer(first);
      first.reset();
    } else {
      throw std::runtime_error("invalid ChainedBuffer node type");
    }
  } catch (...) {
    if (first) {
      try {
        buffer_manager_.release_buffer(first);
      } catch (...) {
      }
    }
    throw;
  }

  if (uninitialized_data_source) {
    set_uninitialized_source(uninitialized_data_source,
                             uninitialized_data_source_offset);
  }
  validate_data_buffers();
}

ChainedBuffer::ChainedBuffer(BufferManager &buffer_manager,
                             std::int32_t buffer_id)
    : ChainedBuffer(buffer_manager, buffer_id, nullptr, 0) {}

std::int32_t ChainedBuffer::encoded_length() const noexcept {
  auto bits = static_cast<std::uint32_t>(size_);
  if (use_xor_mask_)
    bits |= 0x80000000U;
  return std::bit_cast<std::int32_t>(bits);
}

std::uint8_t ChainedBuffer::xor_byte(std::size_t buffer_offset,
                                     std::uint8_t value) const noexcept {
  return value ^ xor_mask_bytes[buffer_offset % xor_mask_bytes.size()];
}

void ChainedBuffer::set_uninitialized_source(const Buffer *source,
                                             std::size_t source_offset) {
  if (!source || source_offset > source->size() ||
      static_cast<std::size_t>(size_) > source->size() - source_offset) {
    throw std::invalid_argument(
        "uninitialized ChainedBuffer source has insufficient bytes");
  }
  uninitialized_data_source_ = source;
  uninitialized_data_source_offset_ = source_offset;
}

void ChainedBuffer::require_valid_locked() const {
  if (first_buffer_id_ < 0 || data_buffer_ids_.empty()) {
    throw std::logic_error("invalidated ChainedBuffer");
  }
}

void ChainedBuffer::require_writable_locked() const {
  require_valid_locked();
  if (read_only_)
    throw std::logic_error("read-only ChainedBuffer");
}

void ChainedBuffer::require_range_locked(std::size_t offset,
                                         std::size_t length) const {
  require_valid_locked();
  const auto logical_size = static_cast<std::size_t>(size_);
  if (offset > logical_size || length > logical_size - offset) {
    throw std::out_of_range("ChainedBuffer access out of bounds");
  }
}

std::size_t ChainedBuffer::size() const {
  std::scoped_lock lock(mutex_);
  require_valid_locked();
  return static_cast<std::size_t>(size_);
}

std::size_t ChainedBuffer::buffer_count() const {
  std::scoped_lock lock(mutex_);
  require_valid_locked();
  return data_buffer_ids_.size() + index_buffer_ids_.size();
}

std::vector<std::int32_t> ChainedBuffer::storage_buffer_ids() const {
  std::scoped_lock lock(mutex_);
  require_valid_locked();
  std::vector<std::int32_t> result = index_buffer_ids_;
  result.reserve(result.size() + data_buffer_ids_.size());
  for (const auto id : data_buffer_ids_) {
    if (id >= 0)
      result.push_back(id);
  }
  return result;
}

void ChainedBuffer::allocate_index(const DataBuffer &sample) {
  data_base_offset_ = indexed_data_base_offset;
  data_space_ = sample.size() - data_base_offset_;
  indexes_per_buffer_ = (sample.size() - index_base_offset) / 4;
  if (data_space_ == 0 || indexes_per_buffer_ == 0) {
    throw std::runtime_error("database buffer is too small for ChainedBuffer");
  }
  const auto count = (static_cast<std::size_t>(size_) - 1) / data_space_ + 1;
  data_buffer_ids_.assign(count, -1);
}

std::shared_ptr<DataBuffer>
ChainedBuffer::append_index_buffer(std::shared_ptr<DataBuffer> index_buffer) {
  auto next = buffer_manager_.create_buffer();
  try {
    next->put_u8(node_type_offset, index_node_type);
    next->put_i32(data_length_offset, -1);
    next->put_i32(next_index_id_offset, -1);
    index_buffer->put_i32(next_index_id_offset, next->id());
    buffer_manager_.release_buffer(index_buffer);
    return next;
  } catch (...) {
    try {
      buffer_manager_.release_buffer(index_buffer);
    } catch (...) {
    }
    try {
      buffer_manager_.release_buffer(next);
    } catch (...) {
    }
    throw;
  }
}

void ChainedBuffer::create_index(std::shared_ptr<DataBuffer> index_buffer) {
  try {
    index_buffer->put_u8(node_type_offset, index_node_type);
    index_buffer->put_i32(data_length_offset, encoded_length());
    index_buffer->put_i32(next_index_id_offset, -1);
    allocate_index(*index_buffer);
    const auto index_buffer_count =
        (data_buffer_ids_.size() - 1) / indexes_per_buffer_ + 1;
    index_buffer_ids_.resize(index_buffer_count);
    const std::vector<std::uint8_t> empty_index(indexes_per_buffer_ * 4, 0xff);

    index_buffer_ids_[0] = index_buffer->id();
    index_buffer->put(index_base_offset, empty_index);
    for (std::size_t index = 1; index < index_buffer_count; ++index) {
      index_buffer = append_index_buffer(std::move(index_buffer));
      index_buffer_ids_[index] = index_buffer->id();
      index_buffer->put(index_base_offset, empty_index);
    }
    buffer_manager_.release_buffer(index_buffer);
  } catch (...) {
    if (index_buffer) {
      try {
        buffer_manager_.release_buffer(index_buffer);
      } catch (...) {
      }
    }
    throw;
  }
}

void ChainedBuffer::build_index(std::shared_ptr<DataBuffer> index_buffer) {
  allocate_index(*index_buffer);
  const auto index_buffer_count =
      (data_buffer_ids_.size() - 1) / indexes_per_buffer_ + 1;
  index_buffer_ids_.resize(index_buffer_count);
  std::size_t slot = 0;
  std::size_t index_buffer_number = 0;
  std::size_t offset = index_base_offset;
  index_buffer_ids_[0] = index_buffer->id();
  std::unordered_set<std::int32_t> visited_index_ids{index_buffer->id()};
  try {
    for (std::size_t index = 0; index < data_buffer_ids_.size(); ++index) {
      if (slot == indexes_per_buffer_) {
        const auto next = index_buffer->get_i32(next_index_id_offset);
        if (next < 0) {
          throw StorageIntegrityError(
              StorageIntegrityCode::chained_buffer_truncated,
              index_buffer->id(),
              "chained-buffer:" + std::to_string(first_buffer_id_));
        }
        if (!visited_index_ids.insert(next).second) {
          throw StorageIntegrityError(
              StorageIntegrityCode::chained_buffer_cycle, next,
              "chained-buffer:" + std::to_string(first_buffer_id_));
        }
        if (buffer_manager_.buffer_state(next) !=
            BufferManager::BufferState::allocated) {
          throw StorageIntegrityError(
              StorageIntegrityCode::invalid_buffer_reference, next,
              "chained-buffer:" + std::to_string(first_buffer_id_),
              "index link references a free or out-of-range buffer");
        }
        buffer_manager_.release_buffer(index_buffer);
        index_buffer = buffer_manager_.get_buffer(next);
        if (index_buffer->get_u8(node_type_offset) != index_node_type) {
          throw StorageIntegrityError(
              StorageIntegrityCode::chained_buffer_node_family, next,
              "chained-buffer:" + std::to_string(first_buffer_id_),
              "index link does not reference a type-8 node");
        }
        index_buffer_ids_[++index_buffer_number] = next;
        slot = 0;
        offset = index_base_offset;
      }
      data_buffer_ids_[index] = index_buffer->get_i32(offset);
      offset += 4;
      ++slot;
    }
    const auto trailing = index_buffer->get_i32(next_index_id_offset);
    if (trailing >= 0) {
      throw StorageIntegrityError(
          visited_index_ids.contains(trailing)
              ? StorageIntegrityCode::chained_buffer_cycle
              : StorageIntegrityCode::chained_buffer_truncated,
          trailing, "chained-buffer:" + std::to_string(first_buffer_id_),
          "unexpected trailing index node");
    }
    buffer_manager_.release_buffer(index_buffer);
  } catch (...) {
    if (index_buffer) {
      try {
        buffer_manager_.release_buffer(index_buffer);
      } catch (...) {
      }
    }
    throw;
  }
}

void ChainedBuffer::validate_data_buffers() {
  const auto owner = "chained-buffer:" + std::to_string(first_buffer_id_);
  std::unordered_set<std::int32_t> owned(index_buffer_ids_.begin(),
                                         index_buffer_ids_.end());
  for (const auto id : data_buffer_ids_) {
    if (id < 0)
      continue;
    if (!owned.insert(id).second) {
      throw StorageIntegrityError(
          StorageIntegrityCode::duplicate_buffer_ownership, id, owner,
          "index and data entries or two data entries share a buffer");
    }
    if (buffer_manager_.buffer_state(id) !=
        BufferManager::BufferState::allocated) {
      throw StorageIntegrityError(
          StorageIntegrityCode::invalid_buffer_reference, id, owner,
          "data entry references a free or out-of-range buffer");
    }
    if (buffer_manager_.inspect_u8(id, node_type_offset) != data_node_type) {
      throw StorageIntegrityError(
          StorageIntegrityCode::chained_buffer_node_family, id, owner,
          "data entry does not reference a type-9 node");
    }
  }
}

void ChainedBuffer::initialize_allocated_buffer(std::size_t index,
                                                DataBuffer &buffer) {
  const auto logical_offset = index * data_space_;
  const auto remaining = static_cast<std::size_t>(size_) - logical_offset;
  const auto length = (std::min)(remaining, data_space_);
  if (length < data_space_)
    buffer.clear();

  std::vector<std::uint8_t> data(length);
  if (uninitialized_data_source_) {
    data = uninitialized_data_source_->get(
        uninitialized_data_source_offset_ + logical_offset, length);
  }
  if (use_xor_mask_) {
    for (std::size_t offset = 0; offset < data.size(); ++offset) {
      data[offset] = xor_byte(offset, data[offset]);
    }
  }
  buffer.put(data_base_offset_, data);
}

void ChainedBuffer::add_data_buffer(std::size_t index, DataBuffer &buffer) {
  buffer.put_u8(node_type_offset, data_node_type);
  const auto index_buffer_id =
      index_buffer_ids_.at(index / indexes_per_buffer_);
  const auto index_offset =
      index_base_offset + (index % indexes_per_buffer_) * 4;
  auto index_buffer = buffer_manager_.get_buffer(index_buffer_id);
  release_after(buffer_manager_, index_buffer, [&](DataBuffer &value) {
    value.put_i32(index_offset, buffer.id());
  });
  data_buffer_ids_.at(index) = buffer.id();
}

std::shared_ptr<DataBuffer>
ChainedBuffer::get_or_allocate_data_buffer(std::size_t index) {
  auto id = data_buffer_ids_.at(index);
  if (id >= 0)
    return buffer_manager_.get_buffer(id);

  auto buffer = buffer_manager_.create_buffer();
  try {
    initialize_allocated_buffer(index, *buffer);
    add_data_buffer(index, *buffer);
    return buffer;
  } catch (...) {
    try {
      buffer_manager_.release_buffer(buffer);
    } catch (...) {
    }
    throw;
  }
}

void ChainedBuffer::get_locked(std::size_t offset,
                               std::span<std::uint8_t> destination) const {
  require_range_locked(offset, destination.size());
  std::size_t copied = 0;
  while (copied < destination.size()) {
    const auto logical = offset + copied;
    const auto index = logical / data_space_;
    const auto within = logical % data_space_;
    const auto count =
        (std::min)(destination.size() - copied, data_space_ - within);
    const auto id = data_buffer_ids_.at(index);
    if (id < 0) {
      if (uninitialized_data_source_) {
        const auto source = uninitialized_data_source_->get(
            uninitialized_data_source_offset_ + logical, count);
        std::copy(source.begin(), source.end(), destination.begin() + copied);
      } else {
        std::fill_n(destination.begin() + copied,
                    static_cast<std::ptrdiff_t>(count), std::uint8_t{0});
      }
    } else {
      auto buffer = buffer_manager_.get_buffer(id);
      try {
        const auto bytes = buffer->get(data_base_offset_ + within, count);
        std::copy(bytes.begin(), bytes.end(), destination.begin() + copied);
        buffer_manager_.release_buffer(buffer);
      } catch (...) {
        try {
          buffer_manager_.release_buffer(buffer);
        } catch (...) {
        }
        throw;
      }
      if (use_xor_mask_) {
        for (std::size_t index_in_block = 0; index_in_block < count;
             ++index_in_block) {
          destination[copied + index_in_block] = xor_byte(
              within + index_in_block, destination[copied + index_in_block]);
        }
      }
    }
    copied += count;
  }
}

std::vector<std::uint8_t> ChainedBuffer::get(std::size_t offset,
                                             std::size_t length) const {
  std::scoped_lock lock(mutex_);
  std::vector<std::uint8_t> result(length);
  get_locked(offset, result);
  return result;
}

void ChainedBuffer::get(std::size_t offset,
                        std::span<std::uint8_t> destination) const {
  std::scoped_lock lock(mutex_);
  get_locked(offset, destination);
}

std::uint8_t ChainedBuffer::get_u8(std::size_t offset) const {
  const auto bytes = get(offset, 1);
  return bytes[0];
}

std::int16_t ChainedBuffer::get_i16(std::size_t offset) const {
  const auto data = get(offset, 2);
  const auto bits = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
  return std::bit_cast<std::int16_t>(bits);
}

std::int32_t ChainedBuffer::get_i32(std::size_t offset) const {
  const auto data = get(offset, 4);
  std::uint32_t bits = 0;
  for (const auto value : data)
    bits = (bits << 8) | value;
  return std::bit_cast<std::int32_t>(bits);
}

std::int64_t ChainedBuffer::get_i64(std::size_t offset) const {
  const auto data = get(offset, 8);
  std::uint64_t bits = 0;
  for (const auto value : data)
    bits = (bits << 8) | value;
  return std::bit_cast<std::int64_t>(bits);
}

void ChainedBuffer::put_locked(std::size_t offset,
                               std::span<const std::uint8_t> source) {
  require_writable_locked();
  require_range_locked(offset, source.size());
  std::size_t copied = 0;
  while (copied < source.size()) {
    const auto logical = offset + copied;
    const auto index = logical / data_space_;
    const auto within = logical % data_space_;
    const auto count = (std::min)(source.size() - copied, data_space_ - within);
    std::span<const std::uint8_t> write_data = source.subspan(copied, count);
    std::vector<std::uint8_t> encoded;
    if (use_xor_mask_) {
      encoded.resize(count);
      for (std::size_t index_in_block = 0; index_in_block < count;
           ++index_in_block) {
        encoded[index_in_block] =
            xor_byte(within + index_in_block, write_data[index_in_block]);
      }
      write_data = encoded;
    }

    auto buffer = get_or_allocate_data_buffer(index);
    release_after(buffer_manager_, buffer, [&](DataBuffer &value) {
      value.put(data_base_offset_ + within, write_data);
    });
    copied += count;
  }
}

std::size_t ChainedBuffer::put(std::size_t offset,
                               std::span<const std::uint8_t> value) {
  std::scoped_lock lock(mutex_);
  put_locked(offset, value);
  return offset + value.size();
}

std::size_t ChainedBuffer::put_u8(std::size_t offset, std::uint8_t value) {
  const std::array<std::uint8_t, 1> bytes{value};
  return put(offset, bytes);
}

std::size_t ChainedBuffer::put_i16(std::size_t offset, std::int16_t value) {
  const auto bits = std::bit_cast<std::uint16_t>(value);
  const std::array<std::uint8_t, 2> bytes{static_cast<std::uint8_t>(bits >> 8),
                                          static_cast<std::uint8_t>(bits)};
  return put(offset, bytes);
}

std::size_t ChainedBuffer::put_i32(std::size_t offset, std::int32_t value) {
  const auto bits = std::bit_cast<std::uint32_t>(value);
  const std::array<std::uint8_t, 4> bytes{static_cast<std::uint8_t>(bits >> 24),
                                          static_cast<std::uint8_t>(bits >> 16),
                                          static_cast<std::uint8_t>(bits >> 8),
                                          static_cast<std::uint8_t>(bits)};
  return put(offset, bytes);
}

std::size_t ChainedBuffer::put_i64(std::size_t offset, std::int64_t value) {
  const auto bits = std::bit_cast<std::uint64_t>(value);
  std::array<std::uint8_t, 8> bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    bytes[index] = static_cast<std::uint8_t>(bits >> ((7 - index) * 8));
  }
  return put(offset, bytes);
}

void ChainedBuffer::fill(std::size_t start_offset, std::size_t end_offset,
                         std::uint8_t value) {
  std::scoped_lock lock(mutex_);
  require_writable_locked();
  if (end_offset < start_offset) {
    throw std::invalid_argument("ChainedBuffer fill range is reversed");
  }
  require_range_locked(start_offset, end_offset - start_offset + 1);
  std::vector<std::uint8_t> chunk(data_space_, value);
  auto offset = start_offset;
  auto remaining = end_offset - start_offset + 1;
  while (remaining != 0) {
    const auto count = (std::min)(remaining, chunk.size());
    put_locked(offset, std::span<const std::uint8_t>(chunk).first(count));
    offset += count;
    remaining -= count;
  }
}

void ChainedBuffer::fill(std::istream &input) {
  std::scoped_lock lock(mutex_);
  require_writable_locked();
  std::vector<std::uint8_t> chunk(data_space_);
  std::size_t offset = 0;
  while (offset < static_cast<std::size_t>(size_)) {
    const auto count =
        (std::min)(chunk.size(), static_cast<std::size_t>(size_) - offset);
    std::fill(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(count),
              std::uint8_t{0});
    input.read(reinterpret_cast<char *>(chunk.data()),
               static_cast<std::streamsize>(count));
    const auto bytes_read = static_cast<std::size_t>(input.gcount());
    if (input.bad())
      throw std::runtime_error("ChainedBuffer stream read failed");
    put_locked(offset, std::span<const std::uint8_t>(chunk).first(count));
    offset += count;
    if (bytes_read < count) {
      while (offset < static_cast<std::size_t>(size_)) {
        const auto zeros =
            (std::min)(chunk.size(), static_cast<std::size_t>(size_) - offset);
        std::fill(chunk.begin(),
                  chunk.begin() + static_cast<std::ptrdiff_t>(zeros),
                  std::uint8_t{0});
        put_locked(offset, std::span<const std::uint8_t>(chunk).first(zeros));
        offset += zeros;
      }
    }
  }
}

void ChainedBuffer::grow(std::int32_t new_size, bool preserve_data) {
  const auto old_size = size_;
  size_ = new_size;

  if (data_buffer_ids_.size() == 1) {
    if (static_cast<std::size_t>(new_size) > data_space_) {
      auto first = buffer_manager_.get_buffer(first_buffer_id_);
      std::shared_ptr<DataBuffer> new_first_data;
      try {
        if (preserve_data) {
          new_first_data = buffer_manager_.create_buffer();
          new_first_data->copy(indexed_data_base_offset, *first,
                               nonindexed_data_base_offset,
                               static_cast<std::size_t>(old_size));
          const auto indexed_space =
              new_first_data->size() - indexed_data_base_offset;
          std::vector<std::uint8_t> zeros(indexed_space -
                                          static_cast<std::size_t>(old_size));
          if (use_xor_mask_) {
            for (std::size_t index = 0; index < zeros.size(); ++index) {
              zeros[index] =
                  xor_byte(static_cast<std::size_t>(old_size) + index, 0);
            }
          }
          new_first_data->put(indexed_data_base_offset +
                                  static_cast<std::size_t>(old_size),
                              zeros);
        }
        create_index(first);
        first.reset();
        if (new_first_data)
          add_data_buffer(0, *new_first_data);
        if (new_first_data) {
          buffer_manager_.release_buffer(new_first_data);
          new_first_data.reset();
        }
      } catch (...) {
        if (first) {
          try {
            buffer_manager_.release_buffer(first);
          } catch (...) {
          }
        }
        if (new_first_data) {
          try {
            buffer_manager_.release_buffer(new_first_data);
          } catch (...) {
          }
        }
        throw;
      }
      return;
    }

    auto first = buffer_manager_.get_buffer(first_buffer_id_);
    release_after(buffer_manager_, first, [&](DataBuffer &buffer) {
      buffer.put_i32(data_length_offset, encoded_length());
    });
    return;
  }

  const auto new_data_count =
      (static_cast<std::size_t>(new_size) - 1) / data_space_ + 1;
  const auto new_index_count = (new_data_count - 1) / indexes_per_buffer_ + 1;
  data_buffer_ids_.resize(new_data_count, -1);
  const auto old_index_count = index_buffer_ids_.size();
  if (old_index_count < new_index_count) {
    index_buffer_ids_.resize(new_index_count, -1);
    const std::vector<std::uint8_t> empty_index(indexes_per_buffer_ * 4, 0xff);
    auto index_buffer =
        buffer_manager_.get_buffer(index_buffer_ids_[old_index_count - 1]);
    for (std::size_t index = old_index_count; index < new_index_count;
         ++index) {
      index_buffer = append_index_buffer(std::move(index_buffer));
      index_buffer->put(index_base_offset, empty_index);
      index_buffer_ids_[index] = index_buffer->id();
    }
    buffer_manager_.release_buffer(index_buffer);
  }
  auto first = buffer_manager_.get_buffer(first_buffer_id_);
  release_after(buffer_manager_, first, [&](DataBuffer &buffer) {
    buffer.put_i32(data_length_offset, encoded_length());
  });
}

bool ChainedBuffer::shrink_to_single_buffer(bool preserve_data) {
  const auto single_space =
      static_cast<std::size_t>(buffer_manager_.buffer_size()) -
      nonindexed_data_base_offset;
  if (static_cast<std::size_t>(size_) > single_space)
    return false;

  auto first = buffer_manager_.get_buffer(first_buffer_id_);
  std::shared_ptr<DataBuffer> old_first_data;
  try {
    first->put_u8(node_type_offset, data_node_type);
    first->put_i32(data_length_offset, encoded_length());
    if (preserve_data && data_buffer_ids_[0] >= 0) {
      old_first_data = buffer_manager_.get_buffer(data_buffer_ids_[0]);
      first->copy(nonindexed_data_base_offset, *old_first_data,
                  indexed_data_base_offset, static_cast<std::size_t>(size_));
    }
    buffer_manager_.release_buffer(first);
    first.reset();
    if (old_first_data) {
      buffer_manager_.release_buffer(old_first_data);
      old_first_data.reset();
    }
  } catch (...) {
    if (first) {
      try {
        buffer_manager_.release_buffer(first);
      } catch (...) {
      }
    }
    if (old_first_data) {
      try {
        buffer_manager_.release_buffer(old_first_data);
      } catch (...) {
      }
    }
    throw;
  }

  for (const auto id : data_buffer_ids_) {
    if (id >= 0)
      buffer_manager_.delete_buffer(id);
  }
  for (std::size_t index = 1; index < index_buffer_ids_.size(); ++index) {
    buffer_manager_.delete_buffer(index_buffer_ids_[index]);
  }
  data_base_offset_ = nonindexed_data_base_offset;
  data_space_ = single_space;
  data_buffer_ids_ = {first_buffer_id_};
  index_buffer_ids_.clear();
  indexes_per_buffer_ = 0;
  return true;
}

void ChainedBuffer::shrink(std::int32_t new_size, bool preserve_data) {
  size_ = new_size;
  if (data_buffer_ids_.size() == 1) {
    auto first = buffer_manager_.get_buffer(first_buffer_id_);
    release_after(buffer_manager_, first, [&](DataBuffer &buffer) {
      buffer.put_i32(data_length_offset, encoded_length());
    });
    return;
  }
  if (shrink_to_single_buffer(preserve_data))
    return;

  const auto new_data_count =
      (static_cast<std::size_t>(new_size) - 1) / data_space_ + 1;
  const auto new_index_count = (new_data_count - 1) / indexes_per_buffer_ + 1;
  for (std::size_t index = new_data_count; index < data_buffer_ids_.size();
       ++index) {
    if (data_buffer_ids_[index] >= 0) {
      buffer_manager_.delete_buffer(data_buffer_ids_[index]);
    }
  }
  data_buffer_ids_.resize(new_data_count);
  for (std::size_t index = new_index_count; index < index_buffer_ids_.size();
       ++index) {
    buffer_manager_.delete_buffer(index_buffer_ids_[index]);
  }
  index_buffer_ids_.resize(new_index_count);
  auto first = buffer_manager_.get_buffer(first_buffer_id_);
  release_after(buffer_manager_, first, [&](DataBuffer &buffer) {
    buffer.put_i32(data_length_offset, encoded_length());
  });
}

void ChainedBuffer::set_size(std::int32_t size, bool preserve_data) {
  std::scoped_lock lock(mutex_);
  require_writable_locked();
  if (uninitialized_data_source_) {
    throw std::logic_error(
        "cannot resize ChainedBuffer with uninitialized source");
  }
  if (size < 0)
    throw std::invalid_argument("negative ChainedBuffer size");
  if (size > size_)
    grow(size, preserve_data);
  else
    shrink(size, preserve_data);
}

std::unique_ptr<ChainedBuffer> ChainedBuffer::split(std::int32_t offset) {
  std::scoped_lock lock(mutex_);
  require_writable_locked();
  if (offset < 0 || offset >= size_) {
    throw std::out_of_range("invalid ChainedBuffer split offset");
  }
  auto result = std::make_unique<ChainedBuffer>(
      size_ - offset, use_xor_mask_, uninitialized_data_source_,
      uninitialized_data_source_offset_ + static_cast<std::size_t>(offset),
      buffer_manager_);

  auto remaining = static_cast<std::size_t>(size_ - offset);
  std::size_t destination_offset = 0;
  auto within = static_cast<std::size_t>(offset) % data_space_;
  for (std::size_t index = static_cast<std::size_t>(offset) / data_space_;
       index < data_buffer_ids_.size(); ++index) {
    const auto count = (std::min)(remaining, data_space_ - within);
    if (data_buffer_ids_[index] >= 0) {
      auto source = buffer_manager_.get_buffer(data_buffer_ids_[index]);
      std::vector<std::uint8_t> data;
      try {
        data = source->get(data_base_offset_ + within, count);
        buffer_manager_.release_buffer(source);
      } catch (...) {
        try {
          buffer_manager_.release_buffer(source);
        } catch (...) {
        }
        throw;
      }
      if (use_xor_mask_) {
        for (std::size_t byte = 0; byte < data.size(); ++byte) {
          data[byte] = xor_byte(within + byte, data[byte]);
        }
      }
      result->put(destination_offset, data);
      if (within == 0) {
        buffer_manager_.delete_buffer(data_buffer_ids_[index]);
        data_buffer_ids_[index] = -1;
      }
    }
    remaining -= count;
    destination_offset += count;
    within = 0;
  }
  shrink(offset, true);
  return result;
}

void ChainedBuffer::append(ChainedBuffer &other) {
  if (&other == this) {
    throw std::invalid_argument("cannot append ChainedBuffer to itself");
  }
  std::scoped_lock lock(mutex_, other.mutex_);
  require_writable_locked();
  other.require_valid_locked();
  if (uninitialized_data_source_) {
    throw std::logic_error(
        "cannot append to ChainedBuffer with uninitialized source");
  }
  if (static_cast<std::uint64_t>(size_) +
          static_cast<std::uint64_t>(other.size_) >
      static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::overflow_error("appended ChainedBuffer is too large");
  }

  auto destination_offset = static_cast<std::size_t>(size_);
  grow(size_ + other.size_, true);
  for (const auto id : other.index_buffer_ids_) {
    other.buffer_manager_.delete_buffer(id);
  }
  other.index_buffer_ids_.clear();
  other.first_buffer_id_ = -1;

  std::size_t remaining = static_cast<std::size_t>(other.size_);
  for (const auto id : other.data_buffer_ids_) {
    const auto count = (std::min)(remaining, other.data_space_);
    if (id >= 0) {
      auto source = other.buffer_manager_.get_buffer(id);
      std::vector<std::uint8_t> data;
      try {
        data = source->get(other.data_base_offset_, count);
        other.buffer_manager_.release_buffer(source);
      } catch (...) {
        try {
          other.buffer_manager_.release_buffer(source);
        } catch (...) {
        }
        throw;
      }
      if (other.use_xor_mask_) {
        for (std::size_t byte = 0; byte < data.size(); ++byte) {
          data[byte] = other.xor_byte(byte, data[byte]);
        }
      }
      put_locked(destination_offset, data);
      other.buffer_manager_.delete_buffer(id);
    }
    destination_offset += count;
    remaining -= count;
  }
  other.data_buffer_ids_.clear();
  other.size_ = 0;
}

void ChainedBuffer::remove() {
  std::scoped_lock lock(mutex_);
  require_writable_locked();
  for (const auto id : data_buffer_ids_) {
    if (id >= 0)
      buffer_manager_.delete_buffer(id);
  }
  for (const auto id : index_buffer_ids_) {
    buffer_manager_.delete_buffer(id);
  }
  data_buffer_ids_.clear();
  index_buffer_ids_.clear();
  size_ = 0;
  first_buffer_id_ = -1;
}

} // namespace llmghidra::db
