/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/database_parameters.hpp"

#include <limits>
#include <stdexcept>

namespace llmghidra::db {

DatabaseParameters::DatabaseParameters(BufferManager &buffers, bool create)
    : buffers_(buffers) {
  if (create) {
    auto buffer = buffers_.create_buffer();
    try {
      if (buffer->id() != 0) {
        throw std::logic_error("DatabaseParameters must be buffer ID 0");
      }
      if (buffer->size() < parameter_base_offset) {
        throw std::runtime_error("database buffer is too small for parameters");
      }
      buffer->clear();
      buffer->put_u8(node_type_offset, node_type);
      buffer->put_i32(data_length_offset, 1);
      buffer->put_u8(version_offset, storage_version);
      buffer->set_dirty(true);
    }
    catch (...) {
      buffer->set_empty(true);
      buffer->set_dirty(true);
      buffers_.release_buffer(buffer);
      throw;
    }
    buffers_.release_buffer(buffer);
  }
  refresh();
}

std::size_t DatabaseParameters::parameter_capacity() const noexcept {
  const auto size = static_cast<std::size_t>(buffers_.buffer_size());
  return size <= parameter_base_offset
             ? 0
             : (size - parameter_base_offset) / sizeof(std::int32_t);
}

std::int32_t DatabaseParameters::get(std::size_t parameter) const {
  if (parameter >= values_.size()) {
    throw std::out_of_range("database parameter is not allocated");
  }
  return values_[parameter];
}

void DatabaseParameters::set(std::size_t parameter, std::int32_t value) {
  if (parameter >= parameter_capacity()) {
    throw std::out_of_range("database parameter exceeds buffer capacity");
  }
  auto buffer = buffers_.get_buffer(0);
  try {
    buffer->put_i32(offset(parameter), value);
    if (parameter >= values_.size()) {
      // Java DBParms leaves expanded holes as zero because the newly-created
      // parameter buffer is cleared before use.
      values_.resize(parameter + 1, 0);
      const auto data_length =
          1 + values_.size() * sizeof(std::int32_t);
      if (data_length >
          static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        throw std::overflow_error("database parameter data length exceeds int32");
      }
      buffer->put_i32(data_length_offset,
                      static_cast<std::int32_t>(data_length));
    }
    values_[parameter] = value;
    buffer->set_dirty(true);
  }
  catch (...) {
    buffers_.release_buffer(buffer);
    throw;
  }
  buffers_.release_buffer(buffer);
}

void DatabaseParameters::refresh() {
  auto buffer = buffers_.get_buffer(0);
  try {
    if (buffer->get_u8(node_type_offset) != node_type) {
      throw std::runtime_error("unexpected DatabaseParameters node type");
    }
    if (buffer->get_u8(version_offset) != storage_version) {
      throw std::runtime_error("unsupported DatabaseParameters version");
    }
    const auto data_length = buffer->get_i32(data_length_offset);
    if (data_length < 1 || (data_length - 1) % 4 != 0) {
      throw std::runtime_error("invalid DatabaseParameters data length");
    }
    const auto count = static_cast<std::size_t>((data_length - 1) / 4);
    if (count > parameter_capacity()) {
      throw std::runtime_error("DatabaseParameters data exceeds buffer");
    }
    std::vector<std::int32_t> refreshed;
    refreshed.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
      refreshed.push_back(buffer->get_i32(offset(index)));
    }
    values_ = std::move(refreshed);
  }
  catch (...) {
    buffers_.release_buffer(buffer);
    throw;
  }
  buffers_.release_buffer(buffer);
}

} // namespace llmghidra::db
