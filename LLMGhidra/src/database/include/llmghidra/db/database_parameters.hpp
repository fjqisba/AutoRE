/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer_manager.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace llmghidra::db {

// Disk-compatible native counterpart of db.DBParms.  The parameter block is
// always DataBuffer ID 0 and participates in BufferManager checkpoints.
class DatabaseParameters final {
public:
  static constexpr std::size_t master_table_root_parameter = 0;
  static constexpr std::size_t database_id_high_parameter = 1;
  static constexpr std::size_t database_id_low_parameter = 2;

  static constexpr std::uint8_t storage_version = 1;
  static constexpr std::uint8_t node_type = 9;
  static constexpr std::size_t node_type_offset = 0;
  static constexpr std::size_t data_length_offset = 1;
  static constexpr std::size_t version_offset = 5;
  static constexpr std::size_t parameter_base_offset = 6;

  DatabaseParameters(BufferManager &buffers, bool create);

  [[nodiscard]] std::int32_t get(std::size_t parameter) const;
  void set(std::size_t parameter, std::int32_t value);
  void refresh();
  [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }

private:
  [[nodiscard]] std::size_t parameter_capacity() const noexcept;
  [[nodiscard]] static std::size_t offset(std::size_t parameter) noexcept {
    return parameter_base_offset + parameter * sizeof(std::int32_t);
  }

  BufferManager &buffers_;
  std::vector<std::int32_t> values_;
};

} // namespace llmghidra::db
