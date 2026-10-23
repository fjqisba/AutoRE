/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace llmghidra::db {

// Native storage-policy boundary corresponding to db.buffers.BufferFileManager.
// Paths may be absent when version, change-data, or change-map storage is not
// enabled by a concrete database container.
class BufferFileManager {
public:
  virtual ~BufferFileManager() = default;
  [[nodiscard]] virtual std::int32_t current_version() const = 0;
  [[nodiscard]] virtual std::filesystem::path
  buffer_file(std::int32_t version) const = 0;
  [[nodiscard]] virtual std::optional<std::filesystem::path>
  version_file(std::int32_t version) const = 0;
  [[nodiscard]] virtual std::optional<std::filesystem::path>
  change_data_file(std::int32_t version) const = 0;
  [[nodiscard]] virtual std::optional<std::filesystem::path>
  change_map_file() const = 0;
  virtual void version_created(std::int32_t version,
                               const std::string &comment,
                               std::int64_t checkin_id) = 0;
  // Called after LocalManagedBufferFile has closed its OS handle when a
  // version-created callback throws. Containers that reject a committed
  // version can safely remove it here on Windows.
  virtual void version_creation_failed(std::int32_t) noexcept {}
  virtual void update_ended(std::int64_t checkin_id) = 0;
};

} // namespace llmghidra::db
