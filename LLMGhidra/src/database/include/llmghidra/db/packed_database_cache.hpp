/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/lock_file.hpp"
#include "llmghidra/db/packed_item.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>

namespace llmghidra::db {

struct PackedDatabaseCacheOptions final {
  std::filesystem::path root;
  std::chrono::milliseconds shelf_life = std::chrono::hours(24 * 7);
  std::chrono::milliseconds lock_timeout = std::chrono::milliseconds(30000);
  LockFileOptions lock_options{};
};

struct PackedDatabaseCacheResult final {
  PackedItemMetadata metadata;
  bool cache_hit = false;
};

// Persistent unpacking cache corresponding to Ghidra's PackedDatabaseCache.
// The cache is an optimization only: every consumer receives a private copy,
// and all authoritative writes still replace the packed database itself.
class PackedDatabaseCache final {
public:
  explicit PackedDatabaseCache(PackedDatabaseCacheOptions options);
  ~PackedDatabaseCache() = default;

  PackedDatabaseCache(const PackedDatabaseCache &) = delete;
  PackedDatabaseCache &operator=(const PackedDatabaseCache &) = delete;
  PackedDatabaseCache(PackedDatabaseCache &&) = delete;
  PackedDatabaseCache &operator=(PackedDatabaseCache &&) = delete;

  [[nodiscard]] const std::filesystem::path &root() const noexcept {
    return root_;
  }

  // Materialize a validated raw database at a new destination. A cache hit
  // still verifies the packed source fingerprint before copying cached bytes.
  PackedDatabaseCacheResult materialize(
      const std::filesystem::path &packed_path,
      const std::filesystem::path &destination);

  // Publish a raw snapshot after the corresponding packed file has been
  // atomically installed. Metadata is re-read from the packed file.
  void publish(const std::filesystem::path &packed_path,
               const std::filesystem::path &raw_database);

  void purge(const std::filesystem::path &packed_path);
  [[nodiscard]] bool contains(const std::filesystem::path &packed_path);
  std::size_t cleanup();

private:
  std::filesystem::path root_;
  std::filesystem::path map_path_;
  LockFile lock_;
  std::chrono::milliseconds shelf_life_;
  std::chrono::milliseconds lock_timeout_;
  std::mutex mutex_;
};

} // namespace llmghidra::db
