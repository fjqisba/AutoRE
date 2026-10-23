/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>

namespace llmghidra::db {

inline constexpr const char *packed_database_directory_lock = ".dbDirLock";

// A .dbDirLock in the directory or any ancestor makes packed databases below
// that point read-only, matching PackedDatabase.isReadOnlyPDBDirectory().
[[nodiscard]] bool
is_read_only_packed_directory(const std::filesystem::path &directory);

// Owns the exclusive temporary directory used to unpack one PackedDatabase.
// Disposal first renames the directory to a .delete sibling, so a failed
// rename cannot accidentally erase a workspace that is still in use.
class PackedDatabaseWorkspace final {
public:
  explicit PackedDatabaseWorkspace(
      std::filesystem::path temporary_root =
          std::filesystem::temp_directory_path());
  ~PackedDatabaseWorkspace();

  PackedDatabaseWorkspace(const PackedDatabaseWorkspace &) = delete;
  PackedDatabaseWorkspace &operator=(const PackedDatabaseWorkspace &) = delete;
  PackedDatabaseWorkspace(PackedDatabaseWorkspace &&) = delete;
  PackedDatabaseWorkspace &operator=(PackedDatabaseWorkspace &&) = delete;

  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }
  [[nodiscard]] bool disposed() const noexcept { return path_.empty(); }
  [[nodiscard]] bool dispose() noexcept;

  static std::size_t cleanup_old(
      const std::filesystem::path &temporary_root,
      std::chrono::hours minimum_age = std::chrono::hours(24 * 7));

private:
  std::filesystem::path path_;
};

} // namespace llmghidra::db
