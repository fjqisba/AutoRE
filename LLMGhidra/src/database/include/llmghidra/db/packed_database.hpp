/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/file_operations.hpp"
#include "llmghidra/db/lock_file.hpp"
#include "llmghidra/db/packed_database_workspace.hpp"
#include "llmghidra/db/packed_item.hpp"

#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace llmghidra::db {

class PackedDatabaseCache;
class BufferFileManager;

class PackedDatabaseError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class PackedDatabaseInUseError : public PackedDatabaseError {
public:
  using PackedDatabaseError::PackedDatabaseError;
};

class PackedDatabaseReadOnlyError : public PackedDatabaseError {
public:
  using PackedDatabaseError::PackedDatabaseError;
};

// Native lifecycle shell for Ghidra's single-version PackedDatabase. The
// unpacked database and its DatabaseHandle are owned by this object; callers
// must close through close_handle() before opening another view.
class PackedDatabase final {
public:
  static constexpr std::int32_t database_file_type = 0;

  explicit PackedDatabase(std::filesystem::path packed_path,
                          std::filesystem::path temporary_root =
                              std::filesystem::temp_directory_path(),
                          LockFileOptions lock_options = {},
                          std::shared_ptr<PackedDatabaseCache> cache = {},
                          std::shared_ptr<FileOperations> file_operations = {});

  static std::unique_ptr<PackedDatabase>
  create_from(DatabaseHandle &source, std::filesystem::path packed_path,
              std::string item_name, std::optional<std::string> content_type,
              std::filesystem::path temporary_root =
                  std::filesystem::temp_directory_path(),
              LockFileOptions lock_options = {},
              std::shared_ptr<PackedDatabaseCache> cache = {},
              std::shared_ptr<FileOperations> file_operations = {});
  ~PackedDatabase();

  PackedDatabase(const PackedDatabase &) = delete;
  PackedDatabase &operator=(const PackedDatabase &) = delete;
  PackedDatabase(PackedDatabase &&) = delete;
  PackedDatabase &operator=(PackedDatabase &&) = delete;

  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return packed_path_;
  }
  [[nodiscard]] const PackedItemMetadata &metadata() const noexcept {
    return metadata_;
  }
  [[nodiscard]] bool read_only() const noexcept { return read_only_; }
  [[nodiscard]] bool handle_open() const noexcept;
  [[nodiscard]] bool update_handle_open() const noexcept;
  [[nodiscard]] bool last_open_used_cache() const noexcept;
  [[nodiscard]] bool disposed() const noexcept;
  [[nodiscard]] const std::filesystem::path &workspace_path() const noexcept {
    return workspace_.path();
  }

  DatabaseHandle &open();
  DatabaseHandle &open_for_update();
  DatabaseHandle &handle();
  const DatabaseHandle &handle() const;
  void save();
  void repack() { save(); }
  void close_handle() noexcept;
  void dispose() noexcept;
  void delete_file();

private:
  DatabaseHandle &open_locked(bool update);
  void refresh_unpacked_locked();
  void validate_metadata_locked(const PackedItemMetadata &metadata) const;
  void require_live_locked() const;
  void recover_packed_file_locked();
  void replace_packed_file_locked(const std::filesystem::path &replacement);
  void managed_update_ended() noexcept;

  std::filesystem::path packed_path_;
  PackedItemMetadata metadata_;
  PackedDatabaseWorkspace workspace_;
  std::unique_ptr<LockFile> general_lock_;
  std::unique_ptr<LockFile> update_lock_;
  std::shared_ptr<BufferFileManager> file_manager_;
  std::unique_ptr<DatabaseHandle> handle_;
  std::shared_ptr<PackedDatabaseCache> cache_;
  std::shared_ptr<FileOperations> file_operations_;
  LockFileOptions lock_options_;
  mutable std::recursive_mutex mutex_;
  bool read_only_ = false;
  bool update_open_ = false;
  bool last_open_used_cache_ = false;
  bool disposed_ = false;
};

} // namespace llmghidra::db
