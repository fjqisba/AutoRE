/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/local_managed_buffer_file.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace llmghidra::db {

class PrivateDatabaseError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class PrivateDatabaseNotFoundError : public PrivateDatabaseError {
public:
  using PrivateDatabaseError::PrivateDatabaseError;
};

class PrivateDatabaseUpdateError : public PrivateDatabaseError {
public:
  using PrivateDatabaseError::PrivateDatabaseError;
};

// Native counterpart of ghidra.framework.store.db.PrivateDatabase and the
// non-versioned db.Database directory policy. The object owns project-store
// metadata while open LocalManagedBufferFile/DatabaseHandle instances retain
// the shared manager state required to finish their save/close lifecycle.
class PrivateDatabase final {
public:
  using VersionCreatedCallback = std::function<void(std::int32_t)>;

  static constexpr std::string_view database_file_prefix = "db.";
  static constexpr std::string_view version_file_prefix = "ver.";
  static constexpr std::string_view change_file_prefix = "change.";
  static constexpr std::string_view buffer_file_extension = ".gbf";
  static constexpr std::string_view cumulative_change_filename =
      "change.data.gbf";
  static constexpr std::string_view cumulative_modification_filename =
      "change.map.gbf";

  // Open an existing private database directory.
  explicit PrivateDatabase(
      std::filesystem::path directory,
      VersionCreatedCallback version_created = {});

  // Create a complete empty database and publish db.1.gbf atomically through
  // LocalManagedBufferFile's normal version-created lifecycle.
  [[nodiscard]] static std::unique_ptr<PrivateDatabase> create(
      std::filesystem::path directory,
      std::int32_t buffer_size = BufferManager::default_buffer_size,
      VersionCreatedCallback version_created = {});

  // Create from a committed logical database. reset_database_identity matches
  // project import behavior and leaves the source database unchanged.
  [[nodiscard]] static std::unique_ptr<PrivateDatabase> create_from(
      std::filesystem::path directory, DatabaseHandle &source,
      bool reset_database_identity,
      VersionCreatedCallback version_created = {});

  // Import a Ghidra packed database item. Project imports normally request a
  // new database identity to avoid duplicate IDs in one project.
  [[nodiscard]] static std::unique_ptr<PrivateDatabase> create_from_packed(
      std::filesystem::path directory,
      const std::filesystem::path &packed_file,
      bool reset_database_identity = true,
      VersionCreatedCallback version_created = {});

  ~PrivateDatabase() = default;
  PrivateDatabase(const PrivateDatabase &) = delete;
  PrivateDatabase &operator=(const PrivateDatabase &) = delete;
  PrivateDatabase(PrivateDatabase &&) = delete;
  PrivateDatabase &operator=(PrivateDatabase &&) = delete;

  [[nodiscard]] std::filesystem::path directory() const;
  [[nodiscard]] std::int32_t current_version() const;
  [[nodiscard]] std::int32_t minimum_version() const;
  [[nodiscard]] std::filesystem::file_time_type last_modified() const;
  [[nodiscard]] std::uintmax_t length() const;
  [[nodiscard]] bool update_allowed() const;
  [[nodiscard]] bool checkout_copy() const;
  [[nodiscard]] bool update_open() const;
  [[nodiscard]] bool disposed() const;

  void refresh();
  void move_to(std::filesystem::path directory);
  void set_checkout_copy(bool state);

  [[nodiscard]] std::shared_ptr<LocalManagedBufferFile> open_buffer_file();
  [[nodiscard]] std::shared_ptr<LocalManagedBufferFile>
  open_buffer_file_for_update();
  [[nodiscard]] std::unique_ptr<DatabaseHandle> open();
  [[nodiscard]] std::unique_ptr<DatabaseHandle> open_for_update();

  [[nodiscard]] bool can_recover() const;
  void update_checkout_copy(LocalManagedBufferFile *source,
                            std::int32_t old_version);
  void clear_checkout_changes();
  void update_checkout_from(PrivateDatabase &other);

  void output(const std::filesystem::path &output_file,
              std::string item_name, std::int32_t file_type,
              std::string content_type) const;

  // Remove this private database's owned data directory. The method rejects
  // filesystem roots and active updates, and leaves the object disposed.
  void delete_database();

private:
  struct State;
  class PrivateBufferFileManager;
  struct CreateTag {};

  PrivateDatabase(std::filesystem::path directory, CreateTag,
                  VersionCreatedCallback version_created);

  static void scan_locked(State &state, bool repair);
  static void require_live_locked(const State &state);
  static void remove_failed_create_locked(State &state) noexcept;
  static std::filesystem::path normalize_directory(
      std::filesystem::path directory);
  static std::filesystem::path buffer_path(const State &state,
                                           std::int32_t version);
  static std::unique_ptr<PrivateDatabase> create_from_handle_impl(
      std::filesystem::path directory, DatabaseHandle &source,
      bool reset_database_identity,
      VersionCreatedCallback version_created);

  std::shared_ptr<State> state_;
  std::shared_ptr<PrivateBufferFileManager> manager_;
};

} // namespace llmghidra::db
