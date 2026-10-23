/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/local_managed_buffer_file.hpp"
#include "llmghidra/task_control.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace llmghidra::db {

class VersionedDatabaseError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class VersionedDatabaseNotFoundError : public VersionedDatabaseError {
public:
  using VersionedDatabaseError::VersionedDatabaseError;
};

class VersionedDatabaseUpdateError : public VersionedDatabaseError {
public:
  using VersionedDatabaseError::VersionedDatabaseError;
};

class VersionedDatabase;

// Pure C++ policy boundary corresponding to VersionedDBListener. The Java
// database object parameter is deliberately absent: callers receive stable
// value data and do not participate in the storage object's lifetime.
class VersionedDatabaseListener {
public:
  virtual ~VersionedDatabaseListener() = default;
  virtual void versions_changed(std::int32_t minimum_version,
                                std::int32_t current_version) = 0;
  [[nodiscard]] virtual bool version_created(std::int32_t version,
                                             std::int64_t creation_time_millis,
                                             const std::string &comment,
                                             std::int64_t checkout_id) = 0;
  virtual void version_deleted(std::int32_t version) = 0;
  [[nodiscard]] virtual std::int32_t
  checkout_version(std::int64_t checkout_id) = 0;
  virtual void checkin_completed(std::int64_t checkout_id) = 0;
};

// Native counterpart of ghidra.framework.store.db.VersionedDatabase. Only the
// latest db.N.gbf is retained; historical versions are reconstructed from the
// contiguous ver.N.gbf chain by LocalManagedBufferFile/VersionFileHandler.
class VersionedDatabase final {
public:
  static constexpr std::int32_t latest_version = -1;
  static constexpr std::int64_t default_checkout_id = -1;
  static constexpr std::string_view database_file_prefix = "db.";
  static constexpr std::string_view version_file_prefix = "ver.";
  static constexpr std::string_view change_file_prefix = "change.";
  static constexpr std::string_view buffer_file_extension = ".gbf";

  // Open and repair an existing versioned database directory.
  VersionedDatabase(std::filesystem::path directory,
                    std::shared_ptr<VersionedDatabaseListener> listener,
                    const TaskContext &task = {});

  [[nodiscard]] static std::unique_ptr<VersionedDatabase>
  create(std::filesystem::path directory,
         std::shared_ptr<VersionedDatabaseListener> listener,
         std::int64_t checkout_id,
         std::int32_t buffer_size = BufferManager::default_buffer_size,
         std::string comment = {});

  [[nodiscard]] static std::unique_ptr<VersionedDatabase>
  create_from(std::filesystem::path directory, DatabaseHandle &source,
              std::shared_ptr<VersionedDatabaseListener> listener,
              std::int64_t checkout_id, std::string comment);

  [[nodiscard]] static std::unique_ptr<VersionedDatabase>
  create_from_packed(std::filesystem::path directory,
                     const std::filesystem::path &packed_file,
                     std::shared_ptr<VersionedDatabaseListener> listener,
                     std::int64_t checkout_id, std::string comment);

  ~VersionedDatabase() = default;
  VersionedDatabase(const VersionedDatabase &) = delete;
  VersionedDatabase &operator=(const VersionedDatabase &) = delete;
  VersionedDatabase(VersionedDatabase &&) = delete;
  VersionedDatabase &operator=(VersionedDatabase &&) = delete;

  [[nodiscard]] std::filesystem::path directory() const;
  [[nodiscard]] std::int32_t minimum_version() const;
  [[nodiscard]] std::int32_t current_version() const;
  [[nodiscard]] std::filesystem::file_time_type last_modified() const;
  [[nodiscard]] std::uintmax_t length() const;
  [[nodiscard]] bool update_open() const;

  void refresh(const TaskContext &task = {});
  // The caller moves the directory first, matching upstream dbMoved().
  void moved_to(std::filesystem::path directory, const TaskContext &task = {});

  [[nodiscard]] std::shared_ptr<LocalManagedBufferFile>
  open_buffer_file(std::int32_t version = latest_version,
                   std::int32_t minimum_change_data_version = -1);
  [[nodiscard]] std::shared_ptr<LocalManagedBufferFile>
  open_buffer_file_for_update(std::int64_t checkout_id);
  [[nodiscard]] std::unique_ptr<DatabaseHandle>
  open(std::int32_t version = latest_version,
       std::int32_t minimum_change_data_version = -1);
  [[nodiscard]] std::unique_ptr<DatabaseHandle>
  open_for_update(std::int64_t checkout_id);

  void delete_minimum_version();
  void delete_current_version();
  void delete_database();

  void output(std::int32_t version, const std::filesystem::path &output_file,
              std::string item_name, std::int32_t file_type,
              std::string content_type) const;

private:
  struct State;
  class VersionedBufferFileManager;
  struct CreateTag {};

  VersionedDatabase(std::filesystem::path directory,
                    std::shared_ptr<VersionedDatabaseListener> listener,
                    CreateTag);

  static std::filesystem::path
  normalize_directory(std::filesystem::path directory);
  static void require_live_locked(const State &state);
  static void scan_locked(State &state, bool repair,
                          const TaskContext &task = {});
  static void remove_failed_create_locked(State &state) noexcept;
  static std::filesystem::path buffer_path(const State &state,
                                           std::int32_t version);
  static std::filesystem::path version_path(const State &state,
                                            std::int32_t version);
  static std::filesystem::path change_path(const State &state,
                                           std::int32_t version);
  static std::unique_ptr<VersionedDatabase>
  create_from_handle_impl(std::filesystem::path directory,
                          DatabaseHandle &source,
                          std::shared_ptr<VersionedDatabaseListener> listener,
                          std::int64_t checkout_id, std::string comment);

  std::shared_ptr<State> state_;
  std::shared_ptr<VersionedBufferFileManager> manager_;
};

} // namespace llmghidra::db
