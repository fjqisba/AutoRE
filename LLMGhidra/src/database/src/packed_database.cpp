/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/packed_database.hpp"
#include "llmghidra/db/buffer_file_manager.hpp"
#include "llmghidra/db/local_managed_buffer_file.hpp"
#include "llmghidra/db/packed_database_cache.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>

namespace llmghidra::db {
namespace {

constexpr auto packed_lock_timeout = std::chrono::milliseconds(30000);

class ScopedFileLock final {
public:
  ScopedFileLock(LockFile *lock, std::chrono::milliseconds timeout)
      : lock_(lock) {
    if (lock_ && !lock_->create_lock(timeout, true)) {
      throw PackedDatabaseInUseError("packed database is in use by " +
                                     lock_->lock_owner());
    }
  }
  ~ScopedFileLock() {
    if (lock_)
      lock_->remove_lock();
  }
  ScopedFileLock(const ScopedFileLock &) = delete;
  ScopedFileLock &operator=(const ScopedFileLock &) = delete;

private:
  LockFile *lock_;
};

std::filesystem::path unique_sibling(const std::filesystem::path &path,
                                     std::string_view purpose) {
  for (std::uint32_t suffix = 0; suffix < 10000; ++suffix) {
    auto candidate = path;
    candidate += "." + std::string(purpose) + "." + std::to_string(suffix);
    if (!std::filesystem::exists(candidate))
      return candidate;
  }
  throw PackedDatabaseError("unable to allocate packed database sibling path");
}

void remove_regular_if_present(const FileOperations &operations,
                               const std::filesystem::path &path,
                               std::string_view purpose) {
  std::error_code error;
  const auto status = operations.symlink_status(path, error);
  if (error) {
    if (error == std::errc::no_such_file_or_directory)
      return;
    throw std::filesystem::filesystem_error(
        "unable to inspect " + std::string(purpose), path, error);
  }
  if (!std::filesystem::exists(status))
    return;
  if (!std::filesystem::is_regular_file(status)) {
    throw PackedDatabaseError(std::string(purpose) +
                              " exists and is not a regular file");
  }
  if (!operations.remove(path, error) || error) {
    throw std::filesystem::filesystem_error(
        "unable to remove " + std::string(purpose), path, error);
  }
}

class PackedBufferFileManager final : public BufferFileManager {
public:
  PackedBufferFileManager(std::filesystem::path directory,
                          std::function<void()> update_ended)
      : directory_(std::move(directory)),
        update_ended_(std::move(update_ended)) {}

  [[nodiscard]] std::int32_t current_version() const override {
    return current_version_;
  }

  [[nodiscard]] std::filesystem::path
  buffer_file(std::int32_t version) const override {
    if (version < 1) {
      throw std::invalid_argument("invalid packed database buffer version");
    }
    return directory_ / ("db." + std::to_string(version) + ".gbf");
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  version_file(std::int32_t) const override {
    return std::nullopt;
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  change_data_file(std::int32_t) const override {
    return std::nullopt;
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  change_map_file() const override {
    return std::nullopt;
  }

  void version_created(std::int32_t version, const std::string &,
                       std::int64_t) override {
    if (version != current_version_ + 1) {
      throw std::runtime_error(
          "non-consecutive packed database buffer version");
    }
    current_version_ = version;
  }

  void update_ended(std::int64_t) override {
    if (update_ended_)
      update_ended_();
  }

private:
  std::filesystem::path directory_;
  std::function<void()> update_ended_;
  std::int32_t current_version_ = 1;
};

void clear_workspace(const std::filesystem::path &directory) {
  std::error_code error;
  for (const auto &entry :
       std::filesystem::directory_iterator(directory, error)) {
    if (error)
      break;
    std::filesystem::remove_all(entry.path(), error);
    if (error)
      break;
  }
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to clear packed database workspace", directory, error);
  }
}

void remove_obsolete_database_files(
    const std::filesystem::path &directory,
    const std::filesystem::path &current_database) {
  std::error_code error;
  for (const auto &entry :
       std::filesystem::directory_iterator(directory, error)) {
    if (error)
      break;
    const auto name = entry.path().filename().string();
    if (entry.path() == current_database || !name.starts_with("db.") ||
        !name.ends_with(".gbf")) {
      continue;
    }
    std::filesystem::remove(entry.path(), error);
    if (error)
      break;
  }
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to remove obsolete packed database version", directory, error);
  }
}

} // namespace

PackedDatabase::PackedDatabase(std::filesystem::path packed_path,
                               std::filesystem::path temporary_root,
                               LockFileOptions lock_options,
                               std::shared_ptr<PackedDatabaseCache> cache,
                               std::shared_ptr<FileOperations> file_operations)
    : packed_path_(
          std::filesystem::absolute(std::move(packed_path)).lexically_normal()),
      workspace_(std::move(temporary_root)), cache_(std::move(cache)),
      file_operations_(file_operations ? std::move(file_operations)
                                       : std::make_shared<FileOperations>()),
      lock_options_(lock_options) {
  read_only_ = is_read_only_packed_directory(packed_path_.parent_path());
  if (!read_only_) {
    general_lock_ = std::make_unique<LockFile>(packed_path_.parent_path(),
                                               packed_path_.filename().string(),
                                               "", lock_options_);
    update_lock_ = std::make_unique<LockFile>(packed_path_.parent_path(),
                                              packed_path_.filename().string(),
                                              "u", lock_options_);
  }
  ScopedFileLock general(general_lock_.get(), packed_lock_timeout);
  recover_packed_file_locked();
  if (!std::filesystem::is_regular_file(packed_path_)) {
    throw PackedDatabaseError("packed database file does not exist");
  }
  PackedItemReader reader(packed_path_);
  validate_metadata_locked(reader.metadata());
  metadata_ = reader.metadata();
}

PackedDatabase::~PackedDatabase() { dispose(); }

std::unique_ptr<PackedDatabase> PackedDatabase::create_from(
    DatabaseHandle &source, std::filesystem::path packed_path,
    std::string item_name, std::optional<std::string> content_type,
    std::filesystem::path temporary_root, LockFileOptions lock_options,
    std::shared_ptr<PackedDatabaseCache> cache,
    std::shared_ptr<FileOperations> file_operations) {
  packed_path =
      std::filesystem::absolute(std::move(packed_path)).lexically_normal();
  if (is_read_only_packed_directory(packed_path.parent_path())) {
    throw PackedDatabaseReadOnlyError("packed database directory is read-only");
  }
  if (std::filesystem::exists(packed_path)) {
    throw PackedDatabaseError("packed database output already exists");
  }

  LockFile update_lock(packed_path.parent_path(),
                       packed_path.filename().string(), "u", lock_options);
  if (!update_lock.create_lock(std::chrono::milliseconds::zero(), true)) {
    throw PackedDatabaseInUseError("packed database output is in use by " +
                                   update_lock.lock_owner());
  }
  bool created = false;
  try {
    PackedDatabaseWorkspace workspace(temporary_root);
    const auto snapshot_path = workspace.path() / "database.bf";
    auto snapshot = std::make_shared<LocalBufferFile>(
        snapshot_path, source.buffer_manager().buffer_size());
    source.save_as(snapshot, false);
    snapshot->close();
    pack_item(snapshot_path, packed_path, item_name, content_type,
              database_file_type);
    if (cache) {
      try {
        cache->publish(packed_path, snapshot_path);
      } catch (...) {
        // Cache failure must never invalidate an authoritative packed file.
      }
    }
    created = true;
    update_lock.remove_lock();
    return std::make_unique<PackedDatabase>(
        packed_path, std::move(temporary_root), lock_options, std::move(cache),
        std::move(file_operations));
  } catch (...) {
    update_lock.remove_lock();
    if (created) {
      std::error_code ignored;
      std::filesystem::remove(packed_path, ignored);
    }
    throw;
  }
}

void PackedDatabase::validate_metadata_locked(
    const PackedItemMetadata &metadata) const {
  if (metadata.file_type != database_file_type) {
    throw PackedDatabaseError("packed item is not a database");
  }
}

void PackedDatabase::require_live_locked() const {
  if (disposed_)
    throw PackedDatabaseError("packed database is disposed");
}

bool PackedDatabase::handle_open() const noexcept {
  std::scoped_lock lock(mutex_);
  return handle_ != nullptr && !handle_->closed();
}

bool PackedDatabase::update_handle_open() const noexcept {
  std::scoped_lock lock(mutex_);
  return handle_ != nullptr && !handle_->closed() && update_open_;
}

bool PackedDatabase::last_open_used_cache() const noexcept {
  std::scoped_lock lock(mutex_);
  return last_open_used_cache_;
}

bool PackedDatabase::disposed() const noexcept {
  std::scoped_lock lock(mutex_);
  return disposed_;
}

void PackedDatabase::refresh_unpacked_locked() {
  ScopedFileLock general(general_lock_.get(), packed_lock_timeout);
  if (!std::filesystem::is_regular_file(packed_path_)) {
    throw PackedDatabaseError("packed database file no longer exists");
  }
  clear_workspace(workspace_.path());
  const auto unpacked_path = workspace_.path() / "db.1.gbf";
  last_open_used_cache_ = false;
  if (cache_) {
    try {
      auto result = cache_->materialize(packed_path_, unpacked_path);
      validate_metadata_locked(result.metadata);
      metadata_ = std::move(result.metadata);
      last_open_used_cache_ = result.cache_hit;
      file_manager_ = std::make_shared<PackedBufferFileManager>(
          workspace_.path(), [this] { managed_update_ended(); });
      return;
    } catch (...) {
      std::error_code error;
      std::filesystem::remove(unpacked_path, error);
    }
  }
  PackedItemReader reader(packed_path_);
  validate_metadata_locked(reader.metadata());
  reader.unpack_to(unpacked_path);
  metadata_ = reader.metadata();
  file_manager_ = std::make_shared<PackedBufferFileManager>(
      workspace_.path(), [this] { managed_update_ended(); });
}

DatabaseHandle &PackedDatabase::open_locked(bool update) {
  require_live_locked();
  if (handle_ && !handle_->closed()) {
    throw PackedDatabaseInUseError("packed database is already open");
  }
  if (handle_) {
    handle_.reset();
    file_manager_.reset();
  }
  if (update && read_only_) {
    throw PackedDatabaseReadOnlyError("packed database directory is read-only");
  }
  if (update &&
      !update_lock_->create_lock(std::chrono::milliseconds::zero(), true)) {
    throw PackedDatabaseInUseError("packed database update is in use by " +
                                   update_lock_->lock_owner());
  }

  try {
    refresh_unpacked_locked();
    auto unpacked_file =
        std::make_shared<LocalManagedBufferFile>(file_manager_, update, -1, -1);
    handle_ = std::make_unique<DatabaseHandle>(
        unpacked_file, BufferManager::default_cache_size,
        static_cast<std::int32_t>(BufferManager::default_undo_count), !update);
    update_open_ = update;
    return *handle_;
  } catch (...) {
    handle_.reset();
    file_manager_.reset();
    if (update && update_lock_)
      update_lock_->remove_lock();
    throw;
  }
}

DatabaseHandle &PackedDatabase::open() {
  std::scoped_lock lock(mutex_);
  return open_locked(false);
}

DatabaseHandle &PackedDatabase::open_for_update() {
  std::scoped_lock lock(mutex_);
  return open_locked(true);
}

DatabaseHandle &PackedDatabase::handle() {
  std::scoped_lock lock(mutex_);
  require_live_locked();
  if (!handle_ || handle_->closed()) {
    throw PackedDatabaseError("packed database is not open");
  }
  return *handle_;
}

const DatabaseHandle &PackedDatabase::handle() const {
  std::scoped_lock lock(mutex_);
  require_live_locked();
  if (!handle_ || handle_->closed()) {
    throw PackedDatabaseError("packed database is not open");
  }
  return *handle_;
}

void PackedDatabase::recover_packed_file_locked() {
  auto backup = packed_path_;
  backup += ".bak";

  const auto inspect = [&](const std::filesystem::path &path,
                           std::string_view purpose) {
    std::error_code error;
    const auto status = file_operations_->symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory) {
      error.clear();
      return std::filesystem::file_status{
          std::filesystem::file_type::not_found};
    }
    if (error) {
      throw std::filesystem::filesystem_error(
          "unable to inspect " + std::string(purpose), path, error);
    }
    return status;
  };
  const auto valid_database = [&](const std::filesystem::path &path) {
    try {
      PackedItemReader reader(path);
      validate_metadata_locked(reader.metadata());
      reader.verify();
      return true;
    } catch (...) {
      return false;
    }
  };

  const auto packed_status = inspect(packed_path_, "packed database");
  const auto backup_status = inspect(backup, "packed database backup");
  const bool packed_exists = std::filesystem::exists(packed_status);
  const bool backup_exists = std::filesystem::exists(backup_status);
  if (!backup_exists)
    return;
  if (!std::filesystem::is_regular_file(backup_status)) {
    throw PackedDatabaseError(
        "packed database backup exists and is not a regular file");
  }
  if (read_only_) {
    if (packed_exists && std::filesystem::is_regular_file(packed_status))
      return;
    throw PackedDatabaseReadOnlyError(
        "packed database backup recovery requires a writable directory");
  }

  std::error_code error;
  if (!packed_exists) {
    if (!valid_database(backup)) {
      throw PackedDatabaseError(
          "packed database is missing and install backup is invalid");
    }
    file_operations_->rename(backup, packed_path_, error);
    if (error) {
      throw std::filesystem::filesystem_error(
          "unable to restore interrupted packed database install", backup,
          packed_path_, error);
    }
    return;
  }
  if (!std::filesystem::is_regular_file(packed_status)) {
    throw PackedDatabaseError(
        "packed database install target is not a regular file");
  }

  if (valid_database(packed_path_)) {
    if (!file_operations_->remove(backup, error) || error) {
      throw std::filesystem::filesystem_error(
          "unable to remove recovered packed database backup", backup, error);
    }
    return;
  }
  if (!valid_database(backup)) {
    throw PackedDatabaseError(
        "packed database and install backup are both invalid");
  }

  if (!file_operations_->remove(packed_path_, error) || error) {
    throw std::filesystem::filesystem_error(
        "unable to remove invalid packed database install", packed_path_,
        error);
  }
  file_operations_->rename(backup, packed_path_, error);
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to restore packed database backup", backup, packed_path_,
        error);
  }
}

void PackedDatabase::replace_packed_file_locked(
    const std::filesystem::path &replacement) {
  auto backup = packed_path_;
  backup += ".bak";
  recover_packed_file_locked();
  remove_regular_if_present(*file_operations_, backup,
                            "packed database backup");

  std::error_code error;
  file_operations_->rename(packed_path_, backup, error);
  if (error) {
    throw std::filesystem::filesystem_error("unable to backup packed database",
                                            packed_path_, backup, error);
  }

  file_operations_->rename(replacement, packed_path_, error);
  if (error) {
    const auto install_error = error;
    std::error_code restore_error;
    file_operations_->rename(backup, packed_path_, restore_error);
    if (restore_error) {
      throw PackedDatabaseError("packed database install failed and backup "
                                "restoration also failed: " +
                                install_error.message() +
                                "; restore: " + restore_error.message());
    }
    throw std::filesystem::filesystem_error(
        "unable to install updated packed database", replacement, packed_path_,
        install_error);
  }

  if (!file_operations_->remove(backup, error) || error) {
    throw std::filesystem::filesystem_error(
        "updated packed database installed but backup removal failed", backup,
        error);
  }
}

void PackedDatabase::save() {
  std::scoped_lock lock(mutex_);
  require_live_locked();
  if (!handle_ || !update_open_ || !update_lock_ ||
      !update_lock_->have_lock(true)) {
    throw PackedDatabaseReadOnlyError("packed database update is not open");
  }

  if (!file_manager_ || !handle_->can_save()) {
    throw PackedDatabaseError("packed database managed save is unavailable");
  }
  handle_->save("");
  const auto current_database =
      file_manager_->buffer_file(file_manager_->current_version());
  remove_obsolete_database_files(workspace_.path(), current_database);
  try {
    const auto replacement = unique_sibling(packed_path_, "update");
    bool replacement_exists = false;
    try {
      pack_item(current_database, replacement, metadata_.item_name,
                metadata_.content_type, database_file_type);
      replacement_exists = true;
      ScopedFileLock general(general_lock_.get(), packed_lock_timeout);
      replace_packed_file_locked(replacement);
      replacement_exists = false;
      metadata_ = PackedItemReader(packed_path_).metadata();
      if (cache_) {
        try {
          cache_->publish(packed_path_, current_database);
        } catch (...) {
          // The packed file is authoritative; cache refresh is best-effort.
        }
      }
    } catch (...) {
      if (replacement_exists) {
        std::error_code ignored;
        std::filesystem::remove(replacement, ignored);
      }
      throw;
    }
  } catch (...) {
    throw;
  }
}

void PackedDatabase::managed_update_ended() noexcept {
  std::scoped_lock lock(mutex_);
  if (update_lock_)
    update_lock_->remove_lock();
  update_open_ = false;
}

void PackedDatabase::close_handle() noexcept {
  std::scoped_lock lock(mutex_);
  if (handle_)
    handle_->close();
  handle_.reset();
  file_manager_.reset();
  if (update_open_ && update_lock_)
    update_lock_->remove_lock();
  update_open_ = false;
}

void PackedDatabase::dispose() noexcept {
  std::scoped_lock lock(mutex_);
  if (disposed_)
    return;
  close_handle();
  if (general_lock_)
    general_lock_->dispose();
  if (update_lock_)
    update_lock_->dispose();
  if (!workspace_.dispose())
    return;
  disposed_ = true;
}

void PackedDatabase::delete_file() {
  std::scoped_lock lock(mutex_);
  require_live_locked();
  if (read_only_ || !update_lock_) {
    throw PackedDatabaseReadOnlyError("packed database directory is read-only");
  }
  close_handle();
  if (!update_lock_->create_lock(std::chrono::milliseconds::zero(), true)) {
    throw PackedDatabaseInUseError("packed database update is in use by " +
                                   update_lock_->lock_owner());
  }
  try {
    std::error_code error;
    if (!std::filesystem::remove(packed_path_, error) || error) {
      throw std::filesystem::filesystem_error(
          "unable to delete packed database", packed_path_, error);
    }
    if (cache_) {
      try {
        cache_->purge(packed_path_);
      } catch (...) {
        // Deletion of authoritative storage has already succeeded.
      }
    }
    update_lock_->remove_lock();
    if (!workspace_.dispose()) {
      throw PackedDatabaseError(
          "packed database deleted but workspace disposal failed");
    }
    disposed_ = true;
  } catch (...) {
    update_lock_->remove_lock();
    throw;
  }
}

} // namespace llmghidra::db
