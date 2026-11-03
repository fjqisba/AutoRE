/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/private_database.hpp"

#include "llmghidra/db/packed_item.hpp"
#include "llmghidra/db/recovery_manager.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <mutex>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace llmghidra::db {
namespace {

std::optional<std::int32_t> parse_version(std::string_view name,
                                          std::string_view prefix) {
  if (!name.starts_with(prefix) ||
      !name.ends_with(PrivateDatabase::buffer_file_extension)) {
    return std::nullopt;
  }
  const auto first = prefix.size();
  const auto count = name.size() - first -
                     PrivateDatabase::buffer_file_extension.size();
  if (count == 0) return std::nullopt;
  const auto text = name.substr(first, count);
  std::int32_t value = 0;
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
      value < 1) {
    return std::nullopt;
  }
  return value;
}

void remove_file_if_present(const std::filesystem::path &path) {
  std::error_code error;
  const auto status = std::filesystem::symlink_status(path, error);
  if (error) {
    if (error == std::errc::no_such_file_or_directory) return;
    throw std::filesystem::filesystem_error("unable to inspect database file",
                                            path, error);
  }
  if (!std::filesystem::exists(status)) return;
  if (!std::filesystem::is_regular_file(status)) {
    throw PrivateDatabaseError("database path is not a regular file: " +
                               path.string());
  }
  if (!std::filesystem::remove(path, error) || error) {
    throw std::filesystem::filesystem_error("unable to remove database file",
                                            path, error);
  }
}

void rename_file(const std::filesystem::path &source,
                 const std::filesystem::path &destination,
                 std::string_view operation) {
  std::error_code error;
  std::filesystem::rename(source, destination, error);
  if (error) {
    throw std::filesystem::filesystem_error(std::string(operation), source,
                                            destination, error);
  }
}

} // namespace

struct PrivateDatabase::State final {
  explicit State(std::filesystem::path value,
                 VersionCreatedCallback callback)
      : directory(std::move(value)), version_created(std::move(callback)) {}

  mutable std::recursive_mutex mutex;
  std::filesystem::path directory;
  VersionCreatedCallback version_created;
  std::int32_t minimum_version = 0;
  std::int32_t current_version = 0;
  std::filesystem::file_time_type last_modified{};
  bool checkout_copy = false;
  bool update_allowed = true;
  bool update_open = false;
  bool directory_created = false;
  bool disposed = false;
};

class PrivateDatabase::PrivateBufferFileManager final
    : public BufferFileManager {
public:
  explicit PrivateBufferFileManager(std::shared_ptr<State> state)
      : state_(std::move(state)) {}

  [[nodiscard]] std::int32_t current_version() const override {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    return state_->current_version;
  }

  [[nodiscard]] std::filesystem::path
  buffer_file(std::int32_t version) const override {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    return buffer_path(*state_, version);
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  version_file(std::int32_t) const override {
    return std::nullopt;
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  change_data_file(std::int32_t) const override {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    if (!state_->checkout_copy) return std::nullopt;
    return state_->directory /
           std::string(PrivateDatabase::cumulative_change_filename);
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  change_map_file() const override {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    if (!state_->checkout_copy) return std::nullopt;
    return state_->directory /
           std::string(PrivateDatabase::cumulative_modification_filename);
  }

  void version_created(std::int32_t version, const std::string &,
                       std::int64_t) override {
    VersionCreatedCallback callback;
    {
      std::scoped_lock lock(state_->mutex);
      require_live_locked(*state_);
      if (state_->current_version != version - 1) {
        if (version > state_->current_version ||
            version < state_->minimum_version) {
          std::error_code ignored;
          std::filesystem::remove(buffer_path(*state_, version), ignored);
        }
        throw PrivateDatabaseUpdateError(
            "unexpected private database version notification");
      }
      scan_locked(*state_, true);
      if (state_->current_version != version) {
        throw PrivateDatabaseUpdateError(
            "new private database version was not published");
      }
      callback = state_->version_created;
    }
    if (callback) callback(version);
  }

  void update_ended(std::int64_t) override {
    std::scoped_lock lock(state_->mutex);
    state_->update_open = false;
  }

private:
  std::shared_ptr<State> state_;
};

std::filesystem::path
PrivateDatabase::normalize_directory(std::filesystem::path directory) {
  if (directory.empty()) {
    throw std::invalid_argument("private database directory is empty");
  }
  return std::filesystem::absolute(std::move(directory)).lexically_normal();
}

std::filesystem::path PrivateDatabase::buffer_path(const State &state,
                                                   std::int32_t version) {
  return state.directory /
         (std::string(database_file_prefix) + std::to_string(version) +
          std::string(buffer_file_extension));
}

void PrivateDatabase::require_live_locked(const State &state) {
  if (state.disposed) {
    throw PrivateDatabaseError("private database is disposed");
  }
}

void PrivateDatabase::scan_locked(State &state, bool repair) {
  require_live_locked(state);
  std::error_code error;
  if (!std::filesystem::is_directory(state.directory, error) || error) {
    throw PrivateDatabaseNotFoundError("database directory not found: " +
                                      state.directory.string());
  }

  std::vector<std::int32_t> database_versions;
  bool version_files_present = false;
  for (std::filesystem::directory_iterator iterator(state.directory, error), end;
       !error && iterator != end; iterator.increment(error)) {
    const auto name = iterator->path().filename().string();
    if (const auto version = parse_version(name, database_file_prefix)) {
      database_versions.push_back(*version);
    }
    else if (parse_version(name, version_file_prefix)) {
      version_files_present = true;
    }
  }
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to scan private database directory", state.directory, error);
  }

  std::sort(database_versions.begin(), database_versions.end());
  database_versions.erase(
      std::unique(database_versions.begin(), database_versions.end()),
      database_versions.end());
  state.current_version = database_versions.empty() ? 0
                                                    : database_versions.back();
  state.minimum_version = state.current_version;
  state.update_allowed = !version_files_present;
  state.last_modified = {};
  if (state.current_version != 0) {
    state.last_modified =
        std::filesystem::last_write_time(
            buffer_path(state, state.current_version), error);
    if (error) {
      throw std::filesystem::filesystem_error(
          "unable to inspect current private database", state.directory,
          error);
    }
  }

  if (repair && database_versions.size() > 1) {
    for (const auto version : database_versions) {
      if (version == state.current_version) continue;
      // Java Database.scanFiles(true) deliberately treats obsolete-buffer
      // deletion as best effort. On Windows the previous source is still open
      // when LocalManagedBufferFile publishes the new version, so failing the
      // version-created callback here would turn a committed save into an
      // apparent failure. A later save/repair pass reclaims the stale file.
      std::error_code ignored;
      std::filesystem::remove(buffer_path(state, version), ignored);
    }
  }
}

PrivateDatabase::PrivateDatabase(std::filesystem::path directory,
                                 VersionCreatedCallback version_created)
    : state_(std::make_shared<State>(normalize_directory(std::move(directory)),
                                     std::move(version_created))),
      manager_(std::make_shared<PrivateBufferFileManager>(state_)) {
  std::scoped_lock lock(state_->mutex);
  scan_locked(*state_, false);
  state_->checkout_copy = std::filesystem::is_regular_file(
      state_->directory / std::string(cumulative_change_filename));
}

PrivateDatabase::PrivateDatabase(std::filesystem::path directory, CreateTag,
                                 VersionCreatedCallback version_created)
    : state_(std::make_shared<State>(normalize_directory(std::move(directory)),
                                     std::move(version_created))),
      manager_(std::make_shared<PrivateBufferFileManager>(state_)) {
  std::scoped_lock lock(state_->mutex);
  std::error_code error;
  const auto status = std::filesystem::symlink_status(state_->directory, error);
  if (error && error != std::errc::no_such_file_or_directory) {
    throw std::filesystem::filesystem_error(
        "unable to inspect private database directory", state_->directory,
        error);
  }
  if (!error && std::filesystem::exists(status)) {
    if (!std::filesystem::is_directory(status)) {
      throw PrivateDatabaseError("private database path is not a directory");
    }
    if (!std::filesystem::is_empty(state_->directory)) {
      throw PrivateDatabaseError("private database directory is not empty");
    }
  }
  else {
    error.clear();
    if (!std::filesystem::create_directories(state_->directory, error) ||
        error) {
      throw std::filesystem::filesystem_error(
          "unable to create private database directory", state_->directory,
          error);
    }
    state_->directory_created = true;
  }
  scan_locked(*state_, false);
}

void PrivateDatabase::remove_failed_create_locked(State &state) noexcept {
  std::error_code ignored;
  if (state.directory_created) {
    std::filesystem::remove_all(state.directory, ignored);
    return;
  }
  for (std::filesystem::directory_iterator iterator(state.directory, ignored),
       end;
       !ignored && iterator != end; iterator.increment(ignored)) {
    const auto name = iterator->path().filename().string();
    if (parse_version(name, database_file_prefix) ||
        (name.starts_with("tmp") && name.ends_with(".ps")) ||
        name == cumulative_change_filename ||
        name == cumulative_modification_filename) {
      std::filesystem::remove_all(iterator->path(), ignored);
      if (ignored) break;
    }
  }
  state.current_version = 0;
  state.minimum_version = 0;
  state.last_modified = {};
  state.update_open = false;
}

std::unique_ptr<PrivateDatabase> PrivateDatabase::create(
    std::filesystem::path directory, std::int32_t buffer_size,
    VersionCreatedCallback version_created) {
  DatabaseHandle source(buffer_size);
  return create_from_handle_impl(std::move(directory), source, false,
                                 std::move(version_created));
}

std::unique_ptr<PrivateDatabase> PrivateDatabase::create_from(
    std::filesystem::path directory, DatabaseHandle &source,
    bool reset_database_identity, VersionCreatedCallback version_created) {
  return create_from_handle_impl(std::move(directory), source,
                                 reset_database_identity,
                                 std::move(version_created));
}

std::unique_ptr<PrivateDatabase> PrivateDatabase::create_from_handle_impl(
    std::filesystem::path directory, DatabaseHandle &source,
    bool reset_database_identity, VersionCreatedCallback version_created) {
  auto database = std::unique_ptr<PrivateDatabase>(new PrivateDatabase(
      std::move(directory), CreateTag{}, std::move(version_created)));
  std::shared_ptr<LocalManagedBufferFile> destination;
  try {
    {
      std::scoped_lock lock(database->state_->mutex);
      database->state_->update_open = true;
    }
    destination = std::make_shared<LocalManagedBufferFile>(
        source.buffer_manager().buffer_size(), database->manager_, -1);
    source.save_as(destination, false);
    destination->close();
    destination.reset();
    if (reset_database_identity) {
      LocalBufferFile file(
          buffer_path(*database->state_, database->state_->current_version),
          LocalBufferFile::OpenMode::read_write);
      (void)DatabaseHandle::reset_database_id(file);
      file.close();
      database->refresh();
    }
    return database;
  }
  catch (...) {
    if (destination) {
      try {
        if (!destination->closed()) destination->delete_file();
      }
      catch (...) {
      }
    }
    std::scoped_lock lock(database->state_->mutex);
    remove_failed_create_locked(*database->state_);
    throw;
  }
}

std::unique_ptr<PrivateDatabase> PrivateDatabase::create_from_packed(
    std::filesystem::path directory,
    const std::filesystem::path &packed_file, bool reset_database_identity,
    VersionCreatedCallback version_created) {
  auto database = std::unique_ptr<PrivateDatabase>(new PrivateDatabase(
      std::move(directory), CreateTag{}, std::move(version_created)));
  try {
    PackedItemReader reader(packed_file);
    if (reader.metadata().file_type != 0) {
      throw PrivateDatabaseError("packed item is not a database");
    }
    const auto destination = buffer_path(*database->state_, 1);
    reader.unpack_to(destination);
    if (reset_database_identity) {
      LocalBufferFile file(destination, LocalBufferFile::OpenMode::read_write);
      (void)DatabaseHandle::reset_database_id(file);
      file.close();
    }
    database->manager_->version_created(1, {}, -1);
    return database;
  }
  catch (...) {
    std::scoped_lock lock(database->state_->mutex);
    remove_failed_create_locked(*database->state_);
    throw;
  }
}

std::filesystem::path PrivateDatabase::directory() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->directory;
}

std::int32_t PrivateDatabase::current_version() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->current_version;
}

std::int32_t PrivateDatabase::minimum_version() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->minimum_version;
}

std::filesystem::file_time_type PrivateDatabase::last_modified() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->last_modified;
}

std::uintmax_t PrivateDatabase::length() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->current_version == 0) {
    throw PrivateDatabaseNotFoundError("database files not found");
  }
  return std::filesystem::file_size(
      buffer_path(*state_, state_->current_version));
}

bool PrivateDatabase::update_allowed() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->update_allowed;
}

bool PrivateDatabase::checkout_copy() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->checkout_copy;
}

bool PrivateDatabase::update_open() const {
  std::scoped_lock lock(state_->mutex);
  return !state_->disposed && state_->update_open;
}

bool PrivateDatabase::disposed() const {
  std::scoped_lock lock(state_->mutex);
  return state_->disposed;
}

void PrivateDatabase::refresh() {
  std::scoped_lock lock(state_->mutex);
  scan_locked(*state_, false);
  if (state_->current_version == 0) {
    throw PrivateDatabaseNotFoundError("database files not found");
  }
}

void PrivateDatabase::move_to(std::filesystem::path directory) {
  directory = normalize_directory(std::move(directory));
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->update_open) {
    throw PrivateDatabaseUpdateError(
        "cannot move database state while an update is open");
  }
  const auto old_directory = state_->directory;
  const auto old_minimum = state_->minimum_version;
  const auto old_current = state_->current_version;
  const auto old_modified = state_->last_modified;
  const auto old_update_allowed = state_->update_allowed;
  state_->directory = std::move(directory);
  try {
    scan_locked(*state_, false);
    if (state_->current_version == 0) {
      throw PrivateDatabaseNotFoundError("moved database files not found");
    }
  }
  catch (...) {
    state_->directory = old_directory;
    state_->minimum_version = old_minimum;
    state_->current_version = old_current;
    state_->last_modified = old_modified;
    state_->update_allowed = old_update_allowed;
    throw;
  }
}

void PrivateDatabase::set_checkout_copy(bool state) {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->update_open) {
    throw PrivateDatabaseUpdateError(
        "cannot change checkout state during an update");
  }
  state_->checkout_copy = state;
}

std::shared_ptr<LocalManagedBufferFile>
PrivateDatabase::open_buffer_file() {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->current_version == 0) {
    throw PrivateDatabaseNotFoundError("database files not found");
  }
  return std::make_shared<LocalManagedBufferFile>(manager_, false, -1, -1);
}

std::shared_ptr<LocalManagedBufferFile>
PrivateDatabase::open_buffer_file_for_update() {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->current_version == 0) {
    throw PrivateDatabaseNotFoundError("database files not found");
  }
  if (!state_->update_allowed) {
    throw PrivateDatabaseUpdateError("update use is not permitted");
  }
  if (state_->update_open) {
    throw PrivateDatabaseUpdateError(
        "private database update is already open");
  }
  state_->update_open = true;
  try {
    return std::make_shared<LocalManagedBufferFile>(manager_, true, -1, -1);
  }
  catch (...) {
    state_->update_open = false;
    throw;
  }
}

std::unique_ptr<DatabaseHandle> PrivateDatabase::open() {
  return std::make_unique<DatabaseHandle>(
      open_buffer_file(), BufferManager::default_cache_size,
      static_cast<std::int32_t>(BufferManager::default_undo_count), true);
}

std::unique_ptr<DatabaseHandle> PrivateDatabase::open_for_update() {
  auto file = open_buffer_file_for_update();
  try {
    return std::make_unique<DatabaseHandle>(
        std::move(file), BufferManager::default_cache_size,
        static_cast<std::int32_t>(BufferManager::default_undo_count), false);
  }
  catch (...) {
    file.reset();
    throw;
  }
}

bool PrivateDatabase::can_recover() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->current_version == 0) return false;
  LocalBufferFile source(buffer_path(*state_, state_->current_version),
                         LocalBufferFile::OpenMode::read_only);
  const auto result = RecoveryManager::can_recover(source);
  source.close();
  return result;
}

void PrivateDatabase::clear_checkout_changes() {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (!state_->checkout_copy) {
    throw PrivateDatabaseUpdateError("database is not a checkout copy");
  }
  remove_file_if_present(
      state_->directory / std::string(cumulative_change_filename));
  remove_file_if_present(
      state_->directory / std::string(cumulative_modification_filename));
}

void PrivateDatabase::update_checkout_copy(LocalManagedBufferFile *source,
                                           std::int32_t old_version) {
  {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    if (!state_->checkout_copy) {
      throw PrivateDatabaseUpdateError("database is not a checkout copy");
    }
  }
  if (source) {
    auto destination = open_buffer_file_for_update();
    try {
      destination->update_from(*source, old_version);
      destination->close();
    }
    catch (...) {
      try {
        destination->close();
      }
      catch (...) {
      }
      throw;
    }
  }
  clear_checkout_changes();
}

void PrivateDatabase::update_checkout_from(PrivateDatabase &other) {
  if (this == &other) {
    throw std::invalid_argument("cannot update a database from itself");
  }
  std::scoped_lock lock(state_->mutex, other.state_->mutex);
  require_live_locked(*state_);
  require_live_locked(*other.state_);
  if (!state_->checkout_copy) {
    throw PrivateDatabaseUpdateError("database is not a checkout copy");
  }
  if (state_->update_open || other.state_->update_open) {
    throw PrivateDatabaseUpdateError(
        "cannot replace a database while an update is open");
  }
  if (other.state_->current_version == 0) {
    throw PrivateDatabaseNotFoundError("update database file not found");
  }
  if (state_->current_version == std::numeric_limits<std::int32_t>::max()) {
    throw PrivateDatabaseUpdateError("database version space exhausted");
  }

  const auto new_version = state_->current_version + 1;
  const auto other_buffer =
      buffer_path(*other.state_, other.state_->current_version);
  const auto new_buffer = buffer_path(*state_, new_version);
  const auto source_change =
      other.state_->directory / std::string(cumulative_change_filename);
  const auto source_map = other.state_->directory /
                          std::string(cumulative_modification_filename);
  const auto change =
      state_->directory / std::string(cumulative_change_filename);
  const auto map = state_->directory /
                   std::string(cumulative_modification_filename);
  const auto backup_change = change.string() + ".bak";
  const auto backup_map = map.string() + ".bak";

  remove_file_if_present(backup_change);
  remove_file_if_present(backup_map);
  if (!std::filesystem::is_regular_file(other_buffer) ||
      !std::filesystem::is_regular_file(source_change) ||
      !std::filesystem::is_regular_file(source_map)) {
    throw PrivateDatabaseNotFoundError(
        "checkout replacement database or change data is missing");
  }
  if (std::filesystem::exists(new_buffer)) {
    throw PrivateDatabaseUpdateError(
        "concurrent private database version modification");
  }

  bool buffer_moved = false;
  bool change_backed_up = false;
  bool map_backed_up = false;
  bool source_change_moved = false;
  bool source_map_moved = false;
  try {
    rename_file(other_buffer, new_buffer, "unable to install update buffer");
    buffer_moved = true;
    if (std::filesystem::exists(map)) {
      rename_file(map, backup_map, "unable to backup modification map");
      map_backed_up = true;
    }
    if (std::filesystem::exists(change)) {
      rename_file(change, backup_change, "unable to backup change data");
      change_backed_up = true;
    }
    rename_file(source_map, map, "unable to install modification map");
    source_map_moved = true;
    rename_file(source_change, change, "unable to install change data");
    source_change_moved = true;

    remove_file_if_present(backup_change);
    remove_file_if_present(backup_map);
    state_->current_version = new_version;
    state_->minimum_version = new_version;
    state_->last_modified = std::filesystem::last_write_time(new_buffer);
    other.state_->current_version = 0;
    other.state_->minimum_version = 0;
    other.state_->last_modified = {};
  }
  catch (...) {
    std::error_code ignored;
    if (source_change_moved) std::filesystem::rename(change, source_change, ignored);
    ignored.clear();
    if (source_map_moved) std::filesystem::rename(map, source_map, ignored);
    ignored.clear();
    if (change_backed_up) std::filesystem::rename(backup_change, change, ignored);
    ignored.clear();
    if (map_backed_up) std::filesystem::rename(backup_map, map, ignored);
    ignored.clear();
    if (buffer_moved) std::filesystem::rename(new_buffer, other_buffer, ignored);
    throw;
  }
}

void PrivateDatabase::output(const std::filesystem::path &output_file,
                             std::string item_name, std::int32_t file_type,
                             std::string content_type) const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->current_version == 0) {
    throw PrivateDatabaseNotFoundError("database files not found");
  }
  pack_item(buffer_path(*state_, state_->current_version), output_file,
            std::move(item_name), std::move(content_type), file_type);
}

void PrivateDatabase::delete_database() {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->update_open) {
    throw PrivateDatabaseUpdateError(
        "cannot delete a database while an update is open");
  }
  const auto root = state_->directory.root_path();
  if (state_->directory.empty() || state_->directory == root) {
    throw PrivateDatabaseError("refusing to delete filesystem root");
  }
  std::error_code error;
  std::filesystem::remove_all(state_->directory, error);
  if (error || std::filesystem::exists(state_->directory)) {
    throw std::filesystem::filesystem_error(
        "unable to delete private database directory", state_->directory,
        error);
  }
  state_->current_version = 0;
  state_->minimum_version = 0;
  state_->last_modified = {};
  state_->disposed = true;
}

} // namespace llmghidra::db
