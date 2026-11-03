/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/versioned_database.hpp"

#include "llmghidra/db/packed_item.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <exception>
#include <mutex>
#include <optional>
#include <set>
#include <system_error>
#include <utility>
#include <vector>

namespace llmghidra::db {
namespace {

std::optional<std::int32_t> parse_version(std::string_view name,
                                          std::string_view prefix) {
  if (!name.starts_with(prefix) ||
      !name.ends_with(VersionedDatabase::buffer_file_extension)) {
    return std::nullopt;
  }
  const auto first = prefix.size();
  const auto count =
      name.size() - first - VersionedDatabase::buffer_file_extension.size();
  if (count == 0)
    return std::nullopt;
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

void remove_regular_file(const std::filesystem::path &path,
                         bool required = true) {
  std::error_code error;
  const auto status = std::filesystem::symlink_status(path, error);
  if (error) {
    if (!required && error == std::errc::no_such_file_or_directory)
      return;
    throw std::filesystem::filesystem_error("unable to inspect database file",
                                            path, error);
  }
  if (!std::filesystem::exists(status)) {
    if (required) {
      throw VersionedDatabaseNotFoundError("database file not found: " +
                                           path.string());
    }
    return;
  }
  if (!std::filesystem::is_regular_file(status)) {
    throw VersionedDatabaseError("database path is not a regular file: " +
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

std::int64_t file_time_millis(std::filesystem::file_time_type value) {
  const auto system_value =
      std::chrono::time_point_cast<std::chrono::system_clock::duration>(
          value - std::filesystem::file_time_type::clock::now() +
          std::chrono::system_clock::now());
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             system_value.time_since_epoch())
      .count();
}

std::filesystem::path
temporary_buffer_path(const std::filesystem::path &directory) {
  static std::atomic<std::uint64_t> sequence{0};
  const auto epoch = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  for (std::uint64_t attempt = 0; attempt < 1024; ++attempt) {
    const auto candidate =
        directory /
        ("tmp-version-output-" +
         std::to_string(epoch ^ sequence.fetch_add(1) ^ attempt) + ".gbf");
    if (!std::filesystem::exists(candidate))
      return candidate;
  }
  throw VersionedDatabaseError("unable to allocate temporary buffer file");
}

void copy_visible_file(LocalBufferFile &source, LocalBufferFile &destination) {
  DataBuffer buffer;
  for (std::int32_t index = 0; index < source.index_count(); ++index) {
    source.get(buffer, index);
    destination.put(buffer, index);
  }
  destination.set_free_indexes(source.free_indexes());
  destination.clear_parameters();
  for (const auto &name : source.parameter_names()) {
    destination.set_parameter(name, source.parameter(name));
  }
}

} // namespace

struct VersionedDatabase::State final {
  State(std::filesystem::path value,
        std::shared_ptr<VersionedDatabaseListener> callback)
      : directory(std::move(value)), listener(std::move(callback)) {}

  mutable std::recursive_mutex mutex;
  std::filesystem::path directory;
  std::shared_ptr<VersionedDatabaseListener> listener;
  std::int32_t minimum_version = 0;
  std::int32_t current_version = 0;
  std::filesystem::file_time_type last_modified{};
  bool update_open = false;
  bool directory_created = false;
  bool disposed = false;
  std::set<std::int32_t> rejected_versions;
};

class VersionedDatabase::VersionedBufferFileManager final
    : public BufferFileManager {
public:
  explicit VersionedBufferFileManager(std::shared_ptr<State> state)
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
  version_file(std::int32_t version) const override {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    return version_path(*state_, version);
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  change_data_file(std::int32_t version) const override {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    return change_path(*state_, version);
  }

  [[nodiscard]] std::optional<std::filesystem::path>
  change_map_file() const override {
    return std::nullopt;
  }

  void version_created(std::int32_t version, const std::string &comment,
                       std::int64_t checkout_id) override {
    std::int64_t creation_time = 0;
    {
      std::scoped_lock lock(state_->mutex);
      require_live_locked(*state_);
      const auto file = buffer_path(*state_, version);
      if (!std::filesystem::is_regular_file(file)) {
        throw VersionedDatabaseNotFoundError("new database version not found");
      }
      if (state_->current_version != version - 1) {
        if (version > state_->current_version ||
            version < state_->minimum_version) {
          std::error_code ignored;
          std::filesystem::remove(file, ignored);
        }
        throw VersionedDatabaseUpdateError(
            "unexpected version-created notification");
      }

      std::error_code error;
      const auto created = std::filesystem::last_write_time(file, error);
      if (error) {
        throw std::filesystem::filesystem_error(
            "unable to inspect new database version", file, error);
      }
      creation_time = file_time_millis(created);
    }

    bool accepted = false;
    try {
      accepted = state_->listener->version_created(version, creation_time,
                                                   comment, checkout_id);
    } catch (...) {
      std::scoped_lock lock(state_->mutex);
      state_->rejected_versions.insert(version);
      throw;
    }
    if (!accepted) {
      std::scoped_lock lock(state_->mutex);
      state_->rejected_versions.insert(version);
      throw VersionedDatabaseUpdateError(
          "new database version was rejected by listener");
    }

    std::int32_t minimum = 0;
    std::int32_t current = 0;
    {
      std::scoped_lock lock(state_->mutex);
      scan_locked(*state_, true);
      if (state_->current_version == 0) {
        throw VersionedDatabaseNotFoundError("database files not found");
      }
      if (state_->current_version != version) {
        throw VersionedDatabaseUpdateError(
            "new database version was rejected or not published");
      }
      minimum = state_->minimum_version;
      current = state_->current_version;
    }
    state_->listener->versions_changed(minimum, current);
  }

  void version_creation_failed(std::int32_t version) noexcept override {
    std::int32_t minimum = 0;
    std::int32_t current = 0;
    {
      std::scoped_lock lock(state_->mutex);
      if (!state_->rejected_versions.erase(version))
        return;
      std::error_code ignored;
      std::filesystem::remove(buffer_path(*state_, version), ignored);
      if (version > 1) {
        std::filesystem::remove(version_path(*state_, version - 1), ignored);
        std::filesystem::remove(change_path(*state_, version - 1), ignored);
      }
      minimum = state_->minimum_version;
      current = state_->current_version;
    }
    try {
      if (minimum > 0 && current >= minimum) {
        state_->listener->versions_changed(minimum, current);
      }
    } catch (...) {
    }
  }

  void update_ended(std::int64_t checkout_id) override {
    {
      std::scoped_lock lock(state_->mutex);
      state_->update_open = false;
      // version_created runs while the prior source file may still be open. A
      // final best-effort pass after all managed handles close enforces the
      // canonical single-db.N layout on Windows.
      std::error_code ignored;
      for (std::filesystem::directory_iterator
               iterator(state_->directory, ignored),
           end;
           !ignored && iterator != end; iterator.increment(ignored)) {
        const auto candidate = parse_version(
            iterator->path().filename().string(), database_file_prefix);
        if (candidate && *candidate != state_->current_version) {
          std::filesystem::remove(iterator->path(), ignored);
          if (ignored)
            ignored.clear();
        }
      }
    }
    state_->listener->checkin_completed(checkout_id);
  }

private:
  std::shared_ptr<State> state_;
};

std::filesystem::path
VersionedDatabase::normalize_directory(std::filesystem::path directory) {
  if (directory.empty()) {
    throw std::invalid_argument("versioned database directory is empty");
  }
  return std::filesystem::absolute(std::move(directory)).lexically_normal();
}

void VersionedDatabase::require_live_locked(const State &state) {
  if (state.disposed) {
    throw VersionedDatabaseError("versioned database is disposed");
  }
}

std::filesystem::path VersionedDatabase::buffer_path(const State &state,
                                                     std::int32_t version) {
  return state.directory /
         (std::string(database_file_prefix) + std::to_string(version) +
          std::string(buffer_file_extension));
}

std::filesystem::path VersionedDatabase::version_path(const State &state,
                                                      std::int32_t version) {
  return state.directory /
         (std::string(version_file_prefix) + std::to_string(version) +
          std::string(buffer_file_extension));
}

std::filesystem::path VersionedDatabase::change_path(const State &state,
                                                     std::int32_t version) {
  return state.directory /
         (std::string(change_file_prefix) + std::to_string(version) +
          std::string(buffer_file_extension));
}

void VersionedDatabase::scan_locked(State &state, bool repair,
                                    const TaskContext &task) {
  require_live_locked(state);
  task.checkpoint();
  std::error_code error;
  if (!std::filesystem::is_directory(state.directory, error) || error) {
    throw VersionedDatabaseNotFoundError("database directory not found: " +
                                         state.directory.string());
  }

  std::vector<std::filesystem::path> entries;
  for (std::filesystem::directory_iterator iterator(state.directory, error),
       end;
       !error && iterator != end; iterator.increment(error)) {
    task.checkpoint();
    entries.push_back(iterator->path());
  }
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to scan versioned database directory", state.directory, error);
  }

  std::vector<std::int32_t> databases;
  std::vector<std::int32_t> versions;
  std::vector<std::int32_t> changes;
  const auto scan_total = static_cast<std::uint64_t>(entries.size());
  task.report("versioned-database-scan", 0, scan_total);
  std::uint64_t scanned = 0;
  for (const auto &entry : entries) {
    const auto name = entry.filename().string();
    if (const auto database_version =
            parse_version(name, database_file_prefix)) {
      databases.push_back(*database_version);
    } else if (const auto historical_version =
                   parse_version(name, version_file_prefix)) {
      versions.push_back(*historical_version);
    } else if (const auto change_version =
                   parse_version(name, change_file_prefix)) {
      changes.push_back(*change_version);
    }
    task.report("versioned-database-scan", ++scanned, scan_total);
  }
  const auto normalize = [](std::vector<std::int32_t> &values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
  };
  normalize(databases);
  normalize(versions);
  normalize(changes);

  const auto current_version = databases.empty() ? 0 : databases.back();
  auto minimum_version = current_version;
  std::filesystem::file_time_type last_modified{};
  if (current_version != 0) {
    last_modified = std::filesystem::last_write_time(
        buffer_path(state, current_version), error);
    if (error) {
      throw std::filesystem::filesystem_error(
          "unable to inspect current database version", state.directory, error);
    }
  }

  std::set<std::int32_t> version_set(versions.begin(), versions.end());
  while (minimum_version > 1 && version_set.contains(minimum_version - 1)) {
    --minimum_version;
  }
  auto minimum_change = current_version;
  std::set<std::int32_t> change_set(changes.begin(), changes.end());
  while (minimum_change > 1 && change_set.contains(minimum_change - 1)) {
    --minimum_change;
  }
  minimum_version = (std::max)(minimum_version, minimum_change);

  std::vector<std::filesystem::path> repair_files;
  if (repair) {
    for (const auto version : databases) {
      if (version == current_version)
        continue;
      repair_files.push_back(buffer_path(state, version));
    }
    for (const auto version : versions) {
      if (version >= current_version || version < minimum_version) {
        repair_files.push_back(version_path(state, version));
      }
    }
    for (const auto version : changes) {
      if (version >= current_version || version < minimum_version) {
        repair_files.push_back(change_path(state, version));
      }
    }

    const auto repair_total = static_cast<std::uint64_t>(repair_files.size());
    task.report("versioned-database-repair", 0, repair_total);
    std::uint64_t prepared = 0;
    for ([[maybe_unused]] const auto &file : repair_files) {
      task.report("versioned-database-repair", ++prepared, repair_total);
    }
  }

  // This is the final cancellation point. Repair publication consists only of
  // best-effort removals, matching fixed-upstream scanFiles(true). Once the
  // first path is removed, cancellation must not turn a committed repair into
  // a reported failure.
  task.checkpoint();
  for (const auto &file : repair_files) {
    std::error_code ignored;
    std::filesystem::remove(file, ignored);
  }
  state.current_version = current_version;
  state.minimum_version = minimum_version;
  state.last_modified = last_modified;
}

VersionedDatabase::VersionedDatabase(
    std::filesystem::path directory,
    std::shared_ptr<VersionedDatabaseListener> listener,
    const TaskContext &task)
    : state_(std::make_shared<State>(normalize_directory(std::move(directory)),
                                     std::move(listener))),
      manager_(std::make_shared<VersionedBufferFileManager>(state_)) {
  if (!state_->listener) {
    throw std::invalid_argument("null VersionedDatabaseListener");
  }
  std::int32_t minimum = 0;
  std::int32_t current = 0;
  {
    std::scoped_lock lock(state_->mutex);
    scan_locked(*state_, true, task);
    if (state_->current_version == 0) {
      throw VersionedDatabaseNotFoundError("database files not found");
    }
    minimum = state_->minimum_version;
    current = state_->current_version;
  }
  state_->listener->versions_changed(minimum, current);
}

VersionedDatabase::VersionedDatabase(
    std::filesystem::path directory,
    std::shared_ptr<VersionedDatabaseListener> listener, CreateTag)
    : state_(std::make_shared<State>(normalize_directory(std::move(directory)),
                                     std::move(listener))),
      manager_(std::make_shared<VersionedBufferFileManager>(state_)) {
  if (!state_->listener) {
    throw std::invalid_argument("null VersionedDatabaseListener");
  }
  std::scoped_lock lock(state_->mutex);
  std::error_code error;
  const auto status = std::filesystem::symlink_status(state_->directory, error);
  if (error && error != std::errc::no_such_file_or_directory) {
    throw std::filesystem::filesystem_error(
        "unable to inspect versioned database directory", state_->directory,
        error);
  }
  if (!error && std::filesystem::exists(status)) {
    if (!std::filesystem::is_directory(status)) {
      throw VersionedDatabaseError("database path is not a directory");
    }
    for (std::filesystem::directory_iterator iterator(state_->directory), end;
         iterator != end; ++iterator) {
      const auto filename = iterator->path().filename().string();
      const bool allowed_metadata =
          std::filesystem::is_regular_file(iterator->path()) &&
          (filename == "checkout.dat" || filename == "history.dat");
      if (!allowed_metadata) {
        throw VersionedDatabaseError(
            "database directory contains unexpected content");
      }
    }
  } else {
    error.clear();
    if (!std::filesystem::create_directories(state_->directory, error) ||
        error) {
      throw std::filesystem::filesystem_error(
          "unable to create versioned database directory", state_->directory,
          error);
    }
    state_->directory_created = true;
  }
}

void VersionedDatabase::remove_failed_create_locked(State &state) noexcept {
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
        parse_version(name, version_file_prefix) ||
        parse_version(name, change_file_prefix) ||
        (name.starts_with("tmp") &&
         (name.ends_with(".ps") || name.ends_with(".gbf")))) {
      std::filesystem::remove_all(iterator->path(), ignored);
      if (ignored)
        break;
    }
  }
  state.minimum_version = 0;
  state.current_version = 0;
  state.last_modified = {};
  state.update_open = false;
}

std::unique_ptr<VersionedDatabase>
VersionedDatabase::create(std::filesystem::path directory,
                          std::shared_ptr<VersionedDatabaseListener> listener,
                          std::int64_t checkout_id, std::int32_t buffer_size,
                          std::string comment) {
  DatabaseHandle source(buffer_size);
  return create_from_handle_impl(std::move(directory), source,
                                 std::move(listener), checkout_id,
                                 std::move(comment));
}

std::unique_ptr<VersionedDatabase> VersionedDatabase::create_from(
    std::filesystem::path directory, DatabaseHandle &source,
    std::shared_ptr<VersionedDatabaseListener> listener,
    std::int64_t checkout_id, std::string comment) {
  return create_from_handle_impl(std::move(directory), source,
                                 std::move(listener), checkout_id,
                                 std::move(comment));
}

std::unique_ptr<VersionedDatabase> VersionedDatabase::create_from_handle_impl(
    std::filesystem::path directory, DatabaseHandle &source,
    std::shared_ptr<VersionedDatabaseListener> listener,
    std::int64_t checkout_id, std::string comment) {
  auto database = std::unique_ptr<VersionedDatabase>(new VersionedDatabase(
      std::move(directory), std::move(listener), CreateTag{}));
  std::shared_ptr<LocalManagedBufferFile> destination;
  try {
    if (database->state_->listener->checkout_version(checkout_id) != 0) {
      throw VersionedDatabaseUpdateError("expected checkout version zero");
    }
    {
      std::scoped_lock lock(database->state_->mutex);
      database->state_->update_open = true;
    }
    destination = std::make_shared<LocalManagedBufferFile>(
        source.buffer_manager().buffer_size(), database->manager_, checkout_id);
    destination->set_version_comment(std::move(comment));
    source.save_as(destination, false);
    destination->close();
    destination.reset();
    return database;
  } catch (...) {
    if (destination) {
      try {
        if (!destination->closed())
          destination->delete_file();
      } catch (...) {
      }
    }
    std::scoped_lock lock(database->state_->mutex);
    remove_failed_create_locked(*database->state_);
    throw;
  }
}

std::unique_ptr<VersionedDatabase> VersionedDatabase::create_from_packed(
    std::filesystem::path directory, const std::filesystem::path &packed_file,
    std::shared_ptr<VersionedDatabaseListener> listener,
    std::int64_t checkout_id, std::string comment) {
  auto database = std::unique_ptr<VersionedDatabase>(new VersionedDatabase(
      std::move(directory), std::move(listener), CreateTag{}));
  try {
    if (database->state_->listener->checkout_version(checkout_id) != 0) {
      throw VersionedDatabaseUpdateError("expected checkout version zero");
    }
    PackedItemReader reader(packed_file);
    if (reader.metadata().file_type != 0) {
      throw VersionedDatabaseError("packed item is not a database");
    }
    reader.unpack_to(buffer_path(*database->state_, 1));
    database->manager_->version_created(1, comment, checkout_id);
    database->manager_->update_ended(checkout_id);
    return database;
  } catch (...) {
    std::scoped_lock lock(database->state_->mutex);
    remove_failed_create_locked(*database->state_);
    throw;
  }
}

std::filesystem::path VersionedDatabase::directory() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->directory;
}

std::int32_t VersionedDatabase::minimum_version() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->minimum_version;
}

std::int32_t VersionedDatabase::current_version() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->current_version;
}

std::filesystem::file_time_type VersionedDatabase::last_modified() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  return state_->last_modified;
}

std::uintmax_t VersionedDatabase::length() const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->current_version == 0) {
    throw VersionedDatabaseNotFoundError("database files not found");
  }
  return std::filesystem::file_size(
      buffer_path(*state_, state_->current_version));
}

bool VersionedDatabase::update_open() const {
  std::scoped_lock lock(state_->mutex);
  return !state_->disposed && state_->update_open;
}

void VersionedDatabase::refresh(const TaskContext &task) {
  std::int32_t minimum = 0;
  std::int32_t current = 0;
  {
    std::scoped_lock lock(state_->mutex);
    scan_locked(*state_, false, task);
    if (state_->current_version == 0) {
      throw VersionedDatabaseNotFoundError("database files not found");
    }
    minimum = state_->minimum_version;
    current = state_->current_version;
  }
  state_->listener->versions_changed(minimum, current);
}

void VersionedDatabase::moved_to(std::filesystem::path directory,
                                 const TaskContext &task) {
  directory = normalize_directory(std::move(directory));
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->update_open) {
    throw VersionedDatabaseUpdateError(
        "cannot move database state while an update is open");
  }
  const auto old_directory = state_->directory;
  const auto old_minimum = state_->minimum_version;
  const auto old_current = state_->current_version;
  const auto old_modified = state_->last_modified;
  state_->directory = std::move(directory);
  try {
    scan_locked(*state_, false, task);
    if (state_->current_version == 0) {
      throw VersionedDatabaseNotFoundError("moved database files not found");
    }
  } catch (...) {
    state_->directory = old_directory;
    state_->minimum_version = old_minimum;
    state_->current_version = old_current;
    state_->last_modified = old_modified;
    throw;
  }
}

std::shared_ptr<LocalManagedBufferFile>
VersionedDatabase::open_buffer_file(std::int32_t version,
                                    std::int32_t minimum_change_data_version) {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (version == latest_version)
    version = state_->current_version;
  if (version < state_->minimum_version || version > state_->current_version) {
    throw VersionedDatabaseNotFoundError(
        "requested database version is not available");
  }
  if (version == state_->current_version) {
    return std::make_shared<LocalManagedBufferFile>(
        manager_, false, minimum_change_data_version, default_checkout_id);
  }
  return std::make_shared<LocalManagedBufferFile>(manager_, version,
                                                  minimum_change_data_version);
}

std::shared_ptr<LocalManagedBufferFile>
VersionedDatabase::open_buffer_file_for_update(std::int64_t checkout_id) {
  const auto checkout_version = state_->listener->checkout_version(checkout_id);
  if (checkout_version < 0) {
    throw VersionedDatabaseUpdateError("checkout not found");
  }
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->update_open) {
    throw VersionedDatabaseUpdateError(
        "versioned database update is already open");
  }
  state_->update_open = true;
  try {
    return std::make_shared<LocalManagedBufferFile>(
        manager_, true, checkout_version, checkout_id);
  } catch (...) {
    state_->update_open = false;
    throw;
  }
}

std::unique_ptr<DatabaseHandle>
VersionedDatabase::open(std::int32_t version,
                        std::int32_t minimum_change_data_version) {
  return std::make_unique<DatabaseHandle>(
      open_buffer_file(version, minimum_change_data_version),
      BufferManager::default_cache_size,
      static_cast<std::int32_t>(BufferManager::default_undo_count), true);
}

std::unique_ptr<DatabaseHandle>
VersionedDatabase::open_for_update(std::int64_t checkout_id) {
  auto file = open_buffer_file_for_update(checkout_id);
  try {
    return std::make_unique<DatabaseHandle>(
        std::move(file), BufferManager::default_cache_size,
        static_cast<std::int32_t>(BufferManager::default_undo_count), false);
  } catch (...) {
    file.reset();
    throw;
  }
}

void VersionedDatabase::delete_minimum_version() {
  std::int32_t deleted = 0;
  std::filesystem::path deleted_version;
  std::filesystem::path deleted_change;
  {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    if (state_->update_open) {
      throw VersionedDatabaseUpdateError(
          "cannot delete a version while an update is open");
    }
    if (state_->minimum_version == state_->current_version) {
      throw VersionedDatabaseUpdateError(
          "unable to delete last remaining version");
    }
    deleted = state_->minimum_version;
    const auto version = version_path(*state_, deleted);
    const auto change = change_path(*state_, deleted);
    deleted_version = version.string() + ".delete";
    deleted_change = change.string() + ".delete";
    remove_regular_file(deleted_version, false);
    remove_regular_file(deleted_change, false);
    rename_file(version, deleted_version, "unable to quarantine version file");
    try {
      rename_file(change, deleted_change, "unable to quarantine change file");
    } catch (...) {
      std::error_code ignored;
      std::filesystem::rename(deleted_version, version, ignored);
      throw;
    }
    ++state_->minimum_version;
  }
  std::exception_ptr callback_error;
  try {
    state_->listener->version_deleted(deleted);
  } catch (...) {
    callback_error = std::current_exception();
  }
  std::error_code ignored;
  std::filesystem::remove(deleted_version, ignored);
  ignored.clear();
  std::filesystem::remove(deleted_change, ignored);
  if (callback_error)
    std::rethrow_exception(callback_error);
}

void VersionedDatabase::delete_current_version() {
  std::int32_t deleted = 0;
  std::filesystem::path deleted_version;
  std::filesystem::path deleted_change;
  std::filesystem::path previous_buffer;
  bool rebuilt = false;
  {
    std::scoped_lock lock(state_->mutex);
    require_live_locked(*state_);
    if (state_->update_open) {
      throw VersionedDatabaseUpdateError(
          "cannot delete a version while an update is open");
    }
    if (state_->minimum_version == state_->current_version) {
      throw VersionedDatabaseUpdateError(
          "unable to delete last remaining version");
    }

    deleted = state_->current_version;
    const auto previous = deleted - 1;
    previous_buffer = buffer_path(*state_, previous);
    if (!std::filesystem::is_regular_file(previous_buffer)) {
      LocalManagedBufferFile source(manager_, previous, -1);
      LocalBufferFile destination(previous_buffer, source.buffer_size());
      try {
        copy_visible_file(source, destination);
        destination.close();
        source.close();
        rebuilt = true;
      } catch (...) {
        try {
          if (!destination.closed())
            destination.delete_file();
        } catch (...) {
        }
        throw;
      }
    }

    const auto version = version_path(*state_, previous);
    const auto change = change_path(*state_, previous);
    deleted_version = version.string() + ".delete";
    deleted_change = change.string() + ".delete";
    remove_regular_file(deleted_version, false);
    remove_regular_file(deleted_change, false);
    try {
      rename_file(version, deleted_version,
                  "unable to quarantine version file");
      try {
        rename_file(change, deleted_change, "unable to quarantine change file");
      } catch (...) {
        std::error_code ignored;
        std::filesystem::rename(deleted_version, version, ignored);
        throw;
      }
      try {
        remove_regular_file(buffer_path(*state_, deleted));
      } catch (...) {
        std::error_code ignored;
        std::filesystem::rename(deleted_version, version, ignored);
        std::filesystem::rename(deleted_change, change, ignored);
        if (rebuilt)
          std::filesystem::remove(previous_buffer, ignored);
        throw;
      }
    } catch (...) {
      if (rebuilt) {
        std::error_code ignored;
        std::filesystem::remove(previous_buffer, ignored);
      }
      throw;
    }

    --state_->current_version;
    state_->last_modified = std::filesystem::last_write_time(previous_buffer);
  }
  std::exception_ptr callback_error;
  try {
    state_->listener->version_deleted(deleted);
  } catch (...) {
    callback_error = std::current_exception();
  }
  std::error_code ignored;
  std::filesystem::remove(deleted_version, ignored);
  ignored.clear();
  std::filesystem::remove(deleted_change, ignored);
  if (callback_error)
    std::rethrow_exception(callback_error);
}

void VersionedDatabase::delete_database() {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (state_->update_open) {
    throw VersionedDatabaseUpdateError(
        "cannot delete a database while an update is open");
  }
  const auto root = state_->directory.root_path();
  if (state_->directory.empty() || state_->directory == root) {
    throw VersionedDatabaseError("refusing to delete filesystem root");
  }
  std::error_code error;
  std::filesystem::remove_all(state_->directory, error);
  if (error || std::filesystem::exists(state_->directory)) {
    throw std::filesystem::filesystem_error(
        "unable to delete versioned database directory", state_->directory,
        error);
  }
  state_->minimum_version = 0;
  state_->current_version = 0;
  state_->last_modified = {};
  state_->disposed = true;
}

void VersionedDatabase::output(std::int32_t version,
                               const std::filesystem::path &output_file,
                               std::string item_name, std::int32_t file_type,
                               std::string content_type) const {
  std::scoped_lock lock(state_->mutex);
  require_live_locked(*state_);
  if (std::filesystem::exists(output_file)) {
    throw VersionedDatabaseError("packed output already exists");
  }
  if (version == latest_version)
    version = state_->current_version;
  if (version < state_->minimum_version || version > state_->current_version) {
    throw VersionedDatabaseNotFoundError(
        "requested database version is not available");
  }
  if (version == state_->current_version) {
    pack_item(buffer_path(*state_, version), output_file, std::move(item_name),
              std::move(content_type), file_type);
    return;
  }

  const auto temporary = temporary_buffer_path(state_->directory);
  bool exists = false;
  try {
    LocalManagedBufferFile source(manager_, version, -1);
    LocalBufferFile destination(temporary, source.buffer_size());
    exists = true;
    copy_visible_file(source, destination);
    destination.close();
    source.close();
    pack_item(temporary, output_file, std::move(item_name),
              std::move(content_type), file_type);
    remove_regular_file(temporary);
  } catch (...) {
    if (exists) {
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
    }
    std::error_code ignored;
    std::filesystem::remove(output_file, ignored);
    throw;
  }
}

} // namespace llmghidra::db
