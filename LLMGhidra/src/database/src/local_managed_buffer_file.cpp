/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/local_managed_buffer_file.hpp"

#include "llmghidra/db/block_stream.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace llmghidra::db {
namespace {

const std::shared_ptr<BufferFileManager> &
require_manager(const std::shared_ptr<BufferFileManager> &manager) {
  if (!manager)
    throw std::invalid_argument("null BufferFileManager");
  return manager;
}

std::filesystem::path
initial_path(const std::shared_ptr<BufferFileManager> &manager) {
  return require_manager(manager)->buffer_file(1);
}

std::filesystem::path
current_path(const std::shared_ptr<BufferFileManager> &manager) {
  const auto version = require_manager(manager)->current_version();
  if (version < 1)
    throw std::invalid_argument("BufferFileManager has no current version");
  return manager->buffer_file(version);
}

} // namespace

LocalManagedBufferFile::LocalManagedBufferFile(
    std::int32_t buffer_size, std::shared_ptr<BufferFileManager> manager,
    std::int64_t checkin_id)
    : LocalBufferFile(initial_path(manager), buffer_size),
      manager_(std::move(manager)), version_(1), checkin_id_(checkin_id),
      open_for_update_(true), update_end_required_(true) {
  if (manager_->current_version() != 0) {
    try {
      delete_file();
    } catch (...) {
    }
    throw std::invalid_argument("initial managed file requires version zero");
  }
}

LocalManagedBufferFile::LocalManagedBufferFile(
    std::shared_ptr<BufferFileManager> manager, bool version_update_enabled,
    std::int32_t minimum_change_data_version, std::int64_t checkin_id)
    : LocalBufferFile(current_path(manager), OpenMode::read_only),
      manager_(std::move(manager)), version_(manager_->current_version()),
      minimum_change_data_version_(minimum_change_data_version),
      checkin_id_(checkin_id), open_for_update_(true),
      update_end_required_(version_update_enabled) {
  if (version_update_enabled)
    start_presave();
}

LocalManagedBufferFile::LocalManagedBufferFile(
    std::shared_ptr<BufferFileManager> manager, std::int32_t version,
    std::int32_t minimum_change_data_version)
    : LocalBufferFile(current_path(manager), OpenMode::read_only),
      manager_(std::move(manager)), version_(version),
      minimum_change_data_version_(minimum_change_data_version) {
  if (version < 1 || version >= manager_->current_version()) {
    throw std::invalid_argument("invalid historical managed file version");
  }
  initialize_historical_view();
}

LocalManagedBufferFile::LocalManagedBufferFile(std::filesystem::path path,
                                               std::int32_t buffer_size)
    : LocalBufferFile(std::move(path), buffer_size) {}

LocalManagedBufferFile::~LocalManagedBufferFile() {
  try {
    close();
  } catch (...) {
    discard_presave();
    discard_save_files();
  }
}

VersionFileHandler::VersionOpener
LocalManagedBufferFile::version_opener() const {
  const auto manager = manager_;
  return [manager](std::int32_t version) -> std::unique_ptr<LocalBufferFile> {
    const auto path = manager->version_file(version);
    if (!path || !std::filesystem::is_regular_file(*path))
      return {};
    return std::make_unique<LocalBufferFile>(*path, OpenMode::read_only);
  };
}

void LocalManagedBufferFile::initialize_historical_view() {
  version_handler_ = std::make_unique<VersionFileHandler>(
      version_opener(), LocalBufferFile::file_id(), manager_->current_version(),
      version_);
  historical_view_ = true;
  historical_file_id_ = version_handler_->original_file_id();
  historical_index_count_ = version_handler_->original_buffer_count();
  historical_free_indexes_ = version_handler_->free_indexes();
  for (const auto &name : version_handler_->old_parameter_names()) {
    historical_parameters_.emplace(name, version_handler_->old_parameter(name));
  }
}

std::filesystem::path LocalManagedBufferFile::allocate_presave_path(
    const std::filesystem::path &directory) {
  static std::atomic<std::uint64_t> sequence{0};
  const auto epoch = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  for (std::uint64_t attempt = 0; attempt < 1024; ++attempt) {
    const auto value = epoch ^ sequence.fetch_add(1) ^ attempt;
    auto candidate = directory / ("tmp" + std::to_string(value) + ".ps");
    if (!std::filesystem::exists(candidate))
      return candidate;
  }
  throw std::runtime_error("unable to allocate pre-save path");
}

void LocalManagedBufferFile::start_presave() {
  if (!manager_ || !read_only() || closed() || historical_view_ ||
      save_in_progress()) {
    return;
  }

  std::shared_ptr<LocalManagedBufferFile> failed_presave;
  std::filesystem::path candidate_path;
  try {
    std::scoped_lock lock(presave_mutex_);
    if (presave_shutdown_ || pre_save_file_ || save_file_ || !presave_done_) {
      return;
    }
    if (presave_worker_.joinable()) {
      presave_worker_.join();
    }

    presave_error_ = {};
    presave_completed_ = 0;
    presave_total_ = static_cast<std::uint64_t>((std::max)(index_count(), 0));
    candidate_path =
        allocate_presave_path(LocalBufferFile::path().parent_path());
    auto presave = std::shared_ptr<LocalManagedBufferFile>(
        new LocalManagedBufferFile(candidate_path, buffer_size()));
    pre_save_file_ = presave;
    presave_cancel_ = CancellationSource{};
    presave_done_ = false;
    const auto cancellation = presave_cancel_.token();
    try {
      presave_worker_ =
          std::thread([this, presave = std::move(presave), cancellation] {
            run_presave(presave, cancellation);
          });
    } catch (...) {
      failed_presave = std::move(pre_save_file_);
      presave_error_ = std::current_exception();
      presave_done_ = true;
      throw;
    }
  } catch (...) {
    if (!failed_presave) {
      std::scoped_lock lock(presave_mutex_);
      presave_error_ = std::current_exception();
      presave_done_ = true;
    }
    if (failed_presave) {
      try {
        failed_presave->delete_file();
      } catch (...) {
      }
    }
    if (!candidate_path.empty()) {
      std::error_code ignored;
      std::filesystem::remove(candidate_path, ignored);
    }
    presave_cv_.notify_all();
  }
}

void LocalManagedBufferFile::run_presave(
    std::shared_ptr<LocalManagedBufferFile> presave,
    CancellationToken cancellation) noexcept {
  std::exception_ptr error;
  bool success = false;
  try {
    TaskContext task{std::move(cancellation), nullptr};
    task.checkpoint();

    // Match the fixed upstream PreSaveTask: use a separate read-only file
    // instance so background seeks never race the primary object's stream.
    LocalManagedBufferFile source(manager_, false, -1, checkin_id_);
    const auto count = source.index_count();
    {
      std::scoped_lock lock(presave_mutex_);
      presave_total_ = static_cast<std::uint64_t>((std::max)(count, 0));
    }
    presave_cv_.notify_all();

    DataBuffer buffer;
    for (std::int32_t index = 0; index < count; ++index) {
      task.checkpoint();
      source.get(buffer, index);
      task.checkpoint();
      presave->put(buffer, index);
      {
        std::scoped_lock lock(presave_mutex_);
        presave_completed_ = static_cast<std::uint64_t>(index) + 1;
      }
      presave_cv_.notify_all();
    }

    task.checkpoint();
    presave->set_free_indexes(source.free_indexes());
    for (const auto &name : source.parameter_names()) {
      task.checkpoint();
      presave->set_parameter(name, source.parameter(name));
    }
    task.checkpoint();
    if (!presave->flush()) {
      throw std::runtime_error("unable to finalize managed pre-save file");
    }
    task.checkpoint();
    success = true;
    source.close();
  } catch (...) {
    error = std::current_exception();
  }

  if (!success) {
    try {
      if (!presave->closed() && !presave->read_only()) {
        presave->delete_file();
      }
    } catch (...) {
    }
  }

  {
    std::scoped_lock lock(presave_mutex_);
    if (pre_save_file_ == presave) {
      if (!success)
        pre_save_file_.reset();
      presave_error_ = error;
      presave_done_ = true;
      if (success)
        presave_completed_ = presave_total_;
    }
  }
  presave_cv_.notify_all();
}

void LocalManagedBufferFile::wait_for_presave(const TaskContext &task) const {
  bool first = true;
  std::uint64_t last_completed = 0;
  std::uint64_t last_total = 0;
  for (;;) {
    std::unique_lock lock(presave_mutex_);
    const auto completed = presave_completed_;
    const auto total = presave_total_;
    const auto done = presave_done_;
    lock.unlock();

    if (first || completed != last_completed || total != last_total || done) {
      task.report("managed-presave", completed, total);
      first = false;
      last_completed = completed;
      last_total = total;
    } else {
      task.checkpoint();
    }
    if (done)
      return;

    lock.lock();
    presave_cv_.wait_for(lock, std::chrono::milliseconds(25), [&] {
      return presave_done_ || presave_completed_ != completed ||
             presave_total_ != total;
    });
  }
}

bool LocalManagedBufferFile::can_save() const noexcept {
  std::scoped_lock lock(presave_mutex_);
  return pre_save_file_ != nullptr;
}

bool LocalManagedBufferFile::save_in_progress() const noexcept {
  std::scoped_lock lock(presave_mutex_);
  return save_file_ != nullptr;
}

void LocalManagedBufferFile::discard_presave() noexcept {
  std::thread worker;
  std::shared_ptr<LocalManagedBufferFile> presave;
  {
    std::scoped_lock lock(presave_mutex_);
    presave_shutdown_ = true;
    presave_cancel_.cancel();
    presave = std::move(pre_save_file_);
    if (presave_worker_.joinable()) {
      worker = std::move(presave_worker_);
    }
  }
  if (worker.joinable())
    worker.join();

  {
    std::scoped_lock lock(presave_mutex_);
    presave_done_ = true;
  }
  if (presave) {
    try {
      if (!presave->closed() && !presave->read_only()) {
        presave->delete_file();
      }
    } catch (...) {
    }
  }
  presave_cv_.notify_all();
}

void LocalManagedBufferFile::discard_save_files() noexcept {
  std::shared_ptr<LocalManagedBufferFile> save_file;
  std::shared_ptr<LocalBufferFile> save_change_file;
  {
    std::scoped_lock lock(presave_mutex_);
    save_file = std::move(save_file_);
    save_change_file = std::move(save_change_file_);
  }
  if (save_file) {
    if (save_file->version_output_) {
      try {
        save_file->version_output_->abort();
      } catch (...) {
      }
      save_file->version_output_.reset();
    }
    if (save_file->change_map_) {
      save_file->change_map_->abort();
      save_file->change_map_.reset();
    }
    try {
      if (!save_file->closed() && !save_file->read_only()) {
        if (!save_file->delete_file()) {
          try {
            save_file->close();
          } catch (...) {
          }
        }
      }
    } catch (...) {
    }
  }
  if (save_change_file) {
    const auto path = save_change_file->path();
    try {
      if (!save_change_file->closed() && !save_change_file->read_only()) {
        if (!save_change_file->delete_file()) {
          try {
            save_change_file->close();
          } catch (...) {
          }
        }
      } else {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
      }
    } catch (...) {
    }
  }
}

std::shared_ptr<LocalManagedBufferFile>
LocalManagedBufferFile::get_save_file(const TaskContext &task) {
  {
    std::scoped_lock lifecycle_lock(lifecycle_mutex_);
    std::scoped_lock presave_lock(presave_mutex_);
    if (presave_shutdown_ || closed())
      return {};
    if (save_file_)
      throw std::logic_error("save already in progress");
  }
  wait_for_presave(task);

  std::unique_lock lifecycle_lock(lifecycle_mutex_);
  std::shared_ptr<LocalManagedBufferFile> save_file;
  {
    std::scoped_lock lock(presave_mutex_);
    if (presave_shutdown_ || closed())
      return {};
    if (save_file_)
      throw std::logic_error("save already in progress");
    if (presave_worker_.joinable())
      presave_worker_.join();
    if (!pre_save_file_)
      return {};
    save_file_ = std::move(pre_save_file_);
    save_file = save_file_;
  }
  try {
    if (index_count() != save_file->index_count()) {
      throw std::runtime_error("pre-save buffer count changed");
    }
    if (const auto path = manager_->version_file(version_)) {
      save_file->version_output_ =
          std::make_unique<VersionFile>(*this, *save_file, *path);
    }
    if (const auto path = manager_->change_map_file()) {
      save_file->change_map_ =
          std::make_unique<ChangeMapFile>(*path, *this, *save_file, version_);
    }
    if (const auto path = manager_->change_data_file(version_)) {
      auto temporary = *path;
      temporary += ".tmp";
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
      auto change_file =
          std::make_shared<LocalBufferFile>(temporary, buffer_size());
      std::scoped_lock lock(presave_mutex_);
      save_change_file_ = std::move(change_file);
    }
    return save_file;
  } catch (...) {
    discard_save_files();
    start_presave();
    throw;
  }
}

std::shared_ptr<LocalBufferFile>
LocalManagedBufferFile::get_save_change_data_file() const {
  std::scoped_lock lock(presave_mutex_);
  return save_change_file_;
}

void LocalManagedBufferFile::commit_save_change_data() {
  std::shared_ptr<LocalBufferFile> save_change_file;
  {
    std::scoped_lock lock(presave_mutex_);
    save_change_file = save_change_file_;
  }
  if (!save_change_file)
    return;
  const auto destination = manager_->change_data_file(version_);
  if (!destination)
    return;
  const auto source = save_change_file->path();
  auto backup = *destination;
  backup += ".bak";
  std::error_code error;
  bool backed_up = false;
  if (std::filesystem::exists(*destination)) {
    std::filesystem::remove(backup, error);
    error.clear();
    std::filesystem::rename(*destination, backup, error);
    if (error)
      throw std::runtime_error("unable to back up change data");
    backed_up = true;
  }
  std::filesystem::rename(source, *destination, error);
  if (error) {
    if (backed_up) {
      std::error_code ignored;
      std::filesystem::rename(backup, *destination, ignored);
    }
    throw std::runtime_error("unable to install change data");
  }
  if (backed_up) {
    error.clear();
    std::filesystem::remove(backup, error);
  }
}

void LocalManagedBufferFile::save_completed(bool commit) {
  std::scoped_lock lifecycle_lock(lifecycle_mutex_);
  std::shared_ptr<LocalManagedBufferFile> committed;
  std::shared_ptr<LocalBufferFile> save_change_file;
  {
    std::scoped_lock lock(presave_mutex_);
    if (!save_file_)
      throw std::logic_error("save is not in progress");
    committed = save_file_;
    save_change_file = save_change_file_;
  }
  if (!commit) {
    discard_save_files();
    start_presave();
    return;
  }

  const auto new_version = version_ + 1;
  const auto destination = manager_->buffer_file(new_version);
  bool success = false;
  try {
    if (save_change_file && !save_change_file->closed()) {
      save_change_file->close();
    }
    if (!committed->rename_to(destination)) {
      throw std::runtime_error("unable to install managed save file");
    }
    committed->version_ = new_version;
    committed->manager_ = manager_;
    committed->open_for_update_ = true;
    committed->update_end_required_ = true;
    committed->checkin_id_ = checkin_id_;
    commit_save_change_data();
    if (!committed->set_read_only()) {
      throw std::runtime_error("unable to commit managed save file");
    }
    success = true;
    update_transferred_ = true;
  } catch (...) {
    if (!success) {
      try {
        if (!committed->closed() && !committed->read_only()) {
          committed->delete_file();
        }
      } catch (...) {
      }
    }
    {
      std::scoped_lock lock(presave_mutex_);
      save_file_.reset();
      save_change_file_.reset();
    }
    throw;
  }
  {
    std::scoped_lock lock(presave_mutex_);
    save_file_.reset();
    save_change_file_.reset();
  }
}

void LocalManagedBufferFile::copy_file(LocalBufferFile &source,
                                       LocalBufferFile &destination,
                                       const ChangeMap *changes) {
  if (source.buffer_size() != destination.buffer_size()) {
    throw std::invalid_argument("managed copy buffer sizes differ");
  }
  const auto &free = source.free_indexes();
  DataBuffer buffer;
  for (std::int32_t index = 0; index < source.index_count(); ++index) {
    if (std::binary_search(free.begin(), free.end(), index))
      continue;
    if (changes && !changes->changed(index))
      continue;
    source.get(buffer, index);
    destination.put(buffer, index);
  }
  if (destination.index_count() > source.index_count()) {
    destination.truncate(source.index_count());
  }
  destination.set_free_indexes(free);
  destination.clear_parameters();
  for (const auto &name : source.parameter_names()) {
    destination.set_parameter(name, source.parameter(name));
  }
}

std::optional<std::vector<std::uint8_t>>
LocalManagedBufferFile::checkout_modification_map() const {
  if (!manager_)
    return std::nullopt;
  const auto path = manager_->change_map_file();
  if (!path || !std::filesystem::is_regular_file(*path))
    return std::nullopt;
  auto &self = const_cast<LocalManagedBufferFile &>(*this);
  ChangeMapFile map(*path, self);
  auto data = map.modification_data();
  map.close();
  return data;
}

void LocalManagedBufferFile::create_new_version(
    LocalManagedBufferFile &destination, std::string comment) {
  auto output = destination.get_save_file();
  if (!output)
    throw std::runtime_error("destination does not allow update");
  bool success = false;
  std::shared_ptr<LocalBufferFile> input_change;
  std::shared_ptr<LocalBufferFile> output_change;
  try {
    output->set_version_comment(std::move(comment));
    input_change = next_change_data_file(true);
    if (!input_change || next_change_data_file(false)) {
      throw std::runtime_error("unexpected check-in change-data sequence");
    }
    const auto data = checkout_modification_map();
    if (!data)
      throw std::runtime_error("check-in modification map is missing");
    ChangeMap changes(*data);
    copy_file(*this, *output, &changes);

    output_change = destination.get_save_change_data_file();
    if (!output_change) {
      throw std::runtime_error("destination change-data file is unavailable");
    }
    copy_file(*input_change, *output_change, nullptr);
    output_change->close();
    output_change.reset();
    success = true;
  } catch (...) {
    destination.save_completed(false);
    if (output && !output->closed())
      output->close();
    throw;
  }
  destination.save_completed(success);
  output->close();
}

void LocalManagedBufferFile::update_from(LocalManagedBufferFile &versioned_file,
                                         std::int32_t old_version) {
  if (!can_save())
    throw std::runtime_error("file does not allow update");
  if (!manager_)
    throw std::logic_error("managed file has no manager");

  ChangeMap changes(versioned_file.forward_modification_map(old_version));
  if (const auto local = checkout_modification_map())
    changes.add(*local);
  changes.set_changed(free_indexes());
  changes.set_unchanged(versioned_file.free_indexes());

  auto output = get_save_file();
  if (!output)
    throw std::runtime_error("pre-save is unavailable");
  try {
    copy_file(versioned_file, *output, &changes);
    save_completed(true);
  } catch (...) {
    if (save_in_progress())
      save_completed(false);
    if (output && !output->closed())
      output->close();
    throw;
  }
  output->close();
}

std::shared_ptr<LocalBufferFile>
LocalManagedBufferFile::next_change_data_file(bool first) {
  if (!manager_)
    return {};
  if (first || next_change_data_version_ == -1) {
    next_change_data_version_ = minimum_change_data_version_ != -1
                                    ? minimum_change_data_version_
                                    : version_ - 1;
  }
  if (next_change_data_version_ >= version_)
    return {};
  const auto path = manager_->change_data_file(next_change_data_version_++);
  if (!path)
    return {};
  if (minimum_change_data_version_ == -1 &&
      !std::filesystem::is_regular_file(*path)) {
    return {};
  }
  return std::make_shared<LocalBufferFile>(*path, OpenMode::read_only);
}

std::vector<std::uint8_t> LocalManagedBufferFile::forward_modification_map(
    std::int32_t old_version) const {
  if (!manager_ || old_version < 1 || old_version >= version_) {
    throw std::invalid_argument("invalid modification map version");
  }
  VersionFileHandler handler(version_opener(), file_id(), version_,
                             old_version);
  return handler.forward_modification_map();
}

std::int64_t LocalManagedBufferFile::file_id() const noexcept {
  return historical_view_ ? historical_file_id_ : LocalBufferFile::file_id();
}

void LocalManagedBufferFile::set_file_id(std::int64_t value) noexcept {
  if (historical_view_)
    historical_file_id_ = value;
  else
    LocalBufferFile::set_file_id(value);
}

std::int32_t LocalManagedBufferFile::index_count() const noexcept {
  return historical_view_ ? historical_index_count_
                          : LocalBufferFile::index_count();
}

std::int32_t LocalManagedBufferFile::parameter(const std::string &name) const {
  if (!historical_view_)
    return LocalBufferFile::parameter(name);
  const auto found = historical_parameters_.find(name);
  if (found == historical_parameters_.end()) {
    throw std::out_of_range("managed historical parameter not found: " + name);
  }
  return found->second;
}

void LocalManagedBufferFile::set_parameter(std::string name,
                                           std::int32_t value) {
  if (historical_view_) {
    throw std::logic_error("historical managed file is read-only");
  }
  LocalBufferFile::set_parameter(std::move(name), value);
}

void LocalManagedBufferFile::clear_parameters() noexcept {
  if (historical_view_)
    historical_parameters_.clear();
  else
    LocalBufferFile::clear_parameters();
}

std::vector<std::string> LocalManagedBufferFile::parameter_names() const {
  if (!historical_view_)
    return LocalBufferFile::parameter_names();
  std::vector<std::string> result;
  result.reserve(historical_parameters_.size());
  for (const auto &[name, value] : historical_parameters_) {
    (void)value;
    result.push_back(name);
  }
  return result;
}

const std::vector<std::int32_t> &
LocalManagedBufferFile::free_indexes() const noexcept {
  return historical_view_ ? historical_free_indexes_
                          : LocalBufferFile::free_indexes();
}

void LocalManagedBufferFile::set_free_indexes(
    std::span<const std::int32_t> indexes) {
  if (historical_view_) {
    throw std::logic_error("historical managed file is read-only");
  }
  LocalBufferFile::set_free_indexes(indexes);
}

DataBuffer &LocalManagedBufferFile::get(DataBuffer &buffer,
                                        std::int32_t index) {
  if (index < 0 || index >= index_count()) {
    throw std::out_of_range("managed buffer index exceeds file");
  }
  if (version_handler_ && version_handler_->get_old_buffer(buffer, index)) {
    return buffer;
  }
  return LocalBufferFile::get(buffer, index);
}

void LocalManagedBufferFile::version_buffer_if_needed(std::int32_t index) {
  if (!version_output_ || !version_output_->accepts_old_buffer(index))
    return;
  DataBuffer old_buffer;
  get(old_buffer, index);
  version_output_->put_old_buffer(old_buffer, index);
}

void LocalManagedBufferFile::put(const DataBuffer &buffer, std::int32_t index) {
  version_buffer_if_needed(index);
  LocalBufferFile::put(buffer, index);
  if (change_map_)
    change_map_->buffer_changed(index, buffer.empty());
}

void LocalManagedBufferFile::put_free_block(std::int32_t index,
                                            std::int32_t next_free_index) {
  version_buffer_if_needed(index);
  LocalBufferFile::put_free_block(index, next_free_index);
  if (change_map_)
    change_map_->buffer_changed(index, true);
}

void LocalManagedBufferFile::notify_version_created() {
  if (!open_for_update_ || version_notified_ || !manager_)
    return;
  try {
    manager_->version_created(version_, comment_, checkin_id_);
  } catch (...) {
    // version_created may reject the newly committed version. Close this
    // object's read handle before container cleanup so Windows can remove it.
    try {
      LocalBufferFile::close();
    } catch (...) {
    }
    manager_->version_creation_failed(version_);
    throw;
  }
  version_notified_ = true;
}

void LocalManagedBufferFile::notify_update_ended() {
  if (!open_for_update_ || !update_end_required_ || update_notified_ ||
      update_transferred_ || !manager_)
    return;
  manager_->update_ended(checkin_id_);
  update_notified_ = true;
}

bool LocalManagedBufferFile::set_read_only() {
  if (!LocalBufferFile::flush())
    return false;
  if (version_output_) {
    version_output_->close();
    version_output_.reset();
  }
  if (change_map_) {
    change_map_->close();
    change_map_.reset();
  }
  if (!LocalBufferFile::set_read_only())
    return false;
  if (open_for_update_) {
    notify_version_created();
    start_presave();
  }
  return true;
}

void LocalManagedBufferFile::close() {
  std::scoped_lock lifecycle_lock(lifecycle_mutex_);
  discard_presave();
  if (closed())
    return;
  if (version_handler_) {
    version_handler_->close();
    version_handler_.reset();
  }
  const bool writable = !read_only();
  bool committed = false;
  try {
    committed = writable && LocalBufferFile::flush();
    if (committed && version_output_) {
      version_output_->close();
      version_output_.reset();
    }
    if (committed && change_map_) {
      change_map_->close();
      change_map_.reset();
    }
    LocalBufferFile::close();
    if (committed)
      notify_version_created();
  } catch (...) {
    const auto failure = std::current_exception();
    if (version_output_) {
      try {
        version_output_->abort();
      } catch (...) {
      }
      version_output_.reset();
    }
    if (change_map_) {
      change_map_->abort();
      change_map_.reset();
    }
    discard_save_files();
    try {
      if (!LocalBufferFile::closed()) {
        if (!LocalBufferFile::read_only() && !LocalBufferFile::delete_file()) {
          try {
            LocalBufferFile::close();
          } catch (...) {
          }
        } else if (!LocalBufferFile::closed()) {
          LocalBufferFile::close();
        }
      }
    } catch (...) {
      try {
        LocalBufferFile::close();
      } catch (...) {
      }
    }
    notify_update_ended();
    std::rethrow_exception(failure);
  }
  discard_save_files();
  notify_update_ended();
  open_for_update_ = false;
}

std::unique_ptr<InputBlockStream> LocalManagedBufferFile::input_block_stream() {
  if (version_handler_)
    return buffer_input_block_stream();
  return LocalBufferFile::input_block_stream();
}

std::unique_ptr<InputBlockStream> LocalManagedBufferFile::input_block_stream(
    std::span<const std::uint8_t> change_map_data) {
  return LocalBufferFile::input_block_stream(change_map_data);
}

std::unique_ptr<OutputBlockStream>
LocalManagedBufferFile::output_block_stream(std::int32_t block_count) {
  return make_output_block_stream(
      block_count,
      [this](std::int32_t block_index) {
        const auto buffer_index = block_index - 1;
        if (buffer_index >= 0)
          version_buffer_if_needed(buffer_index);
      },
      [this](std::int32_t block_index) {
        const auto buffer_index = block_index - 1;
        if (change_map_ && buffer_index >= 0) {
          change_map_->buffer_changed(buffer_index, false);
        }
      });
}

} // namespace llmghidra::db
