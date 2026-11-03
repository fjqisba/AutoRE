/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/local_database_item.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>
#include <system_error>

namespace llmghidra::db {
namespace {

bool is_within(const std::filesystem::path &root,
               const std::filesystem::path &candidate) {
  const auto relative = candidate.lexically_relative(root);
  if (relative.empty())
    return candidate == root;
  const auto first = *relative.begin();
  return first != ".." && !relative.is_absolute();
}

bool contains_symbolic_link(const std::filesystem::path &root,
                            const std::filesystem::path &candidate) {
  const auto relative = candidate.lexically_relative(root);
  auto current = root;
  for (const auto &component : relative) {
    current /= component;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(current, error);
    if (error == std::errc::no_such_file_or_directory) {
      break;
    }
    if (error) {
      throw std::filesystem::filesystem_error(
          "unable to inspect item storage path", current, error);
    }
    if (std::filesystem::is_symlink(status))
      return true;
  }
  return false;
}

bool blank(std::string_view value) {
  return std::all_of(value.begin(), value.end(), [](unsigned char character) {
    return character == ' ' || character == '\t' || character == '\r' ||
           character == '\n';
  });
}

} // namespace

struct LocalDatabaseItem::VersionedItemState final
    : public VersionedDatabaseListener {
  VersionedItemState(std::shared_ptr<LocalFileSystemContext> owner,
                     std::filesystem::path data_directory,
                     std::string parent_path, std::string item_name,
                     bool create)
      : context(std::move(owner)), directory(std::move(data_directory)),
        parent(std::move(parent_path)), name(std::move(item_name)),
        checkout_manager(std::make_unique<CheckoutManager>(directory, create)),
        history_manager(std::make_unique<HistoryManager>(directory, create)) {}

  [[nodiscard]] std::optional<CheckoutStatus>
  new_checkout(CheckoutType type, std::string user, std::int32_t version,
               std::optional<std::string> project_path) {
    std::scoped_lock lock(context->mutex);
    return checkout_manager->new_checkout(type, std::move(user), version,
                                          std::move(project_path));
  }

  void begin_checkin(std::int64_t checkout_id) {
    std::scoped_lock lock(context->mutex);
    if (checkin_id != LocalFolderItem::default_checkout_id) {
      const auto active = checkout_manager->checkout(checkin_id);
      throw LocalItemInUseError(active ? "another checkin is in progress by: " +
                                             active->user
                                       : "another checkin is in progress");
    }
    checkin_id = checkout_id;
  }

  void end_checkin(std::int64_t checkout_id) noexcept {
    std::scoped_lock lock(context->mutex);
    if (checkin_id == checkout_id) {
      checkin_id = LocalFolderItem::default_checkout_id;
    }
  }

  void terminate_checkout(std::int64_t checkout_id, bool notify) {
    std::scoped_lock lock(context->mutex);
    if (!checkout_manager->checkout(checkout_id)) {
      throw LocalItemError("invalid checkout ID");
    }
    if (checkin_id == checkout_id) {
      throw LocalItemInUseError("checkin is in progress");
    }
    checkout_manager->end_checkout(checkout_id);
    if (notify && context->item_changed)
      context->item_changed(parent, name);
  }

  void refresh() {
    std::scoped_lock lock(context->mutex);
    checkout_manager->refresh();
    history_manager->refresh();
  }

  void moved_to(std::filesystem::path new_directory, std::string new_parent,
                std::string new_name) {
    std::scoped_lock lock(context->mutex);
    auto next_checkout =
        std::make_unique<CheckoutManager>(new_directory, false);
    (void)next_checkout->all_checkouts();
    auto next_history = std::make_unique<HistoryManager>(new_directory, false);
    (void)next_history->versions();
    directory = std::move(new_directory);
    parent = std::move(new_parent);
    name = std::move(new_name);
    checkout_manager = std::move(next_checkout);
    history_manager = std::move(next_history);
  }

  void versions_changed(std::int32_t minimum_version,
                        std::int32_t current_version) override {
    std::scoped_lock lock(context->mutex);
    if (minimum_version == 0 && current_version == 0)
      return;
    if (history_manager->fix_history(minimum_version, current_version) &&
        context->item_changed) {
      context->item_changed(parent, name);
    }
  }

  [[nodiscard]] bool version_created(std::int32_t version,
                                     std::int64_t creation_time_millis,
                                     const std::string &comment,
                                     std::int64_t checkout_id) override {
    std::scoped_lock lock(context->mutex);
    const auto checkout = checkout_manager->checkout(checkout_id);
    if (!checkout || checkin_id != checkout_id)
      return false;
    if (!history_manager->version_added(version, creation_time_millis, comment,
                                        checkout->user)) {
      return false;
    }
    checkout_manager->update_checkout(checkout_id, version);
    if (version == 1) {
      if (context->item_created)
        context->item_created(parent, name);
    } else if (context->item_changed) {
      context->item_changed(parent, name);
    }
    return true;
  }

  void version_deleted(std::int32_t version) override {
    std::scoped_lock lock(context->mutex);
    (void)history_manager->version_deleted(version);
    if (context->item_changed)
      context->item_changed(parent, name);
  }

  [[nodiscard]] std::int32_t
  checkout_version(std::int64_t checkout_id) override {
    std::scoped_lock lock(context->mutex);
    const auto checkout = checkout_manager->checkout(checkout_id);
    return checkout ? checkout->version : -1;
  }

  void checkin_completed(std::int64_t checkout_id) override {
    end_checkin(checkout_id);
  }

  std::shared_ptr<LocalFileSystemContext> context;
  std::filesystem::path directory;
  std::string parent;
  std::string name;
  std::unique_ptr<CheckoutManager> checkout_manager;
  std::unique_ptr<HistoryManager> history_manager;
  std::int64_t checkin_id = LocalFolderItem::default_checkout_id;
  std::string delete_user;
};

LocalFileSystemContext::LocalFileSystemContext(
    std::filesystem::path root_directory_value)
    : root_directory(std::filesystem::absolute(std::move(root_directory_value))
                         .lexically_normal()) {
  if (root_directory.empty()) {
    throw std::invalid_argument("project store root is empty");
  }
  std::error_code error;
  auto canonical = std::filesystem::weakly_canonical(root_directory, error);
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to canonicalize project store root", root_directory, error);
  }
  root_directory = std::move(canonical);
}

std::filesystem::path LocalFolderItem::checked_storage_directory(
    const LocalFileSystemContext &context, std::filesystem::path directory) {
  if (directory.empty())
    throw std::invalid_argument("item storage is empty");
  directory =
      std::filesystem::absolute(std::move(directory)).lexically_normal();
  if (!is_within(context.root_directory, directory)) {
    throw std::invalid_argument("item storage is outside project root");
  }
  if (contains_symbolic_link(context.root_directory, directory)) {
    throw std::invalid_argument("item storage traverses a symbolic link");
  }
  return directory;
}

LocalFolderItem::LocalFolderItem(
    std::shared_ptr<LocalFileSystemContext> context, LocalItemIdentity identity,
    bool use_data_directory, bool create)
    : context_(std::move(context)),
      properties_(checked_storage_directory(
                      context_ ? *context_
                               : throw std::invalid_argument(
                                     "local filesystem context is required"),
                      std::move(identity.storage_directory)),
                  std::move(identity.storage_name),
                  std::move(identity.parent_path), std::move(identity.name),
                  identity.persist_identity),
      use_data_directory_(use_data_directory) {
  std::scoped_lock lock(context_->mutex);
  if (create) {
    check_mutable();
    if (properties_.exists()) {
      throw DuplicatePropertyFileError("item property file already exists");
    }
    bool data_created = false;
    try {
      if (use_data_directory_) {
        const auto directory = data_directory();
        if (std::filesystem::exists(directory)) {
          throw LocalItemError("item data directory already exists");
        }
        std::error_code error;
        if (!std::filesystem::create_directory(directory, error) || error) {
          throw std::filesystem::filesystem_error(
              "unable to create item data directory", directory, error);
        }
        data_created = true;
      }
      properties_.write_state();
    } catch (...) {
      if (data_created) {
        std::error_code ignored;
        std::filesystem::remove_all(data_directory(), ignored);
      }
      throw;
    }
  } else if (!properties_.exists() ||
             (use_data_directory_ &&
              !std::filesystem::is_directory(data_directory()))) {
    throw LocalItemError("local item is missing property or data storage");
  } else if (use_data_directory_) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(data_directory(), error);
    if (error || std::filesystem::is_symlink(status)) {
      throw LocalItemError(
          "local item data storage is inaccessible or symbolic link");
    }
  }
}

std::string LocalFolderItem::name() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.name();
}

std::string LocalFolderItem::parent_path() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.parent_path();
}

std::string LocalFolderItem::logical_path() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.logical_path();
}

std::string LocalFolderItem::storage_name() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.storage_name();
}

std::filesystem::path LocalFolderItem::storage_directory() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.parent_storage_directory();
}

std::string LocalFolderItem::escape_hidden_directory_prefixes(
    std::string_view storage_name) {
  std::size_t count = 0;
  while (count < storage_name.size() &&
         storage_name[count] == hidden_directory_prefix) {
    ++count;
  }
  return std::string(count, hidden_directory_prefix) +
         std::string(storage_name);
}

std::filesystem::path LocalFolderItem::data_directory() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.parent_storage_directory() /
         (std::string(1, hidden_directory_prefix) +
          escape_hidden_directory_prefixes(properties_.storage_name()) +
          std::string(data_directory_extension));
}

std::optional<std::string> LocalFolderItem::file_id() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.file_id();
}

std::string LocalFolderItem::content_type() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.get_string(content_type_property, "Unknown");
}

bool LocalFolderItem::item_read_only() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.get_boolean(read_only_property, false);
}

std::int32_t LocalFolderItem::content_type_version() const {
  std::scoped_lock lock(context_->mutex);
  return properties_.get_int(content_type_version_property, 1);
}

bool LocalFolderItem::checked_out() const {
  if (context_->versioned) {
    throw LocalItemError("checked_out is not applicable to versioned item");
  }
  return checkout_id() != default_checkout_id;
}

bool LocalFolderItem::checked_out_exclusive() const {
  std::scoped_lock lock(context_->mutex);
  if (context_->versioned) {
    throw LocalItemError(
        "checked_out_exclusive is not applicable to versioned item");
  }
  return properties_.get_long(checkout_id_property, default_checkout_id) !=
             default_checkout_id &&
         properties_.get_boolean(exclusive_checkout_property, false);
}

std::int64_t LocalFolderItem::checkout_id() const {
  std::scoped_lock lock(context_->mutex);
  if (context_->versioned) {
    throw LocalItemError("checkout_id is not applicable to versioned item");
  }
  return properties_.get_long(checkout_id_property, default_checkout_id);
}

std::int32_t LocalFolderItem::checkout_version() const {
  std::scoped_lock lock(context_->mutex);
  if (context_->versioned) {
    throw LocalItemError(
        "checkout_version is not applicable to versioned item");
  }
  return properties_.get_int(checkout_version_property, -1);
}

std::int32_t LocalFolderItem::local_checkout_version() const {
  std::scoped_lock lock(context_->mutex);
  if (context_->versioned) {
    throw LocalItemError(
        "local_checkout_version is not applicable to versioned item");
  }
  return properties_.get_int(local_checkout_version_property, -1);
}

bool LocalFolderItem::versioned() const noexcept { return context_->versioned; }

void LocalFolderItem::check_mutable() const {
  if (!context_->online) {
    throw LocalItemError("local filesystem is disposed");
  }
  if (context_->read_only) {
    throw LocalItemReadOnlyError("local filesystem is read-only");
  }
}

void LocalFolderItem::check_not_in_use() const {
  if (context_->versioned)
    return;
  if (checkout_id() != default_checkout_id) {
    throw LocalItemInUseError("local item is checked out");
  }
}

void LocalFolderItem::set_item_read_only(bool state) {
  std::scoped_lock lock(context_->mutex);
  check_mutable();
  if (context_->versioned) {
    throw LocalItemError("versioned item does not support read-only property");
  }
  properties_.put_boolean(std::string(read_only_property), state);
  properties_.write_state();
  fire_changed();
}

void LocalFolderItem::set_content_type_version(std::int32_t version) {
  std::scoped_lock lock(context_->mutex);
  check_mutable();
  properties_.put_int(std::string(content_type_version_property), version);
  properties_.write_state();
  fire_changed();
}

std::string LocalFolderItem::generate_file_id() {
  std::array<std::uint64_t, 2> words{};
  std::random_device random;
  for (auto &word : words) {
    word = (static_cast<std::uint64_t>(random()) << 32) ^ random() ^
           static_cast<std::uint64_t>(std::chrono::high_resolution_clock::now()
                                          .time_since_epoch()
                                          .count());
  }
  std::ostringstream result;
  result << std::hex << std::setfill('0');
  for (const auto word : words)
    result << std::setw(16) << word;
  return result.str();
}

std::string LocalFolderItem::reset_file_id() {
  std::scoped_lock lock(context_->mutex);
  check_mutable();
  const auto previous = properties_.file_id();
  const auto next = generate_file_id();
  properties_.set_file_id(next);
  properties_.write_state();
  if (context_->file_id_changed)
    context_->file_id_changed(previous, next);
  if (context_->item_file_id_changed)
    context_->item_file_id_changed(properties_.parent_path(), properties_.name(),
                                   previous, next);
  return next;
}

void LocalFolderItem::set_checkout(std::int64_t id, bool exclusive,
                                   std::int32_t version,
                                   std::int32_t local_version) {
  std::scoped_lock lock(context_->mutex);
  check_mutable();
  if (context_->versioned) {
    throw LocalItemError("set_checkout is not applicable to versioned item");
  }
  if (id <= 0 || version <= 0 || local_version < 0) {
    throw std::invalid_argument("invalid local checkout metadata");
  }
  properties_.put_long(std::string(checkout_id_property), id);
  properties_.put_boolean(std::string(exclusive_checkout_property), exclusive);
  properties_.put_int(std::string(checkout_version_property), version);
  properties_.put_int(std::string(local_checkout_version_property),
                      local_version);
  properties_.write_state();
  fire_changed();
}

void LocalFolderItem::clear_checkout() {
  std::scoped_lock lock(context_->mutex);
  check_mutable();
  if (context_->versioned) {
    throw LocalItemError("clear_checkout is not applicable to versioned item");
  }
  properties_.put_long(std::string(checkout_id_property), default_checkout_id);
  properties_.put_boolean(std::string(exclusive_checkout_property), false);
  properties_.put_int(std::string(checkout_version_property), -1);
  properties_.put_int(std::string(local_checkout_version_property), -1);
  properties_.write_state();
  fire_changed();
}

void LocalFolderItem::refresh() {
  std::scoped_lock lock(context_->mutex);
  if (!properties_.exists() ||
      (use_data_directory_ &&
       !std::filesystem::is_directory(data_directory()))) {
    throw LocalItemError("local item no longer exists");
  }
  properties_.read_state();
}

void LocalFolderItem::configure_database_properties(
    std::string content_type, const std::optional<std::string> &file_id) {
  properties_.put_int(std::string(file_type_property), database_file_type);
  properties_.put_boolean(std::string(read_only_property), false);
  properties_.put_string(std::string(content_type_property),
                         std::move(content_type));
  properties_.set_file_id(file_id);
  properties_.write_state();
}

void LocalFolderItem::move_storage(LocalItemIdentity identity) {
  std::scoped_lock lock(context_->mutex);
  check_mutable();
  check_not_in_use();
  identity.storage_directory = checked_storage_directory(
      *context_, std::move(identity.storage_directory));
  const auto old_directory = properties_.parent_storage_directory();
  const auto old_storage_name = properties_.storage_name();
  const auto old_parent = properties_.parent_path();
  const auto old_name = properties_.name();
  const auto old_data = data_directory();

  properties_.move_to(identity.storage_directory, identity.storage_name,
                      identity.parent_path, identity.name);
  bool data_moved = false;
  try {
    const auto new_data = data_directory();
    if (use_data_directory_ && old_data != new_data) {
      if (std::filesystem::exists(new_data)) {
        throw DuplicatePropertyFileError(
            "item destination data directory already exists");
      }
      std::error_code error;
      std::filesystem::rename(old_data, new_data, error);
      if (error) {
        throw std::filesystem::filesystem_error("item data move failed",
                                                old_data, new_data, error);
      }
      data_moved = true;
    }
  } catch (...) {
    try {
      properties_.move_to(old_directory, old_storage_name, old_parent,
                          old_name);
    } catch (...) {
    }
    if (data_moved) {
      std::error_code ignored;
      std::filesystem::rename(data_directory(), old_data, ignored);
    }
    throw;
  }
}

void LocalFolderItem::abort_create() noexcept {
  std::scoped_lock lock(context_->mutex);
  try {
    properties_.delete_file();
  } catch (...) {
  }
  if (use_data_directory_) {
    std::error_code ignored;
    const auto directory = data_directory();
    if (is_within(context_->root_directory, directory) &&
        directory != context_->root_directory) {
      std::filesystem::remove_all(directory, ignored);
    }
  }
}

void LocalFolderItem::delete_property_file() { properties_.delete_file(); }

void LocalFolderItem::fire_created() const {
  if (context_->item_created) {
    context_->item_created(properties_.parent_path(), properties_.name());
  }
}

void LocalFolderItem::fire_changed() const {
  if (context_->item_changed) {
    context_->item_changed(properties_.parent_path(), properties_.name());
  }
}

void LocalFolderItem::fire_deleted(std::string parent,
                                   std::string name_value) const {
  if (context_->item_deleted) {
    context_->item_deleted(parent, name_value);
  }
}

ItemPropertyFile &LocalFolderItem::properties() noexcept { return properties_; }

const ItemPropertyFile &LocalFolderItem::properties() const noexcept {
  return properties_;
}

std::shared_ptr<LocalFileSystemContext> LocalFolderItem::context() const {
  return context_;
}

LocalDatabaseItem::LocalDatabaseItem(
    std::shared_ptr<LocalFileSystemContext> context, LocalItemIdentity identity,
    bool create)
    : LocalFolderItem(std::move(context), std::move(identity), true, create) {
  if (versioned()) {
    try {
      versioned_state_ = std::make_shared<VersionedItemState>(
          this->context(), data_directory(), parent_path(), name(), create);
    } catch (...) {
      // The base constructor has already published the property file and data
      // directory.  A checkout/history manager failure during a new-item
      // construction must not leave that half-created storage behind.  Never
      // remove an existing item merely because its metadata cannot be opened.
      if (create)
        abort_create();
      throw;
    }
  }
}

void LocalDatabaseItem::validate_content_type(std::string_view content_type) {
  if (content_type.empty() || blank(content_type)) {
    throw std::invalid_argument("database item content type is empty");
  }
}

bool LocalDatabaseItem::uses_versioned_backend() const noexcept {
  return versioned_state_ != nullptr;
}

std::int64_t LocalDatabaseItem::begin_initial_checkin(
    std::string user, std::optional<std::string> project_path) {
  if (!uses_versioned_backend()) {
    throw LocalItemError("initial checkin requires a versioned item");
  }
  if (user.empty()) {
    throw std::invalid_argument("versioned item user is empty");
  }
  const auto checkout = versioned_state_->new_checkout(
      CheckoutType::normal, std::move(user), 0, std::move(project_path));
  if (!checkout)
    throw LocalItemInUseError("initial checkout was denied");
  versioned_state_->begin_checkin(checkout->checkout_id);
  return checkout->checkout_id;
}

std::unique_ptr<LocalDatabaseItem> LocalDatabaseItem::open_existing(
    std::shared_ptr<LocalFileSystemContext> context,
    LocalItemIdentity identity) {
  auto item = std::unique_ptr<LocalDatabaseItem>(
      new LocalDatabaseItem(std::move(context), std::move(identity), false));
  if (item->properties().get_int(file_type_property, unknown_file_type) !=
      database_file_type) {
    throw LocalItemError("local item is not a database");
  }
  item->validate_content_type(item->content_type());
  if (item->uses_versioned_backend()) {
    item->versioned_database_ = std::make_unique<VersionedDatabase>(
        item->data_directory(), item->versioned_state_);
  } else {
    item->private_database_ =
        std::make_unique<PrivateDatabase>(item->data_directory());
    item->private_database_->set_checkout_copy(item->checked_out());
  }
  return item;
}

std::unique_ptr<LocalDatabaseItem> LocalDatabaseItem::create_empty(
    std::shared_ptr<LocalFileSystemContext> context, LocalItemIdentity identity,
    std::string content_type, std::optional<std::string> file_id,
    std::int32_t buffer_size, std::string user,
    std::optional<std::string> project_path, std::string comment) {
  validate_content_type(content_type);
  auto item = std::unique_ptr<LocalDatabaseItem>(
      new LocalDatabaseItem(std::move(context), std::move(identity), true));
  std::int64_t checkout_id = default_checkout_id;
  try {
    item->configure_database_properties(std::move(content_type), file_id);
    if (item->uses_versioned_backend()) {
      checkout_id =
          item->begin_initial_checkin(std::move(user), std::move(project_path));
      item->versioned_database_ = VersionedDatabase::create(
          item->data_directory(), item->versioned_state_, checkout_id,
          buffer_size, std::move(comment));
      item->versioned_state_->terminate_checkout(checkout_id, false);
    } else {
      item->private_database_ =
          PrivateDatabase::create(item->data_directory(), buffer_size);
      item->fire_created();
    }
    return item;
  } catch (...) {
    if (item->versioned_state_ && checkout_id != default_checkout_id) {
      item->versioned_state_->end_checkin(checkout_id);
      try {
        item->versioned_state_->checkout_manager->end_checkout(checkout_id);
      } catch (...) {
      }
    }
    item->versioned_database_.reset();
    item->abort_create();
    throw;
  }
}

std::unique_ptr<LocalDatabaseItem> LocalDatabaseItem::create_from(
    std::shared_ptr<LocalFileSystemContext> context, LocalItemIdentity identity,
    DatabaseHandle &source, std::string content_type,
    std::optional<std::string> file_id, bool reset_database_identity,
    std::string user, std::optional<std::string> project_path,
    std::string comment) {
  validate_content_type(content_type);
  auto item = std::unique_ptr<LocalDatabaseItem>(
      new LocalDatabaseItem(std::move(context), std::move(identity), true));
  std::int64_t checkout_id = default_checkout_id;
  try {
    item->configure_database_properties(std::move(content_type), file_id);
    if (item->uses_versioned_backend()) {
      checkout_id =
          item->begin_initial_checkin(std::move(user), std::move(project_path));
      item->versioned_database_ = VersionedDatabase::create_from(
          item->data_directory(), source, item->versioned_state_, checkout_id,
          std::move(comment));
      item->versioned_state_->terminate_checkout(checkout_id, false);
    } else {
      item->private_database_ = PrivateDatabase::create_from(
          item->data_directory(), source, reset_database_identity);
      item->fire_created();
    }
    return item;
  } catch (...) {
    if (item->versioned_state_ && checkout_id != default_checkout_id) {
      item->versioned_state_->end_checkin(checkout_id);
      try {
        item->versioned_state_->checkout_manager->end_checkout(checkout_id);
      } catch (...) {
      }
    }
    item->versioned_database_.reset();
    item->abort_create();
    throw;
  }
}

std::unique_ptr<LocalDatabaseItem> LocalDatabaseItem::create_from_packed(
    std::shared_ptr<LocalFileSystemContext> context, LocalItemIdentity identity,
    const std::filesystem::path &packed_file, std::string content_type,
    std::optional<std::string> file_id, std::string user,
    std::optional<std::string> project_path, std::string comment) {
  validate_content_type(content_type);
  auto item = std::unique_ptr<LocalDatabaseItem>(
      new LocalDatabaseItem(std::move(context), std::move(identity), true));
  std::int64_t checkout_id = default_checkout_id;
  try {
    if (!file_id)
      file_id = generate_file_id();
    item->configure_database_properties(std::move(content_type), file_id);
    if (item->uses_versioned_backend()) {
      checkout_id =
          item->begin_initial_checkin(std::move(user), std::move(project_path));
      item->versioned_database_ = VersionedDatabase::create_from_packed(
          item->data_directory(), packed_file, item->versioned_state_,
          checkout_id, std::move(comment));
      item->versioned_state_->terminate_checkout(checkout_id, false);
    } else {
      item->private_database_ = PrivateDatabase::create_from_packed(
          item->data_directory(), packed_file, true);
      item->fire_created();
    }
    return item;
  } catch (...) {
    if (item->versioned_state_ && checkout_id != default_checkout_id) {
      item->versioned_state_->end_checkin(checkout_id);
      try {
        item->versioned_state_->checkout_manager->end_checkout(checkout_id);
      } catch (...) {
      }
    }
    item->versioned_database_.reset();
    item->abort_create();
    throw;
  }
}

std::uintmax_t LocalDatabaseItem::length() const {
  return uses_versioned_backend() ? versioned_database_->length()
                                  : private_database_->length();
}

std::filesystem::file_time_type LocalDatabaseItem::last_modified() const {
  return uses_versioned_backend() ? versioned_database_->last_modified()
                                  : private_database_->last_modified();
}

std::int32_t LocalDatabaseItem::current_version() const {
  return uses_versioned_backend() ? versioned_database_->current_version()
                                  : private_database_->current_version();
}

std::int32_t LocalDatabaseItem::minimum_version() const {
  return uses_versioned_backend() ? versioned_database_->minimum_version()
                                  : private_database_->minimum_version();
}

bool LocalDatabaseItem::can_recover() const {
  return !uses_versioned_backend() && private_database_->can_recover();
}

std::shared_ptr<LocalManagedBufferFile>
LocalDatabaseItem::open_buffer_file(std::int32_t version,
                                    std::int32_t minimum_change_data_version) {
  if (uses_versioned_backend()) {
    return versioned_database_->open_buffer_file(version,
                                                 minimum_change_data_version);
  }
  if (version != latest_version || minimum_change_data_version != -1) {
    throw std::invalid_argument(
        "only the latest private database version may be opened");
  }
  return private_database_->open_buffer_file();
}

std::shared_ptr<LocalManagedBufferFile>
LocalDatabaseItem::open_buffer_file_for_update(std::int64_t id) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (uses_versioned_backend()) {
    if (id == default_checkout_id) {
      throw std::invalid_argument(
          "versioned database update requires a checkout ID");
    }
    versioned_state_->begin_checkin(id);
    try {
      return versioned_database_->open_buffer_file_for_update(id);
    } catch (...) {
      versioned_state_->end_checkin(id);
      throw;
    }
  }
  if (id != default_checkout_id) {
    throw std::invalid_argument(
        "private database update does not accept a checkout ID");
  }
  return private_database_->open_buffer_file_for_update();
}

std::unique_ptr<DatabaseHandle>
LocalDatabaseItem::open(std::int32_t version,
                        std::int32_t minimum_change_data_version) {
  if (uses_versioned_backend()) {
    return versioned_database_->open(version, minimum_change_data_version);
  }
  if (version != latest_version || minimum_change_data_version != -1) {
    throw std::invalid_argument(
        "only the latest private database version may be opened");
  }
  return private_database_->open();
}

std::unique_ptr<DatabaseHandle>
LocalDatabaseItem::open_for_update(std::int64_t id) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (uses_versioned_backend()) {
    if (id == default_checkout_id) {
      throw std::invalid_argument(
          "versioned database update requires a checkout ID");
    }
    versioned_state_->begin_checkin(id);
    try {
      return versioned_database_->open_for_update(id);
    } catch (...) {
      versioned_state_->end_checkin(id);
      throw;
    }
  }
  if (id != default_checkout_id) {
    throw std::invalid_argument(
        "private database update does not accept a checkout ID");
  }
  return private_database_->open_for_update();
}

void LocalDatabaseItem::output(const std::filesystem::path &output_file,
                               std::int32_t version) const {
  const auto type = content_type();
  if (type == "Unknown")
    throw LocalItemError("unknown database content type");
  if (uses_versioned_backend()) {
    versioned_database_->output(version, output_file, name(),
                                database_file_type, type);
  } else {
    if (version != latest_version) {
      throw std::invalid_argument(
          "only the latest private database version may be output");
    }
    private_database_->output(output_file, name(), database_file_type, type);
  }
}

std::optional<CheckoutStatus>
LocalDatabaseItem::checkout(CheckoutType type, std::string user,
                            std::optional<std::string> project_path) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (!uses_versioned_backend()) {
    throw LocalItemError("non-versioned item does not support checkout");
  }
  auto status = versioned_state_->checkout_manager->new_checkout(
      type, std::move(user), versioned_database_->current_version(),
      std::move(project_path));
  if (type != CheckoutType::normal && status && !file_id()) {
    (void)reset_file_id();
  }
  return status;
}

void LocalDatabaseItem::terminate_checkout(std::int64_t checkout_id,
                                           bool notify) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (!uses_versioned_backend()) {
    throw LocalItemError("non-versioned item does not support checkout");
  }
  versioned_state_->terminate_checkout(checkout_id, notify);
}

std::optional<CheckoutStatus>
LocalDatabaseItem::checkout_status(std::int64_t checkout_id) const {
  std::scoped_lock lock(context()->mutex);
  if (!uses_versioned_backend()) {
    throw LocalItemError("non-versioned item does not support checkout");
  }
  return versioned_state_->checkout_manager->checkout(checkout_id);
}

std::vector<CheckoutStatus> LocalDatabaseItem::checkouts() const {
  std::scoped_lock lock(context()->mutex);
  if (!uses_versioned_backend()) {
    throw LocalItemError("non-versioned item does not support checkout");
  }
  return versioned_state_->checkout_manager->all_checkouts();
}

std::vector<ItemVersion> LocalDatabaseItem::versions() const {
  std::scoped_lock lock(context()->mutex);
  if (!uses_versioned_backend()) {
    throw LocalItemError("non-versioned item does not support history");
  }
  return versioned_state_->history_manager->versions();
}

void LocalDatabaseItem::update_checkout_version(std::int64_t checkout_id,
                                                std::int32_t version,
                                                std::string_view user) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (!uses_versioned_backend()) {
    throw LocalItemError("checkout-version update requires a versioned item");
  }
  const auto status = versioned_state_->checkout_manager->checkout(checkout_id);
  if (!status || status->user != user) {
    throw LocalItemError("checkout not found");
  }
  versioned_state_->checkout_manager->update_checkout(checkout_id, version);
}

bool LocalDatabaseItem::has_checkouts() const {
  std::scoped_lock lock(context()->mutex);
  return uses_versioned_backend() &&
         versioned_state_->checkout_manager->is_checked_out();
}

bool LocalDatabaseItem::checkin_active() const {
  std::scoped_lock lock(context()->mutex);
  return uses_versioned_backend() &&
         versioned_state_->checkin_id != default_checkout_id;
}

void LocalDatabaseItem::delete_minimum_version(std::string user) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (!uses_versioned_backend()) {
    throw LocalItemError("version deletion requires a versioned item");
  }
  const auto version = versioned_database_->minimum_version();
  if (versioned_state_->checkout_manager->is_checked_out(version)) {
    throw LocalItemInUseError("minimum version is checked out");
  }
  if (versioned_state_->checkin_id != default_checkout_id) {
    throw LocalItemInUseError("checkin is in progress");
  }
  versioned_state_->delete_user = std::move(user);
  versioned_database_->delete_minimum_version();
}

void LocalDatabaseItem::delete_current_version(std::string user) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (!uses_versioned_backend()) {
    throw LocalItemError("version deletion requires a versioned item");
  }
  const auto version = versioned_database_->current_version();
  if (versioned_state_->checkout_manager->is_checked_out(version)) {
    throw LocalItemInUseError("current version is checked out");
  }
  if (versioned_state_->checkin_id != default_checkout_id) {
    throw LocalItemInUseError("checkin is in progress");
  }
  versioned_state_->delete_user = std::move(user);
  versioned_database_->delete_current_version();
}

void LocalDatabaseItem::move_to(LocalItemIdentity identity) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (uses_versioned_backend()) {
    if (versioned_state_->checkout_manager->is_checked_out()) {
      throw LocalItemInUseError("versioned item is checked out");
    }
    if (versioned_state_->checkin_id != default_checkout_id ||
        versioned_database_->update_open()) {
      throw LocalItemInUseError("checkin is in progress");
    }
  }
  LocalItemIdentity old_identity{storage_directory(), storage_name(),
                                 parent_path(), name()};
  const auto old_data = data_directory();
  move_storage(std::move(identity));
  try {
    const auto new_data = data_directory();
    if (uses_versioned_backend()) {
      versioned_database_->moved_to(new_data);
      versioned_state_->moved_to(new_data, parent_path(), name());
    } else {
      private_database_->move_to(new_data);
    }
  } catch (...) {
    try {
      move_storage(std::move(old_identity));
      if (uses_versioned_backend()) {
        versioned_database_->moved_to(old_data);
        versioned_state_->moved_to(old_data, parent_path(), name());
      } else {
        private_database_->move_to(old_data);
      }
    } catch (...) {
    }
    throw;
  }
  fire_changed();
}

void LocalDatabaseItem::delete_item(std::int32_t version, std::string user) {
  std::scoped_lock lock(context()->mutex);
  check_mutable();
  if (!uses_versioned_backend() && version != latest_version) {
    throw std::invalid_argument(
        "private item deletion requires latest/all version");
  }

  if (uses_versioned_backend() && version != latest_version) {
    const auto minimum = versioned_database_->minimum_version();
    const auto current = versioned_database_->current_version();
    if (version != minimum && version != current) {
      throw LocalItemError("only the oldest or latest version may be deleted");
    }
    if (versioned_state_->checkout_manager->is_checked_out(version)) {
      throw LocalItemInUseError("database version is checked out");
    }
    if (versioned_state_->checkin_id != default_checkout_id) {
      throw LocalItemInUseError("checkin is in progress");
    }
    if (minimum != current) {
      if (version == minimum)
        delete_minimum_version(std::move(user));
      else
        delete_current_version(std::move(user));
      return;
    }
  }

  if (uses_versioned_backend()) {
    if (versioned_state_->checkout_manager->is_checked_out()) {
      throw LocalItemInUseError("versioned item is checked out");
    }
    if (versioned_state_->checkin_id != default_checkout_id ||
        versioned_database_->update_open()) {
      throw LocalItemInUseError("checkin is in progress");
    }
    versioned_state_->delete_user = std::move(user);
  } else {
    check_not_in_use();
  }

  const auto old_parent = parent_path();
  const auto old_name = name();
  const auto data = data_directory();
  auto quarantine = data;
  quarantine += ".delete";
  if (std::filesystem::exists(quarantine)) {
    throw LocalItemInUseError("item delete quarantine already exists");
  }
  std::error_code error;
  std::filesystem::rename(data, quarantine, error);
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to isolate item data for deletion", data, quarantine, error);
  }
  try {
    if (uses_versioned_backend()) {
      versioned_database_->moved_to(quarantine);
      versioned_state_->moved_to(quarantine, old_parent, old_name);
    } else {
      private_database_->move_to(quarantine);
    }
    delete_property_file();
  } catch (...) {
    std::error_code ignored;
    std::filesystem::rename(quarantine, data, ignored);
    try {
      if (uses_versioned_backend()) {
        versioned_database_->moved_to(data);
        versioned_state_->moved_to(data, old_parent, old_name);
      } else {
        private_database_->move_to(data);
      }
    } catch (...) {
    }
    throw;
  }
  try {
    if (uses_versioned_backend()) {
      versioned_database_->delete_database();
    } else {
      private_database_->delete_database();
    }
  } catch (...) {
    if (std::filesystem::is_directory(quarantine)) {
      std::error_code ignored;
      std::filesystem::rename(quarantine, data, ignored);
      if (!ignored) {
        try {
          properties().write_state();
          if (uses_versioned_backend()) {
            versioned_database_->moved_to(data);
            versioned_state_->moved_to(data, old_parent, old_name);
          } else {
            private_database_->move_to(data);
          }
        } catch (...) {
        }
      }
    }
    throw;
  }
  fire_deleted(old_parent, old_name);
}

void LocalDatabaseItem::clear_checkout() {
  std::scoped_lock lock(context()->mutex);
  if (uses_versioned_backend()) {
    throw LocalItemError("clear_checkout is not applicable to versioned item");
  }
  private_database_->clear_checkout_changes();
  LocalFolderItem::clear_checkout();
  private_database_->set_checkout_copy(false);
}

void LocalDatabaseItem::fire_changed() const {
  if (private_database_) {
    private_database_->set_checkout_copy(checked_out());
  }
  LocalFolderItem::fire_changed();
}

void LocalDatabaseItem::refresh() {
  std::scoped_lock lock(context()->mutex);
  LocalFolderItem::refresh();
  if (uses_versioned_backend()) {
    versioned_state_->refresh();
    versioned_database_->refresh();
  } else {
    private_database_->refresh();
    private_database_->set_checkout_copy(checked_out());
  }
}

} // namespace llmghidra::db
