/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/checkout_manager.hpp"
#include "llmghidra/db/history_manager.hpp"
#include "llmghidra/db/item_property_file.hpp"
#include "llmghidra/db/private_database.hpp"
#include "llmghidra/db/versioned_database.hpp"

#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace llmghidra::db {

class LocalItemError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class LocalItemReadOnlyError : public LocalItemError {
public:
  using LocalItemError::LocalItemError;
};

class LocalItemInUseError : public LocalItemError {
public:
  using LocalItemError::LocalItemError;
};

struct LocalItemIdentity final {
  std::filesystem::path storage_directory;
  std::string storage_name;
  std::string parent_path;
  std::string name;
  bool persist_identity = false;
};

// Shared by every item in one project store.  The recursive mutex mirrors the
// Java LocalFileSystem synchronization object and keeps item moves, metadata,
// database callbacks, and filesystem index hooks in one serialization domain.
struct LocalFileSystemContext final {
  explicit LocalFileSystemContext(std::filesystem::path root_directory);

  std::filesystem::path root_directory;
  bool online = true;
  bool read_only = false;
  bool versioned = false;
  std::recursive_mutex mutex;

  std::function<void(std::string_view, std::string_view)> item_created;
  std::function<void(std::string_view, std::string_view)> item_changed;
  std::function<void(std::string_view, std::string_view)> item_deleted;
  std::function<void(const std::optional<std::string> &,
                     const std::optional<std::string> &)>
      file_id_changed;
  std::function<void(std::string_view, std::string_view,
                     const std::optional<std::string> &,
                     const std::optional<std::string> &)>
      item_file_id_changed;
};

class LocalFolderItem {
public:
  static constexpr std::int32_t unknown_file_type = -1;
  static constexpr std::int32_t database_file_type = 0;
  static constexpr std::int32_t data_file_type = 1;
  static constexpr std::int32_t link_file_type = 2;
  static constexpr std::int64_t default_checkout_id = -1;
  static constexpr std::int32_t latest_version = -1;

  static constexpr std::string_view file_type_property = "FILE_TYPE";
  static constexpr std::string_view read_only_property = "READ_ONLY";
  static constexpr std::string_view content_type_property = "CONTENT_TYPE";
  static constexpr std::string_view checkout_id_property = "CHECKOUT_ID";
  static constexpr std::string_view exclusive_checkout_property = "EXCLUSIVE";
  static constexpr std::string_view checkout_version_property =
      "CHECKOUT_VERSION";
  static constexpr std::string_view local_checkout_version_property =
      "LOCAL_CHECKOUT_VERSION";
  static constexpr std::string_view content_type_version_property =
      "CONTENT_TYPE_VERSION";
  static constexpr std::string_view data_directory_extension = ".db";
  static constexpr char hidden_directory_prefix = '~';

  virtual ~LocalFolderItem() = default;
  LocalFolderItem(const LocalFolderItem &) = delete;
  LocalFolderItem &operator=(const LocalFolderItem &) = delete;

  [[nodiscard]] std::string name() const;
  [[nodiscard]] std::string parent_path() const;
  [[nodiscard]] std::string logical_path() const;
  [[nodiscard]] std::string storage_name() const;
  [[nodiscard]] std::filesystem::path storage_directory() const;
  [[nodiscard]] std::filesystem::path data_directory() const;
  [[nodiscard]] std::optional<std::string> file_id() const;
  [[nodiscard]] std::string content_type() const;
  [[nodiscard]] bool item_read_only() const;
  [[nodiscard]] std::int32_t content_type_version() const;
  [[nodiscard]] bool checked_out() const;
  [[nodiscard]] bool checked_out_exclusive() const;
  [[nodiscard]] std::int64_t checkout_id() const;
  [[nodiscard]] std::int32_t checkout_version() const;
  [[nodiscard]] std::int32_t local_checkout_version() const;
  [[nodiscard]] bool versioned() const noexcept;

  void set_item_read_only(bool state);
  void set_content_type_version(std::int32_t version);
  [[nodiscard]] std::string reset_file_id();
  void set_checkout(std::int64_t checkout_id, bool exclusive,
                    std::int32_t checkout_version, std::int32_t local_version);
  virtual void clear_checkout();
  virtual void refresh();

  [[nodiscard]] static std::string
  escape_hidden_directory_prefixes(std::string_view storage_name);

protected:
  LocalFolderItem(std::shared_ptr<LocalFileSystemContext> context,
                  LocalItemIdentity identity, bool use_data_directory,
                  bool create);

  void configure_database_properties(std::string content_type,
                                     const std::optional<std::string> &file_id);
  void check_mutable() const;
  void check_not_in_use() const;
  void move_storage(LocalItemIdentity identity);
  void abort_create() noexcept;
  void delete_property_file();
  void fire_created() const;
  virtual void fire_changed() const;
  void fire_deleted(std::string parent, std::string name) const;
  [[nodiscard]] static std::string generate_file_id();

  [[nodiscard]] ItemPropertyFile &properties() noexcept;
  [[nodiscard]] const ItemPropertyFile &properties() const noexcept;
  [[nodiscard]] std::shared_ptr<LocalFileSystemContext> context() const;

private:
  static std::filesystem::path
  checked_storage_directory(const LocalFileSystemContext &context,
                            std::filesystem::path directory);

  std::shared_ptr<LocalFileSystemContext> context_;
  ItemPropertyFile properties_;
  bool use_data_directory_;
};

// Native private-project counterpart of LocalDatabaseItem.  Its metadata and
// path contract are shared with the upcoming versioned backend; no JVM or Java
// filesystem service participates in open/save/move/delete operations.
class LocalDatabaseItem final : public LocalFolderItem {
public:
  [[nodiscard]] static std::unique_ptr<LocalDatabaseItem>
  open_existing(std::shared_ptr<LocalFileSystemContext> context,
                LocalItemIdentity identity);
  [[nodiscard]] static std::unique_ptr<LocalDatabaseItem>
  create_empty(std::shared_ptr<LocalFileSystemContext> context,
               LocalItemIdentity identity, std::string content_type,
               std::optional<std::string> file_id = std::nullopt,
               std::int32_t buffer_size = BufferManager::default_buffer_size,
               std::string user = {},
               std::optional<std::string> project_path = std::nullopt,
               std::string comment = {});
  [[nodiscard]] static std::unique_ptr<LocalDatabaseItem>
  create_from(std::shared_ptr<LocalFileSystemContext> context,
              LocalItemIdentity identity, DatabaseHandle &source,
              std::string content_type, std::optional<std::string> file_id,
              bool reset_database_identity, std::string user = {},
              std::optional<std::string> project_path = std::nullopt,
              std::string comment = {});
  [[nodiscard]] static std::unique_ptr<LocalDatabaseItem> create_from_packed(
      std::shared_ptr<LocalFileSystemContext> context,
      LocalItemIdentity identity, const std::filesystem::path &packed_file,
      std::string content_type,
      std::optional<std::string> file_id = std::nullopt, std::string user = {},
      std::optional<std::string> project_path = std::nullopt,
      std::string comment = {});

  [[nodiscard]] std::uintmax_t length() const;
  [[nodiscard]] std::filesystem::file_time_type last_modified() const;
  [[nodiscard]] std::int32_t current_version() const;
  [[nodiscard]] std::int32_t minimum_version() const;
  [[nodiscard]] bool can_recover() const;

  [[nodiscard]] std::shared_ptr<LocalManagedBufferFile>
  open_buffer_file(std::int32_t version = latest_version,
                   std::int32_t minimum_change_data_version = -1);
  [[nodiscard]] std::shared_ptr<LocalManagedBufferFile>
  open_buffer_file_for_update(std::int64_t checkout_id = default_checkout_id);
  [[nodiscard]] std::unique_ptr<DatabaseHandle>
  open(std::int32_t version = latest_version,
       std::int32_t minimum_change_data_version = -1);
  [[nodiscard]] std::unique_ptr<DatabaseHandle>
  open_for_update(std::int64_t checkout_id = default_checkout_id);

  void output(const std::filesystem::path &output_file,
              std::int32_t version = latest_version) const;

  [[nodiscard]] std::optional<CheckoutStatus>
  checkout(CheckoutType type, std::string user,
           std::optional<std::string> project_path = std::nullopt);
  void terminate_checkout(std::int64_t checkout_id, bool notify = true);
  [[nodiscard]] std::optional<CheckoutStatus>
  checkout_status(std::int64_t checkout_id) const;
  [[nodiscard]] std::vector<CheckoutStatus> checkouts() const;
  [[nodiscard]] std::vector<ItemVersion> versions() const;
  void update_checkout_version(std::int64_t checkout_id, std::int32_t version,
                               std::string_view user);
  [[nodiscard]] bool has_checkouts() const;
  [[nodiscard]] bool checkin_active() const;
  void delete_minimum_version(std::string user);
  void delete_current_version(std::string user);

  void move_to(LocalItemIdentity identity);
  void delete_item(std::int32_t version = latest_version,
                   std::string user = {});
  void clear_checkout() override;
  void refresh() override;

private:
  struct VersionedItemState;
  struct CreateTag {};
  LocalDatabaseItem(std::shared_ptr<LocalFileSystemContext> context,
                    LocalItemIdentity identity, bool create);

  static void validate_content_type(std::string_view content_type);
  [[nodiscard]] bool uses_versioned_backend() const noexcept;
  [[nodiscard]] std::int64_t
  begin_initial_checkin(std::string user,
                        std::optional<std::string> project_path);
  void fire_changed() const override;

  std::unique_ptr<PrivateDatabase> private_database_;
  std::shared_ptr<VersionedItemState> versioned_state_;
  std::unique_ptr<VersionedDatabase> versioned_database_;
};

} // namespace llmghidra::db
