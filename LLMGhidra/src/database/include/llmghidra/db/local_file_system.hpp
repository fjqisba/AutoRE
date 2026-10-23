/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/local_database_item.hpp"
#include "llmghidra/task_control.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace llmghidra::db {

class LocalFileSystemError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class LocalFileSystemNotFoundError : public LocalFileSystemError {
public:
  using LocalFileSystemError::LocalFileSystemError;
};

class LocalFileSystemDuplicateError : public LocalFileSystemError {
public:
  using LocalFileSystemError::LocalFileSystemError;
};

class LocalFileSystemInvalidNameError : public LocalFileSystemError {
public:
  using LocalFileSystemError::LocalFileSystemError;
};

class LocalFileSystemIndexError : public LocalFileSystemError {
public:
  using LocalFileSystemError::LocalFileSystemError;
};

enum class LocalFileSystemSchema {
  mangled,
  indexed_v0,
  indexed_v1,
};

enum class LocalFileSystemEventKind {
  folder_created,
  folder_deleted,
  folder_moved,
  folder_renamed,
  item_created,
  item_changed,
  item_deleted,
  item_moved,
  item_renamed,
  file_id_changed,
};

struct LocalFileSystemEvent final {
  LocalFileSystemEventKind kind;
  std::string parent_path;
  std::string name;
  std::string new_parent_path;
  std::string new_name;
};

// Pure C++ counterpart of Ghidra's LocalFileSystem family. New projects use
// Indexed V1. Existing Indexed V0 and legacy mangled projects remain readable
// and writable in their original on-disk schema, matching the fixed upstream.
class LocalFileSystem final {
public:
  using EventSink = std::function<void(const LocalFileSystemEvent &)>;

  [[nodiscard]] static std::unique_ptr<LocalFileSystem>
  create(std::filesystem::path root, bool versioned, bool read_only = false);
  [[nodiscard]] static std::unique_ptr<LocalFileSystem>
  open(std::filesystem::path root, bool versioned, bool read_only = false,
       bool repair_index = true, const TaskContext &task = {});

  ~LocalFileSystem();
  LocalFileSystem(const LocalFileSystem &) = delete;
  LocalFileSystem &operator=(const LocalFileSystem &) = delete;

  [[nodiscard]] const std::filesystem::path &root() const noexcept;
  [[nodiscard]] LocalFileSystemSchema schema() const noexcept;
  [[nodiscard]] bool versioned() const noexcept;
  [[nodiscard]] bool read_only() const noexcept;
  [[nodiscard]] bool online() const noexcept;

  void set_event_sink(EventSink sink);
  void dispose() noexcept;
  void refresh();
  void flush_index();

  [[nodiscard]] bool folder_exists(std::string_view path) const;
  [[nodiscard]] bool item_exists(std::string_view parent,
                                 std::string_view name) const;
  [[nodiscard]] std::vector<std::string>
  folder_names(std::string_view path) const;
  [[nodiscard]] std::vector<std::string>
  item_names(std::string_view path, bool include_hidden = false) const;
  [[nodiscard]] std::size_t item_count() const;

  void create_folder(std::string parent, std::string name);
  void delete_folder(std::string path);
  void move_folder(std::string parent, std::string name,
                   std::string new_parent);
  void rename_folder(std::string parent, std::string name,
                     std::string new_name);

  [[nodiscard]] std::unique_ptr<LocalDatabaseItem> item(std::string parent,
                                                        std::string name) const;
  [[nodiscard]] std::unique_ptr<LocalDatabaseItem>
  item_by_file_id(std::string_view file_id) const;

  [[nodiscard]] std::unique_ptr<LocalDatabaseItem>
  create_database(std::string parent, std::string name,
                  std::string content_type,
                  std::optional<std::string> file_id = std::nullopt,
                  std::int32_t buffer_size = BufferManager::default_buffer_size,
                  std::string user = {},
                  std::optional<std::string> project_path = std::nullopt,
                  std::string comment = {});
  [[nodiscard]] std::unique_ptr<LocalDatabaseItem>
  create_database_from(std::string parent, std::string name,
                       DatabaseHandle &source, std::string content_type,
                       std::optional<std::string> file_id,
                       bool reset_database_identity, std::string user = {},
                       std::optional<std::string> project_path = std::nullopt,
                       std::string comment = {});
  [[nodiscard]] std::unique_ptr<LocalDatabaseItem> create_database_from_packed(
      std::string parent, std::string name,
      const std::filesystem::path &packed_file,
      std::optional<std::string> file_id = std::nullopt, std::string user = {},
      std::optional<std::string> project_path = std::nullopt,
      std::string comment = {});

  void move_item(std::string parent, std::string name, std::string new_parent,
                 std::string new_name);

  [[nodiscard]] static bool valid_utf8(std::string_view text) noexcept;
  static void validate_name(std::string_view name,
                            std::size_t maximum_bytes = 254);
  static void validate_path(std::string_view path,
                            std::size_t maximum_name_bytes = 254);
  [[nodiscard]] static std::string path(std::string_view parent,
                                        std::string_view name);
  [[nodiscard]] static std::string parent_path(std::string_view value);
  [[nodiscard]] static std::string basename(std::string_view value);

private:
  struct Impl;
  explicit LocalFileSystem(std::shared_ptr<Impl> implementation);
  std::shared_ptr<Impl> impl_;
};

} // namespace llmghidra::db
