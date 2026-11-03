/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace llmghidra::db {

class PropertyFileError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class DuplicatePropertyFileError : public PropertyFileError {
public:
  using PropertyFileError::PropertyFileError;
};

// Native implementation of ghidra.util.PropertyFile's compatibility XML.
// Values retain their declared Java primitive type instead of being coerced.
class PropertyFile {
public:
  static constexpr std::string_view property_extension = ".prp";

  PropertyFile(std::filesystem::path directory, std::string storage_name);
  virtual ~PropertyFile() = default;

  PropertyFile(const PropertyFile &) = delete;
  PropertyFile &operator=(const PropertyFile &) = delete;
  PropertyFile(PropertyFile &&) noexcept = default;
  PropertyFile &operator=(PropertyFile &&) noexcept = default;

  [[nodiscard]] bool contains(std::string_view key) const;
  [[nodiscard]] std::int32_t get_int(std::string_view key,
                                     std::int32_t fallback) const;
  [[nodiscard]] std::int64_t get_long(std::string_view key,
                                      std::int64_t fallback) const;
  [[nodiscard]] bool get_boolean(std::string_view key, bool fallback) const;
  [[nodiscard]] std::optional<std::string>
  get_string(std::string_view key) const;
  [[nodiscard]] std::string get_string(std::string_view key,
                                       std::string fallback) const;

  void put_int(std::string key, std::int32_t value);
  void put_long(std::string key, std::int64_t value);
  void put_boolean(std::string key, bool value);
  void put_string(std::string key, std::optional<std::string> value);
  void remove(std::string_view key);

  void read_state();
  void write_state() const;
  void move_to(std::filesystem::path directory, std::string storage_name);
  void delete_file();

  [[nodiscard]] bool exists() const;
  [[nodiscard]] bool read_only() const;
  [[nodiscard]] std::filesystem::file_time_type last_modified() const;
  [[nodiscard]] const std::filesystem::path &path() const noexcept;
  [[nodiscard]] const std::filesystem::path &parent_storage_directory() const
      noexcept;
  [[nodiscard]] const std::string &storage_name() const noexcept;

protected:
  enum class EntryType { integer, long_integer, boolean, string, unknown };
  struct Entry final {
    EntryType type;
    std::string value;
    std::string serialized_type;
  };

  std::filesystem::path directory_;
  std::filesystem::path path_;
  std::string storage_name_;
  std::map<std::string, Entry, std::less<>> entries_;
};

// Logical name/path are intentionally supplied by the filesystem index.  As in
// Java ItemPropertyFile they are not serialized into the legacy .prp file.
class ItemPropertyFile final : public PropertyFile {
public:
  static constexpr std::string_view file_id_property = "FILE_ID";
  static constexpr std::string_view name_property = "NAME";
  static constexpr std::string_view parent_path_property = "PARENT";

  ItemPropertyFile(std::filesystem::path directory, std::string storage_name,
                   std::string parent_path, std::string name,
                   bool persist_identity = false);

  [[nodiscard]] const std::string &name() const noexcept;
  [[nodiscard]] const std::string &parent_path() const noexcept;
  [[nodiscard]] std::string logical_path() const;
  [[nodiscard]] std::optional<std::string> file_id() const;
  void set_file_id(std::optional<std::string> file_id);

  void move_to(std::filesystem::path directory, std::string storage_name,
               std::string parent_path, std::string name);

private:
  std::string parent_path_;
  std::string name_;
  bool persist_identity_ = false;
};

} // namespace llmghidra::db
