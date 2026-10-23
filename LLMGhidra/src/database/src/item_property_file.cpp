/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/item_property_file.hpp"

#include <charconv>
#include <fstream>
#include <limits>
#include <system_error>

namespace llmghidra::db {
namespace {

std::string xml_escape(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (const char character : value) {
    switch (character) {
    case '&': result += "&amp;"; break;
    case '<': result += "&lt;"; break;
    case '>': result += "&gt;"; break;
    case '"': result += "&quot;"; break;
    case '\'': result += "&apos;"; break;
    default: result.push_back(character); break;
    }
  }
  return result;
}

void append_utf8(std::string &result, std::uint32_t codepoint) {
  if (codepoint == 0 || codepoint > 0x10ffff ||
      (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
    throw PropertyFileError("invalid XML character reference");
  }
  if (codepoint <= 0x7f) {
    result.push_back(static_cast<char>(codepoint));
  }
  else if (codepoint <= 0x7ff) {
    result.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
    result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  }
  else if (codepoint <= 0xffff) {
    result.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
    result.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  }
  else {
    result.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
    result.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
    result.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  }
}

std::string xml_unescape(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (std::size_t index = 0; index < value.size();) {
    if (value[index] != '&') {
      result.push_back(value[index++]);
      continue;
    }
    const auto end = value.find(';', index + 1);
    if (end == std::string_view::npos) {
      throw PropertyFileError("unterminated XML entity");
    }
    const auto entity = value.substr(index + 1, end - index - 1);
    if (entity == "amp") result.push_back('&');
    else if (entity == "lt") result.push_back('<');
    else if (entity == "gt") result.push_back('>');
    else if (entity == "quot") result.push_back('"');
    else if (entity == "apos") result.push_back('\'');
    else if (entity.starts_with("#x") || entity.starts_with("#X")) {
      std::uint32_t codepoint = 0;
      const auto digits = entity.substr(2);
      const auto parsed = std::from_chars(digits.data(),
                                          digits.data() + digits.size(),
                                          codepoint, 16);
      if (digits.empty() || parsed.ec != std::errc{} ||
          parsed.ptr != digits.data() + digits.size()) {
        throw PropertyFileError("invalid hexadecimal XML entity");
      }
      append_utf8(result, codepoint);
    }
    else if (entity.starts_with('#')) {
      std::uint32_t codepoint = 0;
      const auto digits = entity.substr(1);
      const auto parsed = std::from_chars(digits.data(),
                                          digits.data() + digits.size(),
                                          codepoint);
      if (digits.empty() || parsed.ec != std::errc{} ||
          parsed.ptr != digits.data() + digits.size()) {
        throw PropertyFileError("invalid decimal XML entity");
      }
      append_utf8(result, codepoint);
    }
    else {
      throw PropertyFileError("unknown XML entity");
    }
    index = end + 1;
  }
  return result;
}

std::string attribute(std::string_view element, std::string_view name) {
  std::size_t position = 0;
  while ((position = element.find(name, position)) != std::string_view::npos) {
    const bool left_boundary = position == 0 ||
        element[position - 1] == ' ' || element[position - 1] == '\t' ||
        element[position - 1] == '\r' || element[position - 1] == '\n';
    auto cursor = position + name.size();
    if (!left_boundary) {
      position = cursor;
      continue;
    }
    while (cursor < element.size() &&
           (element[cursor] == ' ' || element[cursor] == '\t' ||
            element[cursor] == '\r' || element[cursor] == '\n')) {
      ++cursor;
    }
    if (cursor >= element.size() || element[cursor++] != '=') {
      position += name.size();
      continue;
    }
    while (cursor < element.size() &&
           (element[cursor] == ' ' || element[cursor] == '\t' ||
            element[cursor] == '\r' || element[cursor] == '\n')) {
      ++cursor;
    }
    if (cursor >= element.size() || element[cursor++] != '"') {
      throw PropertyFileError("property attribute is not double quoted");
    }
    const auto end = element.find('"', cursor);
    if (end == std::string_view::npos) {
      throw PropertyFileError("unterminated property attribute");
    }
    return xml_unescape(element.substr(cursor, end - cursor));
  }
  throw PropertyFileError("missing property attribute: " + std::string(name));
}

template <typename Integer>
std::optional<Integer> parse_integer(std::string_view value) {
  Integer result{};
  const auto parsed =
      std::from_chars(value.data(), value.data() + value.size(), result);
  if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
    return std::nullopt;
  }
  return result;
}

} // namespace

PropertyFile::PropertyFile(std::filesystem::path directory,
                           std::string storage_name)
    : directory_(std::move(directory)), storage_name_(std::move(storage_name)) {
  if (!directory_.is_absolute()) {
    throw std::invalid_argument("property directory must be absolute");
  }
  if (storage_name_.empty()) {
    throw std::invalid_argument("property storage name is empty");
  }
  directory_ = directory_.lexically_normal();
  path_ = directory_ / (storage_name_ + std::string(property_extension));
  std::error_code error;
  const auto status = std::filesystem::symlink_status(path_, error);
  if (!error && std::filesystem::is_symlink(status)) {
    throw PropertyFileError("property file may not be a symbolic link");
  }
  if (error && error != std::errc::no_such_file_or_directory) {
    throw std::filesystem::filesystem_error(
        "unable to inspect property file", path_, error);
  }
  if (exists()) read_state();
}

bool PropertyFile::contains(std::string_view key) const {
  return entries_.contains(key);
}

std::int32_t PropertyFile::get_int(std::string_view key,
                                   std::int32_t fallback) const {
  const auto found = entries_.find(key);
  if (found == entries_.end() || found->second.type != EntryType::integer) {
    return fallback;
  }
  return parse_integer<std::int32_t>(found->second.value).value_or(fallback);
}

std::int64_t PropertyFile::get_long(std::string_view key,
                                    std::int64_t fallback) const {
  const auto found = entries_.find(key);
  if (found == entries_.end() || found->second.type != EntryType::long_integer) {
    return fallback;
  }
  return parse_integer<std::int64_t>(found->second.value).value_or(fallback);
}

bool PropertyFile::get_boolean(std::string_view key, bool fallback) const {
  const auto found = entries_.find(key);
  if (found == entries_.end() || found->second.type != EntryType::boolean) {
    return fallback;
  }
  // Boolean.parseBoolean is case-insensitive and returns false for every
  // spelling other than "true".
  std::string lowered = found->second.value;
  for (char &character : lowered) {
    if (character >= 'A' && character <= 'Z') character += 'a' - 'A';
  }
  return lowered == "true";
}

std::optional<std::string>
PropertyFile::get_string(std::string_view key) const {
  const auto found = entries_.find(key);
  if (found == entries_.end() || found->second.type != EntryType::string) {
    return std::nullopt;
  }
  return found->second.value;
}

std::string PropertyFile::get_string(std::string_view key,
                                     std::string fallback) const {
  const auto value = get_string(key);
  return value ? *value : std::move(fallback);
}

void PropertyFile::put_int(std::string key, std::int32_t value) {
  entries_.insert_or_assign(std::move(key),
                            Entry{EntryType::integer, std::to_string(value),
                                  "int"});
}

void PropertyFile::put_long(std::string key, std::int64_t value) {
  entries_.insert_or_assign(std::move(key),
                            Entry{EntryType::long_integer,
                                  std::to_string(value), "long"});
}

void PropertyFile::put_boolean(std::string key, bool value) {
  entries_.insert_or_assign(std::move(key),
                            Entry{EntryType::boolean,
                                  value ? "true" : "false", "boolean"});
}

void PropertyFile::put_string(std::string key,
                              std::optional<std::string> value) {
  if (!value) {
    entries_.erase(key);
    return;
  }
  entries_.insert_or_assign(std::move(key),
                            Entry{EntryType::string, std::move(*value),
                                  "string"});
}

void PropertyFile::remove(std::string_view key) {
  const auto found = entries_.find(key);
  if (found != entries_.end()) entries_.erase(found);
}

void PropertyFile::read_state() {
  std::ifstream input(path_, std::ios::binary);
  if (!input) throw PropertyFileError("unable to open property file");
  const std::string xml((std::istreambuf_iterator<char>(input)),
                        std::istreambuf_iterator<char>());
  if (!input.eof() && input.fail()) {
    throw PropertyFileError("unable to read property file");
  }
  const auto file_start = xml.find("<FILE_INFO>");
  const auto file_end = xml.find("</FILE_INFO>");
  const auto basic_start = xml.find("<BASIC_INFO>", file_start);
  const auto basic_end = xml.find("</BASIC_INFO>", basic_start);
  if (file_start == std::string::npos || file_end == std::string::npos ||
      basic_start == std::string::npos || basic_end == std::string::npos ||
      !(file_start < basic_start && basic_start < basic_end &&
        basic_end < file_end)) {
    throw PropertyFileError("XML parse error in properties file");
  }

  std::map<std::string, Entry, std::less<>> parsed_entries;
  auto cursor = basic_start + std::string_view("<BASIC_INFO>").size();
  while (true) {
    const auto state = xml.find("<STATE", cursor);
    if (state == std::string::npos || state >= basic_end) break;
    const auto end = xml.find("/>", state);
    if (end == std::string::npos || end >= basic_end) {
      throw PropertyFileError("unterminated STATE element");
    }
    const std::string_view element(xml.data() + state, end + 2 - state);
    auto name = attribute(element, "NAME");
    auto type_name = attribute(element, "TYPE");
    auto value = attribute(element, "VALUE");
    auto type = EntryType::unknown;
    if (type_name == "int") type = EntryType::integer;
    else if (type_name == "long") type = EntryType::long_integer;
    else if (type_name == "boolean") type = EntryType::boolean;
    else if (type_name == "string") type = EntryType::string;
    parsed_entries.insert_or_assign(
        std::move(name),
        Entry{type, std::move(value), std::move(type_name)});
    cursor = end + 2;
  }
  entries_ = std::move(parsed_entries);
}

void PropertyFile::write_state() const {
  std::error_code error;
  if (!std::filesystem::is_directory(directory_, error) || error) {
    throw PropertyFileError("property directory does not exist");
  }
  std::ofstream output(path_, std::ios::binary | std::ios::trunc);
  if (!output) throw PropertyFileError("unable to create property file");
  output << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
         << "<FILE_INFO>\n"
         << "    <BASIC_INFO>\n";
  for (const auto &[name, entry] : entries_) {
    if (entry.type == EntryType::unknown) {
      throw PropertyFileError("cannot serialize unknown property type: " +
                              entry.serialized_type);
    }
    output << "        <STATE NAME=\"" << xml_escape(name)
           << "\" TYPE=\"" << xml_escape(entry.serialized_type)
           << "\" VALUE=\"" << xml_escape(entry.value) << "\" />\n";
  }
  output << "    </BASIC_INFO>\n"
         << "</FILE_INFO>\n";
  output.flush();
  if (!output) throw PropertyFileError("unable to write property file");
}

void PropertyFile::move_to(std::filesystem::path directory,
                           std::string storage_name) {
  if (!directory.is_absolute()) {
    throw std::invalid_argument("property directory must be absolute");
  }
  if (storage_name.empty()) {
    throw std::invalid_argument("property storage name is empty");
  }
  directory = directory.lexically_normal();
  const auto destination =
      directory / (storage_name + std::string(property_extension));
  if (destination == path_) return;
  if (std::filesystem::exists(destination)) {
    throw DuplicatePropertyFileError("property destination already exists");
  }
  std::error_code error;
  std::filesystem::rename(path_, destination, error);
  if (error) {
    throw std::filesystem::filesystem_error("property move failed", path_,
                                            destination, error);
  }
  directory_ = std::move(directory);
  path_ = destination;
  storage_name_ = std::move(storage_name);
}

void PropertyFile::delete_file() {
  std::error_code error;
  if (!std::filesystem::remove(path_, error) && error) {
    throw std::filesystem::filesystem_error("property delete failed", path_,
                                            error);
  }
}

bool PropertyFile::exists() const { return std::filesystem::is_regular_file(path_); }

bool PropertyFile::read_only() const {
  std::error_code error;
  const auto permissions = std::filesystem::status(path_, error).permissions();
  if (error) return false;
  using perms = std::filesystem::perms;
  return (permissions & (perms::owner_write | perms::group_write |
                         perms::others_write)) == perms::none;
}

std::filesystem::file_time_type PropertyFile::last_modified() const {
  std::error_code error;
  const auto result = std::filesystem::last_write_time(path_, error);
  if (error) return {};
  return result;
}

const std::filesystem::path &PropertyFile::path() const noexcept { return path_; }

const std::filesystem::path &
PropertyFile::parent_storage_directory() const noexcept {
  return directory_;
}

const std::string &PropertyFile::storage_name() const noexcept {
  return storage_name_;
}

ItemPropertyFile::ItemPropertyFile(std::filesystem::path directory,
                                   std::string storage_name,
                                   std::string parent_path, std::string name,
                                   bool persist_identity)
    : PropertyFile(std::move(directory), std::move(storage_name)),
      parent_path_(std::move(parent_path)), name_(std::move(name)),
      persist_identity_(persist_identity) {
  if (!persist_identity_)
    return;
  const auto stored_name = get_string(name_property);
  const auto stored_parent = get_string(parent_path_property);
  if (stored_name && stored_parent) {
    name_ = *stored_name;
    parent_path_ = *stored_parent;
  } else {
    put_string(std::string(name_property), name_);
    put_string(std::string(parent_path_property), parent_path_);
  }
}

const std::string &ItemPropertyFile::name() const noexcept { return name_; }

const std::string &ItemPropertyFile::parent_path() const noexcept {
  return parent_path_;
}

std::string ItemPropertyFile::logical_path() const {
  if (parent_path_.empty() || name_.empty()) return {};
  if (parent_path_ == "/") return parent_path_ + name_;
  return parent_path_ + "/" + name_;
}

std::optional<std::string> ItemPropertyFile::file_id() const {
  return get_string(file_id_property);
}

void ItemPropertyFile::set_file_id(std::optional<std::string> file_id) {
  put_string(std::string(file_id_property), std::move(file_id));
}

void ItemPropertyFile::move_to(std::filesystem::path directory,
                               std::string storage_name,
                               std::string parent_path, std::string name) {
  const auto old_directory = directory_;
  const auto old_storage_name = storage_name_;
  const auto old_parent = parent_path_;
  const auto old_name = name_;
  PropertyFile::move_to(std::move(directory), std::move(storage_name));
  try {
    parent_path_ = std::move(parent_path);
    name_ = std::move(name);
    if (persist_identity_) {
      put_string(std::string(name_property), name_);
      put_string(std::string(parent_path_property), parent_path_);
      write_state();
    }
  } catch (...) {
    parent_path_ = old_parent;
    name_ = old_name;
    if (persist_identity_) {
      put_string(std::string(name_property), old_name);
      put_string(std::string(parent_path_property), old_parent);
    }
    try {
      PropertyFile::move_to(old_directory, old_storage_name);
      if (persist_identity_)
        write_state();
    } catch (...) {
    }
    throw;
  }
}

} // namespace llmghidra::db
