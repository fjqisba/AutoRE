/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/checkout_manager.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <limits>
#include <optional>
#include <system_error>

namespace llmghidra::db {
namespace {

bool whitespace(char value) {
  return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::string xml_escape(std::string_view value) {
  std::string result;
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
    throw CheckoutManagerError("invalid XML character reference");
  }
  if (codepoint <= 0x7f) result.push_back(static_cast<char>(codepoint));
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
  for (std::size_t index = 0; index < value.size();) {
    if (value[index] != '&') {
      result.push_back(value[index++]);
      continue;
    }
    const auto end = value.find(';', index + 1);
    if (end == std::string_view::npos) {
      throw CheckoutManagerError("unterminated XML entity");
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
        throw CheckoutManagerError("invalid hexadecimal XML entity");
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
        throw CheckoutManagerError("invalid decimal XML entity");
      }
      append_utf8(result, codepoint);
    }
    else throw CheckoutManagerError("unknown XML entity");
    index = end + 1;
  }
  return result;
}

std::optional<std::string> optional_attribute(std::string_view element,
                                              std::string_view name) {
  std::size_t position = 0;
  while ((position = element.find(name, position)) != std::string_view::npos) {
    const bool boundary = position == 0 || whitespace(element[position - 1]);
    auto cursor = position + name.size();
    if (!boundary) {
      position = cursor;
      continue;
    }
    while (cursor < element.size() && whitespace(element[cursor])) ++cursor;
    if (cursor >= element.size() || element[cursor++] != '=') {
      position += name.size();
      continue;
    }
    while (cursor < element.size() && whitespace(element[cursor])) ++cursor;
    if (cursor >= element.size() ||
        (element[cursor] != '"' && element[cursor] != '\'')) {
      throw CheckoutManagerError("checkout attribute is not quoted");
    }
    const auto quote = element[cursor++];
    const auto end = element.find(quote, cursor);
    if (end == std::string_view::npos) {
      throw CheckoutManagerError("unterminated checkout attribute");
    }
    return xml_unescape(element.substr(cursor, end - cursor));
  }
  return std::nullopt;
}

std::string attribute(std::string_view element, std::string_view name) {
  const auto value = optional_attribute(element, name);
  if (value) return *value;
  throw CheckoutManagerError("missing checkout attribute: " +
                             std::string(name));
}

bool boolean_true(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char character) {
                   return static_cast<char>(std::tolower(character));
                 });
  return value == "true";
}

template <typename Integer>
Integer integer(std::string_view text, std::string_view field) {
  Integer value{};
  const auto parsed =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || parsed.ec != std::errc{} ||
      parsed.ptr != text.data() + text.size()) {
    throw CheckoutManagerError("invalid checkout " + std::string(field));
  }
  return value;
}

std::int64_t current_time_millis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

void replace_file(const std::filesystem::path &temporary,
                  const std::filesystem::path &destination) {
  auto backup = destination;
  backup += ".bak";
  std::error_code error;
  std::filesystem::remove(backup, error);
  error.clear();
  bool backed_up = false;
  if (std::filesystem::exists(destination)) {
    std::filesystem::rename(destination, backup, error);
    if (error) {
      throw std::filesystem::filesystem_error(
          "failed to update checkout file", destination, backup, error);
    }
    backed_up = true;
  }
  std::filesystem::rename(temporary, destination, error);
  if (error) {
    if (backed_up) {
      std::error_code ignored;
      std::filesystem::rename(backup, destination, ignored);
    }
    throw std::filesystem::filesystem_error(
        "failed to install checkout file", temporary, destination, error);
  }
  if (backed_up) {
    error.clear();
    std::filesystem::remove(backup, error);
  }
}

} // namespace

std::optional<std::string> CheckoutStatus::user_host_name() const {
  if (!project_path) return std::nullopt;
  const auto separator = project_path->find("::");
  if (separator == std::string::npos || separator == 0) return std::nullopt;
  return project_path->substr(0, separator);
}

std::optional<std::string> CheckoutStatus::project_location() const {
  if (!project_path) return std::nullopt;
  auto path = *project_path;
  const auto separator = path.find("::");
  if (separator != std::string::npos && separator > 0) {
    path.erase(0, separator + 2);
  }
  const auto slash = path.rfind('/');
  if (slash == std::string::npos) return std::nullopt;
  return path.substr(0, slash);
}

std::optional<std::string> CheckoutStatus::project_name() const {
  if (!project_path) return std::nullopt;
  auto path = *project_path;
  const auto separator = path.find("::");
  if (separator != std::string::npos && separator > 0) {
    path.erase(0, separator + 2);
  }
  const auto slash = path.rfind('/');
  if (slash == std::string::npos) return std::nullopt;
  return path.substr(slash + 1);
}

CheckoutManager::CheckoutManager(std::filesystem::path data_directory,
                                 bool create) {
  if (data_directory.empty()) {
    throw std::invalid_argument("checkout data directory is empty");
  }
  data_directory =
      std::filesystem::absolute(std::move(data_directory)).lexically_normal();
  if (!std::filesystem::is_directory(data_directory)) {
    throw CheckoutManagerError("checkout data directory not found");
  }
  path_ = data_directory / filename;
  if (create) {
    if (std::filesystem::exists(path_)) {
      throw CheckoutManagerError("checkout file already exists");
    }
    loaded_ = true;
    write_file();
  }
}

void CheckoutManager::ensure_loaded() const {
  if (!loaded_) const_cast<CheckoutManager *>(this)->read_file();
}

void CheckoutManager::refresh() {
  loaded_ = false;
  read_file();
}

std::int64_t CheckoutManager::next_checkout_id() {
  ensure_loaded();
  return next_id_;
}

void CheckoutManager::read_file() {
  checkouts_.clear();
  next_id_ = 1;
  if (!std::filesystem::exists(path_)) {
    loaded_ = true;
    return;
  }
  std::ifstream input(path_, std::ios::binary);
  if (!input) throw CheckoutManagerError("unable to open checkout file");
  const std::string xml((std::istreambuf_iterator<char>(input)),
                        std::istreambuf_iterator<char>());
  if (xml.find("<!DOCTYPE") != std::string::npos ||
      xml.find("<!doctype") != std::string::npos) {
    throw CheckoutManagerError("DOCTYPE is not permitted in checkouts file");
  }
  std::size_t root = 0;
  if (xml.starts_with("\xef\xbb\xbf")) root = 3;
  while (root < xml.size() && whitespace(xml[root])) ++root;
  if (xml.compare(root, 5, "<?xml") == 0) {
    const auto declaration_end = xml.find("?>", root + 5);
    if (declaration_end == std::string::npos) {
      throw CheckoutManagerError("invalid checkouts XML declaration");
    }
    root = declaration_end + 2;
    while (root < xml.size() && whitespace(xml[root])) ++root;
  }
  if (xml.compare(root, 14, "<CHECKOUT_LIST") != 0 ||
      (root + 14 < xml.size() && !whitespace(xml[root + 14]) &&
       xml[root + 14] != '>' && xml[root + 14] != '/')) {
    throw CheckoutManagerError("invalid checkouts root element");
  }
  const auto root_end = root == std::string::npos
                            ? std::string::npos
                            : xml.find('>', root);
  if (root_end == std::string::npos) {
    throw CheckoutManagerError("invalid checkouts file");
  }
  auto root_tail = root_end;
  while (root_tail > root && whitespace(xml[root_tail - 1])) --root_tail;
  const bool empty_root = root_tail > root && xml[root_tail - 1] == '/';
  const auto closing = empty_root ? root_end : xml.find("</CHECKOUT_LIST>", root_end + 1);
  if (closing == std::string::npos || closing < root_end) {
    throw CheckoutManagerError("invalid checkouts file");
  }
  const auto document_end = empty_root ? root_end + 1 : closing + 16;
  if (std::any_of(xml.begin() + static_cast<std::ptrdiff_t>(document_end),
                  xml.end(), [](char character) {
                    return !whitespace(character);
                  })) {
    throw CheckoutManagerError("unexpected data after checkouts root");
  }
  const std::string_view root_element(xml.data() + root,
                                      root_end + 1 - root);
  next_id_ = integer<std::int64_t>(attribute(root_element, "NEXT_ID"),
                                   "NEXT_ID");
  if (next_id_ < 1) throw CheckoutManagerError("invalid checkout NEXT_ID");

  auto cursor = root_end + 1;
  std::int64_t maximum_id = 0;
  while (true) {
    const auto start = xml.find("<CHECKOUT", cursor);
    if (start == std::string::npos || start >= closing) break;
    if (xml.compare(start, 14, "<CHECKOUT_LIST") == 0) {
      cursor = start + 14;
      continue;
    }
    const auto end = xml.find("/>", start);
    if (end == std::string::npos || end >= closing) {
      throw CheckoutManagerError("unterminated CHECKOUT element");
    }
    const std::string_view element(xml.data() + start, end + 2 - start);
    CheckoutStatus status;
    status.checkout_id = integer<std::int64_t>(attribute(element, "ID"), "ID");
    status.user = attribute(element, "USER");
    status.version = integer<std::int32_t>(attribute(element, "VERSION"),
                                           "VERSION");
    status.time_millis = integer<std::int64_t>(attribute(element, "TIME"),
                                               "TIME");
    const auto project = optional_attribute(element, "PROJECT");
    if (project) status.project_path = *project;
    const auto exclusive = optional_attribute(element, "EXCLUSIVE");
    status.type = exclusive && boolean_true(*exclusive)
                      ? CheckoutType::exclusive
                      : CheckoutType::normal;
    if (status.checkout_id <= 0 || status.version < 0 || status.user.empty() ||
        checkouts_.contains(status.checkout_id)) {
      throw CheckoutManagerError("bad CHECKOUT element");
    }
    maximum_id = std::max(maximum_id, status.checkout_id);
    checkouts_.emplace(status.checkout_id, std::move(status));
    cursor = end + 2;
  }
  if (next_id_ <= maximum_id) {
    throw CheckoutManagerError("checkout NEXT_ID does not exceed existing ids");
  }
  loaded_ = true;
}

void CheckoutManager::write_file() const {
  auto temporary = path_;
  temporary += ".new";
  std::error_code ignored;
  std::filesystem::remove(temporary, ignored);
  try {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw CheckoutManagerError("unable to create checkout file");
    output << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           << "<CHECKOUT_LIST NEXT_ID=\"" << next_id_ << "\">\n";
    for (const auto &[id, status] : checkouts_) {
      (void)id;
      if (status.type == CheckoutType::transient) continue;
      output << "    <CHECKOUT ID=\"" << status.checkout_id
             << "\" USER=\"" << xml_escape(status.user)
             << "\" VERSION=\"" << status.version
             << "\" TIME=\"" << status.time_millis << '"';
      if (status.project_path) {
        output << " PROJECT=\"" << xml_escape(*status.project_path) << '"';
      }
      output << " EXCLUSIVE=\""
             << (status.type == CheckoutType::exclusive ? "true" : "false")
             << "\" />\n";
    }
    output << "</CHECKOUT_LIST>\n";
    output.flush();
    if (!output) throw CheckoutManagerError("unable to write checkout file");
    output.close();
    replace_file(temporary, path_);
  }
  catch (...) {
    std::filesystem::remove(temporary, ignored);
    throw;
  }
}

std::optional<CheckoutStatus> CheckoutManager::new_checkout(
    CheckoutType type, std::string user, std::int32_t version,
    std::optional<std::string> project_path) {
  ensure_loaded();
  if (type != CheckoutType::normal && type != CheckoutType::exclusive &&
      type != CheckoutType::transient) {
    throw std::invalid_argument("checkout type is invalid");
  }
  if (user.empty()) throw std::invalid_argument("checkout user is empty");
  if (version < 0) throw std::invalid_argument("checkout version is invalid");
  if (project_path) {
    std::replace(project_path->begin(), project_path->end(), '\\', '/');
  }
  if (!checkouts_.empty()) {
    if (type != CheckoutType::normal) return std::nullopt;
    const auto existing = checkouts_.begin()->second;
    if (existing.type == CheckoutType::transient) {
      throw ExclusiveCheckoutError(
          "file temporarily checked out exclusively by: " + existing.user);
    }
    if (existing.type == CheckoutType::exclusive) {
      throw ExclusiveCheckoutError(
          "file checked out exclusively by: " + existing.user);
    }
  }
  if (next_id_ == std::numeric_limits<std::int64_t>::max()) {
    throw CheckoutManagerError("checkout id space exhausted");
  }
  CheckoutStatus status{next_id_++, type, std::move(user), version,
                        current_time_millis(), std::move(project_path)};
  checkouts_.emplace(status.checkout_id, status);
  if (type != CheckoutType::transient) {
    try {
      write_file();
    }
    catch (...) {
      checkouts_.erase(status.checkout_id);
      --next_id_;
      throw;
    }
  }
  return status;
}

void CheckoutManager::update_checkout(std::int64_t checkout_id,
                                      std::int32_t version) {
  ensure_loaded();
  if (version < 0) throw std::invalid_argument("checkout version is invalid");
  const auto found = checkouts_.find(checkout_id);
  if (found == checkouts_.end()) return;
  const auto previous = found->second;
  found->second.version = version;
  found->second.time_millis = current_time_millis();
  if (found->second.type != CheckoutType::transient) {
    try {
      write_file();
    }
    catch (...) {
      found->second = previous;
      throw;
    }
  }
}

void CheckoutManager::end_checkout(std::int64_t checkout_id) {
  ensure_loaded();
  const auto found = checkouts_.find(checkout_id);
  if (found == checkouts_.end()) return;
  const auto status = found->second;
  checkouts_.erase(found);
  if (status.type != CheckoutType::transient) {
    try {
      write_file();
    }
    catch (...) {
      checkouts_.emplace(checkout_id, status);
      throw;
    }
  }
}

bool CheckoutManager::is_checked_out() const {
  ensure_loaded();
  return !checkouts_.empty();
}

bool CheckoutManager::is_checked_out(std::int32_t version) const {
  ensure_loaded();
  return std::any_of(checkouts_.begin(), checkouts_.end(),
                     [version](const auto &entry) {
                       return entry.second.version == version;
                     });
}

std::optional<CheckoutStatus>
CheckoutManager::checkout(std::int64_t checkout_id) const {
  ensure_loaded();
  const auto found = checkouts_.find(checkout_id);
  if (found == checkouts_.end()) return std::nullopt;
  return found->second;
}

std::vector<CheckoutStatus> CheckoutManager::all_checkouts() const {
  ensure_loaded();
  std::vector<CheckoutStatus> result;
  result.reserve(checkouts_.size());
  for (const auto &[id, status] : checkouts_) {
    (void)id;
    result.push_back(status);
  }
  return result;
}

} // namespace llmghidra::db
