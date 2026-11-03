/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/history_manager.hpp"

#include <charconv>
#include <fstream>
#include <map>
#include <system_error>

namespace llmghidra::db {
namespace {

template <typename Integer>
Integer integer(std::string_view text, std::string_view field) {
  Integer value{};
  const auto parsed =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || parsed.ec != std::errc{} ||
      parsed.ptr != text.data() + text.size()) {
    throw HistoryManagerError("invalid history " + std::string(field));
  }
  return value;
}

std::string encode_comment(std::string_view text) {
  std::string result;
  result.reserve(text.size());
  for (const char character : text) {
    switch (character) {
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case ';':
      result += "\\s";
      break;
    case '\\':
      result += "\\\\";
      break;
    default:
      result.push_back(character);
      break;
    }
  }
  return result;
}

std::string decode_comment(std::string_view text) {
  std::string result;
  bool control = false;
  for (const char character : text) {
    if (character == '\\') {
      control = true;
    } else if (control) {
      switch (character) {
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 's':
        result.push_back(';');
        break;
      default:
        result.push_back(character);
        break;
      }
      control = false;
    } else
      result.push_back(character);
  }
  return result;
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
      throw std::filesystem::filesystem_error("history file is in use",
                                              destination, backup, error);
    }
    backed_up = true;
  }
  std::filesystem::rename(temporary, destination, error);
  if (error) {
    if (backed_up) {
      std::error_code ignored;
      std::filesystem::rename(backup, destination, ignored);
    }
    throw std::filesystem::filesystem_error("history file install failed",
                                            temporary, destination, error);
  }
  if (backed_up) {
    error.clear();
    std::filesystem::remove(backup, error);
  }
}

} // namespace

HistoryManager::HistoryManager(std::filesystem::path data_directory,
                               bool create, ErrorCallback error_callback)
    : error_callback_(std::move(error_callback)) {
  if (data_directory.empty()) {
    throw std::invalid_argument("history data directory is empty");
  }
  data_directory =
      std::filesystem::absolute(std::move(data_directory)).lexically_normal();
  if (!std::filesystem::is_directory(data_directory)) {
    throw HistoryManagerError("history data directory not found");
  }
  path_ = data_directory / filename;
  if (!create && std::filesystem::exists(path_))
    read_file();
}

void HistoryManager::refresh(const TaskContext &task) { validate(task); }

void HistoryManager::validate(const TaskContext &task) {
  task.checkpoint();
  if (std::filesystem::exists(path_)) {
    const auto old_versions = versions_;
    const auto old_minimum = minimum_version_;
    const auto old_current = current_version_;
    try {
      read_file(task);
    } catch (...) {
      versions_ = old_versions;
      minimum_version_ = old_minimum;
      current_version_ = old_current;
      throw;
    }
  } else {
    task.checkpoint();
    versions_.clear();
    minimum_version_ = 0;
    current_version_ = 0;
  }
}

void HistoryManager::read_file(const TaskContext &task) {
  task.checkpoint();
  std::ifstream input(path_, std::ios::binary);
  if (!input)
    throw HistoryManagerError("unable to open history file");
  std::vector<ItemVersion> parsed;
  std::string line;
  std::int32_t previous = 0;
  while (std::getline(input, line)) {
    task.checkpoint();
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    auto entry = decode(line);
    if (previous != 0 && entry.version != previous + 1) {
      throw HistoryManagerError("history versions are not sequential");
    }
    previous = entry.version;
    parsed.push_back(std::move(entry));
  }
  if (!input.eof() && input.fail()) {
    throw HistoryManagerError("unable to read history file");
  }
  task.checkpoint();
  versions_ = std::move(parsed);
  minimum_version_ = versions_.empty() ? 0 : versions_.front().version;
  current_version_ = versions_.empty() ? 0 : versions_.back().version;
}

std::string HistoryManager::encode(const ItemVersion &version) {
  return std::to_string(version.version) + ";" + version.user + ";" +
         std::to_string(version.creation_time_millis) + ";" +
         encode_comment(version.comment);
}

ItemVersion HistoryManager::decode(std::string_view line) {
  const auto first = line.find(';');
  const auto second = first == std::string_view::npos
                          ? std::string_view::npos
                          : line.find(';', first + 1);
  const auto third = second == std::string_view::npos
                         ? std::string_view::npos
                         : line.find(';', second + 1);
  if (first == std::string_view::npos || second == std::string_view::npos) {
    throw HistoryManagerError("bad history line");
  }
  ItemVersion result;
  result.version = integer<std::int32_t>(line.substr(0, first), "version");
  result.user = std::string(line.substr(first + 1, second - first - 1));
  const auto time_end = third == std::string_view::npos ? line.size() : third;
  result.creation_time_millis = integer<std::int64_t>(
      line.substr(second + 1, time_end - second - 1), "time");
  result.comment = third == std::string_view::npos
                       ? std::string{}
                       : decode_comment(line.substr(third + 1));
  if (result.version < 1 || result.user.empty()) {
    throw HistoryManagerError("bad history entry");
  }
  return result;
}

void HistoryManager::report_write_error(std::string message) noexcept {
  if (!error_callback_)
    return;
  try {
    error_callback_(message);
  } catch (...) {
  }
}

void HistoryManager::write_file() noexcept {
  auto temporary = path_;
  temporary += ".new";
  std::error_code ignored;
  std::filesystem::remove(temporary, ignored);
  try {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output)
      throw HistoryManagerError("unable to create history file");
    for (const auto &entry : versions_) {
      output << encode(entry) << '\n';
    }
    output.flush();
    if (!output)
      throw HistoryManagerError("unable to write history file");
    output.close();
    replace_file(temporary, path_);
  } catch (const std::exception &error) {
    std::filesystem::remove(temporary, ignored);
    report_write_error(std::string("failed to update history file: ") +
                       error.what());
  }
}

void HistoryManager::append_file(const ItemVersion &version) noexcept {
  try {
    std::ofstream output(path_, std::ios::binary | std::ios::app);
    if (!output)
      throw HistoryManagerError("unable to append history file");
    output << encode(version) << '\n';
    output.flush();
    if (!output)
      throw HistoryManagerError("unable to append history entry");
  } catch (const std::exception &error) {
    report_write_error(std::string("failed to update history file: ") +
                       error.what());
  }
}

bool HistoryManager::fix_history(std::int32_t minimum_version,
                                 std::int32_t current_version,
                                 const TaskContext &task) {
  task.checkpoint();
  auto prior_versions = versions_;
  const auto prior_minimum = minimum_version_;
  const auto prior_current = current_version_;
  try {
    validate(task);
    task.checkpoint();
    if (minimum_version == minimum_version_ &&
        current_version == current_version_) {
      return false;
    }
    if (minimum_version < 1 || current_version < minimum_version) {
      throw std::invalid_argument("invalid history version range");
    }

    const auto total = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(current_version) -
        static_cast<std::int64_t>(minimum_version) + 1);
    task.report("history-repair", 0, total);
    std::map<std::int32_t, ItemVersion> old;
    for (const auto &entry : versions_) {
      task.checkpoint();
      old.emplace(entry.version, entry);
    }
    std::vector<ItemVersion> corrected;
    corrected.reserve(static_cast<std::size_t>(total));
    for (std::uint64_t offset = 0; offset < total; ++offset) {
      const auto value =
          static_cast<std::int32_t>(static_cast<std::int64_t>(minimum_version) +
                                    static_cast<std::int64_t>(offset));
      const auto found = old.find(value);
      if (found != old.end())
        corrected.push_back(found->second);
      else
        corrected.push_back(ItemVersion{value, 0, "<Unknown>", "<Recovered>"});
      task.report("history-repair", offset + 1, total);
    }

    // Fixed upstream deliberately retains the new in-memory history when its
    // noexcept write path reports an error through the callback. Cancellation
    // therefore ends here, before both the memory transition and file write.
    task.checkpoint();
    versions_ = std::move(corrected);
    minimum_version_ = minimum_version;
    current_version_ = current_version;
    write_file();
    return true;
  } catch (const OperationCancelled &) {
    versions_.swap(prior_versions);
    minimum_version_ = prior_minimum;
    current_version_ = prior_current;
    throw;
  }
}

bool HistoryManager::version_added(std::int32_t version,
                                   std::int64_t creation_time_millis,
                                   std::string comment, std::string user) {
  validate();
  if (version != current_version_ + 1)
    return false;
  ItemVersion entry{version, creation_time_millis, std::move(user),
                    std::move(comment)};
  append_file(entry);
  versions_.push_back(std::move(entry));
  current_version_ = version;
  if (version == 1)
    minimum_version_ = 1;
  return true;
}

bool HistoryManager::version_deleted(std::int32_t version) {
  validate();
  if (versions_.size() <= 1)
    return false;
  if (version == versions_.front().version)
    versions_.erase(versions_.begin());
  else if (version == versions_.back().version)
    versions_.pop_back();
  else
    return false;
  minimum_version_ = versions_.front().version;
  current_version_ = versions_.back().version;
  write_file();
  return true;
}

std::vector<ItemVersion> HistoryManager::versions() {
  validate();
  return versions_;
}

std::optional<ItemVersion> HistoryManager::version(std::int32_t version_value) {
  validate();
  if (version_value < minimum_version_ || version_value >= current_version_) {
    return std::nullopt;
  }
  return versions_.at(
      static_cast<std::size_t>(version_value - minimum_version_));
}

std::int32_t HistoryManager::minimum_version() {
  validate();
  return minimum_version_;
}

std::int32_t HistoryManager::current_version() {
  validate();
  return current_version_;
}

} // namespace llmghidra::db
