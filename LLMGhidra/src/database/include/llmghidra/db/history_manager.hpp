/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/task_control.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace llmghidra::db {

class HistoryManagerError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

struct ItemVersion final {
  std::int32_t version = 0;
  std::int64_t creation_time_millis = 0;
  std::string user;
  std::string comment;

  friend bool operator==(const ItemVersion &, const ItemVersion &) = default;
};

// Ghidra-compatible history.dat owner. Read/parse failures are reported to the
// caller. Like the upstream implementation, metadata write failures are sent
// to an error callback while the in-memory version transition remains valid.
class HistoryManager final {
public:
  using ErrorCallback = std::function<void(const std::string &)>;
  static constexpr const char *filename = "history.dat";

  HistoryManager(std::filesystem::path data_directory, bool create,
                 ErrorCallback error_callback = {});

  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }
  void refresh(const TaskContext &task = {});
  [[nodiscard]] bool fix_history(std::int32_t minimum_version,
                                 std::int32_t current_version,
                                 const TaskContext &task = {});
  [[nodiscard]] bool version_added(std::int32_t version,
                                   std::int64_t creation_time_millis,
                                   std::string comment, std::string user);
  [[nodiscard]] bool version_deleted(std::int32_t version);

  [[nodiscard]] std::vector<ItemVersion> versions();
  // Matches upstream: the current version is deliberately not returned by
  // this single-version historical query.
  [[nodiscard]] std::optional<ItemVersion> version(std::int32_t version);
  [[nodiscard]] std::int32_t minimum_version();
  [[nodiscard]] std::int32_t current_version();

  [[nodiscard]] static std::string encode(const ItemVersion &version);
  [[nodiscard]] static ItemVersion decode(std::string_view line);

private:
  void validate(const TaskContext &task = {});
  void read_file(const TaskContext &task = {});
  void write_file() noexcept;
  void append_file(const ItemVersion &version) noexcept;
  void report_write_error(std::string message) noexcept;

  std::filesystem::path path_;
  ErrorCallback error_callback_;
  std::int32_t minimum_version_ = 0;
  std::int32_t current_version_ = 0;
  std::vector<ItemVersion> versions_;
};

} // namespace llmghidra::db
