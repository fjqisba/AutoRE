/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/packed_database_workspace.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace llmghidra::db {
namespace {

constexpr std::string_view workspace_prefix = "~tmp";
constexpr std::string_view workspace_suffix = ".pdb.db";
constexpr std::size_t random_width = 8;
std::atomic<std::uint32_t> workspace_sequence{0};

std::string random_component() {
  std::random_device random;
  const auto sequence = workspace_sequence.fetch_add(1);
  const auto time = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  const auto value = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(random()) << 1) ^ time ^ sequence);
  std::ostringstream output;
  output << std::uppercase << std::hex << std::setw(random_width)
         << std::setfill('0') << value;
  return output.str();
}

bool workspace_name(std::string_view name) {
  return name.size() == workspace_prefix.size() + random_width +
                            workspace_suffix.size() &&
         name.starts_with(workspace_prefix) &&
         name.ends_with(workspace_suffix);
}

} // namespace

bool is_read_only_packed_directory(const std::filesystem::path &directory) {
  if (directory.empty()) return true;
  std::error_code error;
  auto current = std::filesystem::absolute(directory, error).lexically_normal();
  if (error) return true;
  for (;;) {
    const auto marker = current / packed_database_directory_lock;
    const auto status = std::filesystem::status(marker, error);
    if (error) {
      if (error != std::errc::no_such_file_or_directory) return true;
      error.clear();
    }
    else if (std::filesystem::is_regular_file(status)) {
      return true;
    }
    const auto parent = current.parent_path();
    if (parent.empty() || parent == current) return false;
    current = parent;
  }
}

PackedDatabaseWorkspace::PackedDatabaseWorkspace(
    std::filesystem::path temporary_root) {
  std::error_code error;
  if (!std::filesystem::is_directory(temporary_root, error) || error) {
    throw std::invalid_argument("packed database temporary root is not a directory");
  }
  for (int attempt = 0; attempt < 10; ++attempt) {
    auto candidate = temporary_root /
                     (std::string(workspace_prefix) + random_component() +
                      std::string(workspace_suffix));
    if (std::filesystem::create_directory(candidate, error)) {
      path_ = std::move(candidate);
      return;
    }
    if (error && error != std::errc::file_exists) {
      throw std::filesystem::filesystem_error(
          "unable to create packed database temporary directory", candidate,
          error);
    }
    error.clear();
  }
  throw std::runtime_error("unable to allocate packed database temporary directory");
}

PackedDatabaseWorkspace::~PackedDatabaseWorkspace() { (void)dispose(); }

bool PackedDatabaseWorkspace::dispose() noexcept {
  if (path_.empty()) return true;
  auto deletion_path = path_;
  deletion_path += ".delete";
  std::error_code error;
  std::filesystem::remove_all(deletion_path, error);
  error.clear();
  std::filesystem::rename(path_, deletion_path, error);
  if (error) return false;
  std::filesystem::remove_all(deletion_path, error);
  if (error || std::filesystem::exists(deletion_path, error)) return false;
  path_.clear();
  return true;
}

std::size_t PackedDatabaseWorkspace::cleanup_old(
    const std::filesystem::path &temporary_root,
    std::chrono::hours minimum_age) {
  if (minimum_age < std::chrono::hours::zero()) {
    throw std::invalid_argument("packed workspace cleanup age is negative");
  }
  std::error_code error;
  std::filesystem::directory_iterator iterator(temporary_root, error);
  if (error) return 0;
  std::size_t removed = 0;
  const auto cutoff = std::filesystem::file_time_type::clock::now() - minimum_age;
  for (const auto &entry : iterator) {
    if (entry.is_symlink(error)) {
      error.clear();
      continue;
    }
    const auto name = entry.path().filename().string();
    if (!entry.is_directory(error) || error || !workspace_name(name)) {
      error.clear();
      continue;
    }
    const auto modified = entry.last_write_time(error);
    if (error || modified > cutoff) {
      error.clear();
      continue;
    }
    const auto count = std::filesystem::remove_all(entry.path(), error);
    if (!error && count != 0) ++removed;
    error.clear();
  }
  return removed;
}

} // namespace llmghidra::db
