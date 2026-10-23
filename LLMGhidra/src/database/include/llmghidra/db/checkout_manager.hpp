/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace llmghidra::db {

class CheckoutManagerError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

class ExclusiveCheckoutError : public CheckoutManagerError {
public:
  using CheckoutManagerError::CheckoutManagerError;
};

enum class CheckoutType : std::uint8_t {
  normal = 'N',
  exclusive = 'E',
  transient = 'T'
};

struct CheckoutStatus final {
  std::int64_t checkout_id = 0;
  CheckoutType type = CheckoutType::normal;
  std::string user;
  std::int32_t version = 0;
  std::int64_t time_millis = 0;
  std::optional<std::string> project_path;

  [[nodiscard]] std::optional<std::string> project_name() const;
  [[nodiscard]] std::optional<std::string> project_location() const;
  [[nodiscard]] std::optional<std::string> user_host_name() const;
  friend bool operator==(const CheckoutStatus &, const CheckoutStatus &) = default;
};

// Ghidra-compatible checkout.dat owner. Transient checkouts remain in memory
// only; persistent mutations use sibling .new/.bak replacement.
class CheckoutManager final {
public:
  static constexpr const char *filename = "checkout.dat";

  CheckoutManager(std::filesystem::path data_directory, bool create);

  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }
  [[nodiscard]] std::int64_t next_checkout_id();
  void refresh();

  [[nodiscard]] std::optional<CheckoutStatus>
  new_checkout(CheckoutType type, std::string user, std::int32_t version,
               std::optional<std::string> project_path);
  void update_checkout(std::int64_t checkout_id, std::int32_t version);
  void end_checkout(std::int64_t checkout_id);

  [[nodiscard]] bool is_checked_out() const;
  [[nodiscard]] bool is_checked_out(std::int32_t version) const;
  [[nodiscard]] std::optional<CheckoutStatus>
  checkout(std::int64_t checkout_id) const;
  [[nodiscard]] std::vector<CheckoutStatus> all_checkouts() const;

private:
  void ensure_loaded() const;
  void read_file();
  void write_file() const;

  std::filesystem::path path_;
  mutable bool loaded_ = false;
  std::int64_t next_id_ = 1;
  std::map<std::int64_t, CheckoutStatus> checkouts_;
};

} // namespace llmghidra::db
