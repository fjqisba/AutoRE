/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

namespace llmghidra::db {

enum class LockFileIoPhase : std::uint8_t {
  clock_probe,
  snapshot_read,
  owner_create,
  owner_renew,
  owned_remove,
  stale_reclaim,
};

enum class LockFileIoOperation : std::uint8_t {
  create,
  open,
  stat,
  read,
  lock,
  write,
  truncate,
  flush,
  remove,
  close,
};

struct LockFileIoPoint final {
  LockFileIoPhase phase;
  LockFileIoOperation operation;
};

// Fault/instrumentation seam around native LockFile syscalls. Hooks can reject
// or shorten an operation, but never replace the product identity checks.
// Implementations must be thread-safe because renewal can run concurrently.
class LockFileIoHooks {
public:
  virtual ~LockFileIoHooks() = default;

  [[nodiscard]] virtual std::error_code before(LockFileIoPoint) noexcept {
    return {};
  }

  [[nodiscard]] virtual std::size_t
  write_limit(LockFileIoPoint, std::size_t requested) noexcept {
    return requested;
  }
};

struct LockFileOptions final {
  std::chrono::milliseconds maximum_lease{15000};
  std::chrono::milliseconds renewal_period{13000};
  std::chrono::milliseconds default_timeout{30000};
  std::chrono::milliseconds poll_interval{100};
  // local system clock minus filesystem/server clock. When omitted, the
  // first conflicting lock triggers a same-directory timestamp probe.
  std::optional<std::chrono::milliseconds> filesystem_clock_delta;
  std::shared_ptr<LockFileIoHooks> io_hooks;
};

// Cross-process lease lock compatible with Ghidra's local LockFile naming and
// lifecycle. Lock ownership is represented by an atomically-created sibling
// file and renewed by rewriting its owner record before the lease expires.
// Public operations are thread-safe while the object remains alive; callers
// must still exclude concurrent destruction.
class LockFile final {
public:
  LockFile(std::filesystem::path directory, std::string name,
           std::string lock_type = {}, LockFileOptions options = {});
  explicit LockFile(std::filesystem::path controlled_file,
                    LockFileOptions options = {});
  ~LockFile();

  LockFile(const LockFile &) = delete;
  LockFile &operator=(const LockFile &) = delete;
  LockFile(LockFile &&) = delete;
  LockFile &operator=(LockFile &&) = delete;

  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }
  [[nodiscard]] bool have_lock();
  [[nodiscard]] bool have_lock(bool verify);
  [[nodiscard]] std::size_t lock_count() const noexcept;
  [[nodiscard]] std::string lock_owner() const;

  [[nodiscard]] bool create_lock();
  [[nodiscard]] bool create_lock(std::chrono::milliseconds timeout, bool hold);
  void remove_lock() noexcept;
  void dispose() noexcept;

  // Input and output are strict UTF-8. Mangling follows fixed-Java UTF-16 char
  // semantics, including preservation of supplementary uppercase code points.
  [[nodiscard]] static std::string mangle_name(std::string_view name);
  [[nodiscard]] static bool is_locked(const std::filesystem::path &directory,
                                      std::string_view name);
  [[nodiscard]] static bool
  is_locked(const std::filesystem::path &controlled_file);
  [[nodiscard]] static bool
  contains_lock(const std::filesystem::path &directory);

private:
  [[nodiscard]] bool acquire_once(bool remove_stale);
  [[nodiscard]] bool verify_locked();
  [[nodiscard]] bool renew_locked();
  [[nodiscard]] bool reclaim_stale_lock();
  [[nodiscard]] bool remove_owned_file() noexcept;
  void clear_ownership_locked() noexcept;
  void start_hold_locked();
  [[nodiscard]] std::thread take_hold_thread_locked() noexcept;
  void write_owner(bool exclusive_create);
  [[nodiscard]] std::string owner_record() const;

  std::filesystem::path path_;
  LockFileOptions options_;
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  std::thread hold_thread_;
  bool hold_enabled_ = false;
  std::uint64_t hold_generation_ = 0;
  std::array<std::uint64_t, 2> owned_identity_{};
  std::array<std::int64_t, 2> owned_write_time_{};
  std::string owned_record_;
  bool ownership_snapshot_valid_ = false;
  std::int64_t filesystem_clock_delta_ = 0;
  bool filesystem_clock_delta_valid_ = false;
  std::size_t lock_count_ = 0;
};

} // namespace llmghidra::db
