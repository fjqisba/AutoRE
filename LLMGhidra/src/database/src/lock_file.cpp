/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/lock_file.hpp"
#include "llmghidra/db/detail/lock_file_time.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace llmghidra::db {
namespace {

std::atomic<std::uint64_t> owner_sequence{0};
std::atomic<std::uint64_t> clock_probe_sequence{0};

struct UnicodeLowercaseMapping final {
  std::uint16_t uppercase;
  std::uint16_t lowercase;
};

#include "unicode_bmp_lowercase.inc"

struct Utf8CodePoint final {
  std::uint32_t value;
  std::size_t length;
};

bool is_continuation(unsigned char byte) noexcept {
  return (byte & 0xc0U) == 0x80U;
}

Utf8CodePoint decode_utf8(std::string_view text, std::size_t offset) {
  const auto invalid = [] {
    throw std::invalid_argument("lock name is not valid UTF-8");
  };
  const auto first = static_cast<unsigned char>(text[offset]);
  if (first <= 0x7fU)
    return {first, 1};
  if (first >= 0xc2U && first <= 0xdfU) {
    if (offset + 2 > text.size())
      invalid();
    const auto second = static_cast<unsigned char>(text[offset + 1]);
    if (!is_continuation(second))
      invalid();
    return {
        static_cast<std::uint32_t>(((first & 0x1fU) << 6U) | (second & 0x3fU)),
        2};
  }
  if (first >= 0xe0U && first <= 0xefU) {
    if (offset + 3 > text.size())
      invalid();
    const auto second = static_cast<unsigned char>(text[offset + 1]);
    const auto third = static_cast<unsigned char>(text[offset + 2]);
    if (!is_continuation(second) || !is_continuation(third) ||
        (first == 0xe0U && second < 0xa0U) ||
        (first == 0xedU && second >= 0xa0U)) {
      invalid();
    }
    return {static_cast<std::uint32_t>(((first & 0x0fU) << 12U) |
                                       ((second & 0x3fU) << 6U) |
                                       (third & 0x3fU)),
            3};
  }
  if (first >= 0xf0U && first <= 0xf4U) {
    if (offset + 4 > text.size())
      invalid();
    const auto second = static_cast<unsigned char>(text[offset + 1]);
    const auto third = static_cast<unsigned char>(text[offset + 2]);
    const auto fourth = static_cast<unsigned char>(text[offset + 3]);
    if (!is_continuation(second) || !is_continuation(third) ||
        !is_continuation(fourth) || (first == 0xf0U && second < 0x90U) ||
        (first == 0xf4U && second > 0x8fU)) {
      invalid();
    }
    return {static_cast<std::uint32_t>(
                ((first & 0x07U) << 18U) | ((second & 0x3fU) << 12U) |
                ((third & 0x3fU) << 6U) | (fourth & 0x3fU)),
            4};
  }
  invalid();
  return {};
}

void append_utf8(std::string &text, std::uint32_t value) {
  if (value <= 0x7fU) {
    text.push_back(static_cast<char>(value));
  } else if (value <= 0x7ffU) {
    text.push_back(static_cast<char>(0xc0U | (value >> 6U)));
    text.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
  } else {
    text.push_back(static_cast<char>(0xe0U | (value >> 12U)));
    text.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
    text.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
  }
}

const UnicodeLowercaseMapping *java_lowercase(std::uint16_t value) noexcept {
  const auto *first = std::begin(java_bmp_lowercase);
  const auto *last = std::end(java_bmp_lowercase);
  while (first != last) {
    const auto *middle = first + (last - first) / 2;
    if (middle->uppercase < value)
      first = middle + 1;
    else
      last = middle;
  }
  return first != std::end(java_bmp_lowercase) && first->uppercase == value
             ? first
             : nullptr;
}

std::string path_utf8(const std::filesystem::path &path) {
  const auto encoded = path.u8string();
  return {reinterpret_cast<const char *>(encoded.data()), encoded.size()};
}

std::filesystem::path path_from_utf8(std::string_view encoded) {
  std::u8string value;
  value.reserve(encoded.size());
  for (const unsigned char byte : encoded)
    value.push_back(static_cast<char8_t>(byte));
  return std::filesystem::path(value);
}

std::uint64_t process_id() noexcept {
#ifdef _WIN32
  return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(getpid());
#endif
}

std::filesystem::path clock_probe_path(const std::filesystem::path &directory) {
  return directory /
         path_from_utf8(
             ".llmghidra-clock-probe-" + std::to_string(process_id()) + "-" +
             std::to_string(clock_probe_sequence.fetch_add(1) + 1) + ".tmp");
}

using FileIdentity = std::array<std::uint64_t, 2>;
using FileWriteTime = std::array<std::int64_t, 2>;

struct LockSnapshot final {
  FileIdentity identity{};
  FileWriteTime write_time{};
  std::string owner_record;
  bool complete = false;
};

std::error_code hook_before(LockFileIoHooks *hooks, LockFileIoPhase phase,
                            LockFileIoOperation operation) noexcept {
  return hooks ? hooks->before({phase, operation}) : std::error_code{};
}

std::size_t hook_write_limit(LockFileIoHooks *hooks, LockFileIoPhase phase,
                             std::size_t requested) {
  return hooks ? (std::min)(requested,
                            hooks->write_limit(
                                {phase, LockFileIoOperation::write}, requested))
               : requested;
}

bool snapshot_matches(const LockSnapshot &snapshot,
                      const FileIdentity &identity,
                      const FileWriteTime &write_time,
                      std::string_view owner_record) noexcept {
  return snapshot.complete && snapshot.identity == identity &&
         snapshot.write_time == write_time &&
         snapshot.owner_record == owner_record;
}

#ifdef _WIN32
std::optional<LockSnapshot>
snapshot_handle(HANDLE handle, std::size_t byte_limit,
                LockFileIoHooks *hooks = nullptr,
                LockFileIoPhase phase = LockFileIoPhase::snapshot_read) {
  if (hook_before(hooks, phase, LockFileIoOperation::stat))
    return std::nullopt;
  BY_HANDLE_FILE_INFORMATION information{};
  if (!GetFileInformationByHandle(handle, &information))
    return std::nullopt;

  LARGE_INTEGER size{};
  if (!GetFileSizeEx(handle, &size) || size.QuadPart < 0)
    return std::nullopt;
  const auto unsigned_size = static_cast<std::uint64_t>(size.QuadPart);
  const auto read_size = static_cast<std::size_t>(
      (std::min)(unsigned_size, static_cast<std::uint64_t>(byte_limit)));

  LARGE_INTEGER beginning{};
  if (!SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN))
    return std::nullopt;
  std::string contents(read_size, '\0');
  std::size_t offset = 0;
  while (offset != contents.size()) {
    if (hook_before(hooks, phase, LockFileIoOperation::read))
      return std::nullopt;
    const auto chunk = static_cast<DWORD>((std::min)(
        contents.size() - offset,
        static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    DWORD count = 0;
    if (!ReadFile(handle, contents.data() + offset, chunk, &count, nullptr))
      return std::nullopt;
    if (count == 0)
      break;
    offset += count;
  }
  contents.resize(offset);

  ULARGE_INTEGER file_index{};
  file_index.HighPart = information.nFileIndexHigh;
  file_index.LowPart = information.nFileIndexLow;
  ULARGE_INTEGER modified{};
  modified.HighPart = information.ftLastWriteTime.dwHighDateTime;
  modified.LowPart = information.ftLastWriteTime.dwLowDateTime;
  return LockSnapshot{{information.dwVolumeSerialNumber, file_index.QuadPart},
                      {static_cast<std::int64_t>(modified.QuadPart), 0},
                      std::move(contents),
                      unsigned_size <= byte_limit};
}

std::optional<LockSnapshot>
read_snapshot(const std::filesystem::path &path, std::size_t byte_limit,
              LockFileIoHooks *hooks = nullptr,
              LockFileIoPhase phase = LockFileIoPhase::snapshot_read) {
  if (hook_before(hooks, phase, LockFileIoOperation::open))
    return std::nullopt;
  const HANDLE handle =
      CreateFileW(path.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    return std::nullopt;
  auto snapshot = snapshot_handle(handle, byte_limit, hooks, phase);
  const auto close_error =
      hook_before(hooks, phase, LockFileIoOperation::close);
  const bool close_ok = CloseHandle(handle) != 0;
  if (close_error || !close_ok)
    snapshot.reset();
  return snapshot;
}

std::int64_t native_now() noexcept {
  FILETIME now_file_time{};
  GetSystemTimeAsFileTime(&now_file_time);
  ULARGE_INTEGER now{};
  now.HighPart = now_file_time.dwHighDateTime;
  now.LowPart = now_file_time.dwLowDateTime;
  return static_cast<std::int64_t>(now.QuadPart);
}

std::int64_t snapshot_write_time_native(const LockSnapshot &snapshot) noexcept {
  return snapshot.write_time[0];
}

std::int64_t milliseconds_to_native(std::chrono::milliseconds value) noexcept {
  constexpr std::int64_t ticks_per_millisecond = 10000;
  return detail::saturated_multiply(value.count(), ticks_per_millisecond);
}

bool snapshot_is_stale(const LockSnapshot &snapshot,
                       std::chrono::milliseconds lease,
                       std::int64_t filesystem_clock_delta) noexcept {
  return detail::lock_timestamp_is_stale(
      snapshot_write_time_native(snapshot), native_now(),
      milliseconds_to_native(lease), filesystem_clock_delta);
}

std::optional<std::int64_t>
measure_filesystem_clock_delta(const std::filesystem::path &directory,
                               LockFileIoHooks *hooks) {
  constexpr int attempts = 32;
  for (int attempt = 0; attempt < attempts; ++attempt) {
    const auto path = clock_probe_path(directory);
    if (hook_before(hooks, LockFileIoPhase::clock_probe,
                    LockFileIoOperation::create))
      return std::nullopt;
    const HANDLE handle = CreateFileW(
        path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
      const auto error = GetLastError();
      if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)
        continue;
      return std::nullopt;
    }

    constexpr char marker = 0;
    DWORD written = 0;
    const auto write_error = hook_before(hooks, LockFileIoPhase::clock_probe,
                                         LockFileIoOperation::write);
    const auto write_size =
        hook_write_limit(hooks, LockFileIoPhase::clock_probe, 1);
    const bool write_ok = !write_error && write_size == 1 &&
                          WriteFile(handle, &marker, 1, &written, nullptr) &&
                          written == 1;
    const auto flush_error =
        write_ok ? hook_before(hooks, LockFileIoPhase::clock_probe,
                               LockFileIoOperation::flush)
                 : std::error_code{};
    const bool flush_ok = write_ok && !flush_error && FlushFileBuffers(handle);
    const auto snapshot =
        flush_ok
            ? snapshot_handle(handle, 0, hooks, LockFileIoPhase::clock_probe)
            : std::nullopt;
    const auto local_now = native_now();
    const auto remove_error = hook_before(hooks, LockFileIoPhase::clock_probe,
                                          LockFileIoOperation::remove);
    const auto close_error = hook_before(hooks, LockFileIoPhase::clock_probe,
                                         LockFileIoOperation::close);
    const bool close_ok =
        CloseHandle(handle) != 0 && !remove_error && !close_error;
    if (!snapshot || !close_ok)
      return std::nullopt;
    return detail::saturated_subtract(local_now,
                                      snapshot_write_time_native(*snapshot));
  }
  return std::nullopt;
}

bool delete_owned_path(const std::filesystem::path &path,
                       const FileIdentity &identity,
                       const FileWriteTime &write_time,
                       std::string_view owner_record,
                       LockFileIoHooks *hooks) noexcept {
  if (hook_before(hooks, LockFileIoPhase::owned_remove,
                  LockFileIoOperation::lock) ||
      hook_before(hooks, LockFileIoPhase::owned_remove,
                  LockFileIoOperation::open))
    return false;
  const HANDLE handle =
      CreateFileW(path.c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    return false;
  const auto snapshot = snapshot_handle(handle, owner_record.size() + 1, hooks,
                                        LockFileIoPhase::owned_remove);
  FILE_DISPOSITION_INFO disposition{TRUE};
  const bool removed =
      snapshot &&
      snapshot_matches(*snapshot, identity, write_time, owner_record) &&
      !hook_before(hooks, LockFileIoPhase::owned_remove,
                   LockFileIoOperation::remove) &&
      SetFileInformationByHandle(handle, FileDispositionInfo, &disposition,
                                 sizeof(disposition));
  const auto close_error = hook_before(hooks, LockFileIoPhase::owned_remove,
                                       LockFileIoOperation::close);
  const bool close_ok = CloseHandle(handle) != 0;
  return removed && !close_error && close_ok;
}

bool reclaim_stale_path(const std::filesystem::path &path,
                        const LockSnapshot &preliminary,
                        std::chrono::milliseconds lease,
                        std::int64_t filesystem_clock_delta,
                        LockFileIoHooks *hooks) noexcept {
  if (!snapshot_is_stale(preliminary, lease, filesystem_clock_delta))
    return false;
  if (hook_before(hooks, LockFileIoPhase::stale_reclaim,
                  LockFileIoOperation::lock) ||
      hook_before(hooks, LockFileIoPhase::stale_reclaim,
                  LockFileIoOperation::open))
    return false;
  const HANDLE handle =
      CreateFileW(path.c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    return false;
  const auto snapshot =
      snapshot_handle(handle, 0, hooks, LockFileIoPhase::stale_reclaim);
  FILE_DISPOSITION_INFO disposition{TRUE};
  const bool removed =
      snapshot && snapshot_is_stale(*snapshot, lease, filesystem_clock_delta) &&
      !hook_before(hooks, LockFileIoPhase::stale_reclaim,
                   LockFileIoOperation::remove) &&
      SetFileInformationByHandle(handle, FileDispositionInfo, &disposition,
                                 sizeof(disposition));
  (void)hook_before(hooks, LockFileIoPhase::stale_reclaim,
                    LockFileIoOperation::close);
  const bool close_ok = CloseHandle(handle) != 0;
  // Once delete disposition has been committed and the real close succeeds,
  // the path is gone even if the fault seam reports a close error.  Treating
  // that injected report as a failed reclaim would strand acquire_once() after
  // it has already removed the stale owner.
  return removed && close_ok;
}

std::string wide_to_utf8(std::wstring_view value) {
  if (value.empty())
    return {};
  if (value.size() >
      static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    return {};
  const int required = WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (required <= 0)
    return {};
  std::string encoded(static_cast<std::size_t>(required), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), encoded.data(),
                          required, nullptr, nullptr) != required) {
    return {};
  }
  return encoded;
}

std::string windows_environment_utf8(const wchar_t *name) {
  const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
  if (required == 0)
    return {};
  std::wstring value(required, L'\0');
  const DWORD length = GetEnvironmentVariableW(name, value.data(), required);
  if (length == 0 || length >= required)
    return {};
  value.resize(length);
  return wide_to_utf8(value);
}
#else
FileIdentity identity_from_stat(const struct stat &status) noexcept {
  return {static_cast<std::uint64_t>(status.st_dev),
          static_cast<std::uint64_t>(status.st_ino)};
}

FileWriteTime write_time_from_stat(const struct stat &status) noexcept {
#if defined(__APPLE__)
  return {static_cast<std::int64_t>(status.st_mtimespec.tv_sec),
          static_cast<std::int64_t>(status.st_mtimespec.tv_nsec)};
#else
  return {static_cast<std::int64_t>(status.st_mtim.tv_sec),
          static_cast<std::int64_t>(status.st_mtim.tv_nsec)};
#endif
}

std::optional<LockSnapshot>
snapshot_descriptor(int descriptor, std::size_t byte_limit,
                    LockFileIoHooks *hooks = nullptr,
                    LockFileIoPhase phase = LockFileIoPhase::snapshot_read) {
  if (hook_before(hooks, phase, LockFileIoOperation::stat))
    return std::nullopt;
  struct stat status {};
  if (::fstat(descriptor, &status) != 0 || status.st_size < 0)
    return std::nullopt;
  const auto unsigned_size = static_cast<std::uint64_t>(status.st_size);
  const auto read_size = static_cast<std::size_t>(
      (std::min)(unsigned_size, static_cast<std::uint64_t>(byte_limit)));
  std::string contents(read_size, '\0');
  std::size_t offset = 0;
  while (offset != contents.size()) {
    if (hook_before(hooks, phase, LockFileIoOperation::read))
      return std::nullopt;
    const auto count =
        ::pread(descriptor, contents.data() + offset, contents.size() - offset,
                static_cast<off_t>(offset));
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      break;
    offset += static_cast<std::size_t>(count);
  }
  contents.resize(offset);
  return LockSnapshot{identity_from_stat(status), write_time_from_stat(status),
                      std::move(contents), unsigned_size <= byte_limit};
}

int open_lock_path(const std::filesystem::path &path, int access) noexcept {
  int flags = access;
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  return ::open(path.c_str(), flags);
}

std::optional<LockSnapshot>
read_snapshot(const std::filesystem::path &path, std::size_t byte_limit,
              LockFileIoHooks *hooks = nullptr,
              LockFileIoPhase phase = LockFileIoPhase::snapshot_read) {
  if (hook_before(hooks, phase, LockFileIoOperation::open))
    return std::nullopt;
  const int descriptor = open_lock_path(path, O_RDONLY);
  if (descriptor < 0)
    return std::nullopt;
  auto snapshot = snapshot_descriptor(descriptor, byte_limit, hooks, phase);
  const auto close_error =
      hook_before(hooks, phase, LockFileIoOperation::close);
  const bool close_ok = ::close(descriptor) == 0;
  if (close_error || !close_ok)
    snapshot.reset();
  return snapshot;
}

bool path_has_identity(const std::filesystem::path &path,
                       const FileIdentity &identity) noexcept {
  struct stat status {};
  return ::lstat(path.c_str(), &status) == 0 &&
         identity_from_stat(status) == identity;
}

std::int64_t native_now() noexcept {
  const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  return now;
}

std::int64_t snapshot_write_time_native(const LockSnapshot &snapshot) noexcept {
  constexpr std::int64_t nanoseconds_per_second = 1000000000;
  return detail::saturated_add(
      detail::saturated_multiply(snapshot.write_time[0],
                                 nanoseconds_per_second),
      snapshot.write_time[1]);
}

std::int64_t milliseconds_to_native(std::chrono::milliseconds value) noexcept {
  constexpr std::int64_t nanoseconds_per_millisecond = 1000000;
  return detail::saturated_multiply(value.count(), nanoseconds_per_millisecond);
}

bool snapshot_is_stale(const LockSnapshot &snapshot,
                       std::chrono::milliseconds lease,
                       std::int64_t filesystem_clock_delta) noexcept {
  return detail::lock_timestamp_is_stale(
      snapshot_write_time_native(snapshot), native_now(),
      milliseconds_to_native(lease), filesystem_clock_delta);
}

std::optional<std::int64_t>
measure_filesystem_clock_delta(const std::filesystem::path &directory,
                               LockFileIoHooks *hooks) {
  constexpr int attempts = 32;
  for (int attempt = 0; attempt < attempts; ++attempt) {
    const auto path = clock_probe_path(directory);
    if (hook_before(hooks, LockFileIoPhase::clock_probe,
                    LockFileIoOperation::create))
      return std::nullopt;
    int flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags, 0600);
    if (descriptor < 0) {
      if (errno == EEXIST)
        continue;
      return std::nullopt;
    }

    constexpr char marker = 0;
    ssize_t written = -1;
    const auto write_error = hook_before(hooks, LockFileIoPhase::clock_probe,
                                         LockFileIoOperation::write);
    const auto write_size =
        hook_write_limit(hooks, LockFileIoPhase::clock_probe, 1);
    if (!write_error && write_size != 0) {
      do {
        written = ::pwrite(descriptor, &marker, write_size, 0);
      } while (written < 0 && errno == EINTR);
    }
    const bool write_ok = written == 1;
    const auto flush_error =
        write_ok ? hook_before(hooks, LockFileIoPhase::clock_probe,
                               LockFileIoOperation::flush)
                 : std::error_code{};
    const bool flush_ok = write_ok && !flush_error && ::fsync(descriptor) == 0;
    const auto snapshot =
        flush_ok ? snapshot_descriptor(descriptor, 0, hooks,
                                       LockFileIoPhase::clock_probe)
                 : std::nullopt;
    const auto local_now = native_now();
    const auto remove_error = hook_before(hooks, LockFileIoPhase::clock_probe,
                                          LockFileIoOperation::remove);
    const bool removed = !remove_error && ::unlink(path.c_str()) == 0;
    const auto close_error = hook_before(hooks, LockFileIoPhase::clock_probe,
                                         LockFileIoOperation::close);
    const bool close_ok = ::close(descriptor) == 0 && !close_error;
    if (!removed)
      (void)::unlink(path.c_str());
    if (!snapshot || !removed || !close_ok)
      return std::nullopt;
    return detail::saturated_subtract(local_now,
                                      snapshot_write_time_native(*snapshot));
  }
  return std::nullopt;
}

bool delete_owned_path(const std::filesystem::path &path,
                       const FileIdentity &identity,
                       const FileWriteTime &write_time,
                       std::string_view owner_record,
                       LockFileIoHooks *hooks) noexcept {
  if (hook_before(hooks, LockFileIoPhase::owned_remove,
                  LockFileIoOperation::open))
    return false;
  const int descriptor = open_lock_path(path, O_RDONLY);
  const auto lock_error = hook_before(hooks, LockFileIoPhase::owned_remove,
                                      LockFileIoOperation::lock);
  if (descriptor < 0 || lock_error ||
      ::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    if (descriptor >= 0)
      ::close(descriptor);
    return false;
  }
  const auto snapshot =
      snapshot_descriptor(descriptor, owner_record.size() + 1, hooks,
                          LockFileIoPhase::owned_remove);
  const auto remove_error = hook_before(hooks, LockFileIoPhase::owned_remove,
                                        LockFileIoOperation::remove);
  const bool removed =
      snapshot &&
      snapshot_matches(*snapshot, identity, write_time, owner_record) &&
      path_has_identity(path, identity) && !remove_error &&
      ::unlink(path.c_str()) == 0;
  ::flock(descriptor, LOCK_UN);
  const auto close_error = hook_before(hooks, LockFileIoPhase::owned_remove,
                                       LockFileIoOperation::close);
  const bool close_ok = ::close(descriptor) == 0;
  return removed && !close_error && close_ok;
}

bool reclaim_stale_path(const std::filesystem::path &path,
                        const LockSnapshot &preliminary,
                        std::chrono::milliseconds lease,
                        std::int64_t filesystem_clock_delta,
                        LockFileIoHooks *hooks) noexcept {
  if (!snapshot_is_stale(preliminary, lease, filesystem_clock_delta))
    return false;
  if (hook_before(hooks, LockFileIoPhase::stale_reclaim,
                  LockFileIoOperation::open))
    return false;
  const int descriptor = open_lock_path(path, O_RDONLY);
  const auto lock_error = hook_before(hooks, LockFileIoPhase::stale_reclaim,
                                      LockFileIoOperation::lock);
  if (descriptor < 0 || lock_error ||
      ::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    if (descriptor >= 0)
      ::close(descriptor);
    return false;
  }
  const auto snapshot =
      snapshot_descriptor(descriptor, 0, hooks, LockFileIoPhase::stale_reclaim);
  const auto remove_error = hook_before(hooks, LockFileIoPhase::stale_reclaim,
                                        LockFileIoOperation::remove);
  const bool removed =
      snapshot && snapshot_is_stale(*snapshot, lease, filesystem_clock_delta) &&
      path_has_identity(path, snapshot->identity) && !remove_error &&
      ::unlink(path.c_str()) == 0;
  ::flock(descriptor, LOCK_UN);
  (void)hook_before(hooks, LockFileIoPhase::stale_reclaim,
                    LockFileIoOperation::close);
  const bool close_ok = ::close(descriptor) == 0;
  // unlink() has already removed this exact inode from the namespace.  The
  // hook still observes the close point and the real descriptor is always
  // closed, but an injected close report must not turn the committed reclaim
  // into a false failure.
  return removed && close_ok;
}
#endif

std::string current_user() {
#ifdef _WIN32
  auto user = windows_environment_utf8(L"USERNAME");
  if (!user.empty())
    return user;
#else
  if (const auto *value = std::getenv("USER"); value && *value) {
    return value;
  }
#endif
  return "<Unknown>";
}

void require_valid_options(const LockFileOptions &options) {
  if (options.maximum_lease <= std::chrono::milliseconds::zero() ||
      options.renewal_period <= std::chrono::milliseconds::zero() ||
      options.renewal_period >= options.maximum_lease ||
      options.default_timeout < std::chrono::milliseconds::zero() ||
      options.poll_interval <= std::chrono::milliseconds::zero()) {
    throw std::invalid_argument("invalid lock file timing options");
  }
}

bool has_lock_suffix(std::string_view file_name,
                     std::string_view mangled_name) {
  if (!file_name.starts_with(mangled_name) || !file_name.ends_with("lock")) {
    return false;
  }
  const auto middle = file_name.substr(
      mangled_name.size(), file_name.size() - mangled_name.size() - 4);
  return !middle.empty() && middle.front() == '.' &&
         middle.find('.', 1) == std::string_view::npos;
}

bool has_any_lock(const std::filesystem::path &directory,
                  std::string_view name_prefix) {
  std::error_code error;
  std::filesystem::directory_iterator iterator(directory, error);
  if (error)
    return false;
  for (const auto &entry : iterator) {
    if (entry.is_regular_file(error) && !error &&
        has_lock_suffix(path_utf8(entry.path().filename()), name_prefix)) {
      return true;
    }
    error.clear();
  }
  return false;
}

bool exclusive_create_contention(const std::error_code &error) noexcept {
  if (error == std::errc::file_exists)
    return true;
#ifdef _WIN32
  if (error.category() == std::system_category()) {
    switch (static_cast<DWORD>(error.value())) {
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_DELETE_PENDING:
      return true;
    default:
      break;
    }
  }
#endif
  return false;
}

} // namespace

LockFile::LockFile(std::filesystem::path directory, std::string name,
                   std::string lock_type, LockFileOptions options)
    : options_(options) {
  require_valid_options(options_);
  if (options_.filesystem_clock_delta) {
    filesystem_clock_delta_ =
        milliseconds_to_native(*options_.filesystem_clock_delta);
    filesystem_clock_delta_valid_ = true;
  }
  if (lock_type.find('.') != std::string::npos) {
    throw std::invalid_argument("lock type may not contain '.'");
  }
  if (name.empty())
    throw std::invalid_argument("lock name is empty");
  const auto file_name =
      mangle_name(name) + "." + std::move(lock_type) + "lock";
  path_ = std::move(directory) / path_from_utf8(file_name);
}

LockFile::LockFile(std::filesystem::path controlled_file,
                   LockFileOptions options)
    : path_(controlled_file), options_(options) {
  require_valid_options(options_);
  if (options_.filesystem_clock_delta) {
    filesystem_clock_delta_ =
        milliseconds_to_native(*options_.filesystem_clock_delta);
    filesystem_clock_delta_valid_ = true;
  }
  if (controlled_file.filename().empty()) {
    throw std::invalid_argument("controlled file has no name");
  }
  path_ += ".lock";
}

LockFile::~LockFile() { dispose(); }

std::string LockFile::mangle_name(std::string_view name) {
  std::string mangled;
  mangled.reserve(name.size() * 2);
  for (std::size_t offset = 0; offset < name.size();) {
    const auto decoded = decode_utf8(name, offset);
    if (decoded.value == '_') {
      mangled += "__";
    } else if (decoded.value <= 0xffffU) {
      const auto *mapping =
          java_lowercase(static_cast<std::uint16_t>(decoded.value));
      if (!mapping) {
        mangled.append(name.substr(offset, decoded.length));
        offset += decoded.length;
        continue;
      }
      mangled.push_back('_');
      append_utf8(mangled, mapping->lowercase);
    } else {
      // NamingUtilities iterates UTF-16 char values rather than code points.
      // Both surrogates of a supplementary character are therefore preserved.
      mangled.append(name.substr(offset, decoded.length));
    }
    offset += decoded.length;
  }
  return mangled;
}

bool LockFile::is_locked(const std::filesystem::path &directory,
                         std::string_view name) {
  return has_any_lock(directory, mangle_name(name));
}

bool LockFile::is_locked(const std::filesystem::path &controlled_file) {
  return has_any_lock(controlled_file.parent_path(),
                      path_utf8(controlled_file.filename()));
}

bool LockFile::contains_lock(const std::filesystem::path &directory) {
  std::error_code error;
  std::filesystem::recursive_directory_iterator iterator(
      directory, std::filesystem::directory_options::skip_permission_denied,
      error);
  if (error)
    return false;
  for (const auto &entry : iterator) {
    if (entry.is_symlink(error)) {
      if (entry.is_directory(error))
        iterator.disable_recursion_pending();
      error.clear();
      continue;
    }
    if (entry.is_regular_file(error) && !error &&
        path_utf8(entry.path().filename()).ends_with("lock")) {
      return true;
    }
    error.clear();
  }
  return false;
}

std::size_t LockFile::lock_count() const noexcept {
  std::lock_guard guard(mutex_);
  return lock_count_;
}

bool LockFile::have_lock() { return have_lock(false); }

bool LockFile::have_lock(bool verify) {
  std::lock_guard guard(mutex_);
  if (lock_count_ == 0)
    return false;
  return !verify || verify_locked();
}

bool LockFile::verify_locked() {
  if (lock_count_ == 0 || !ownership_snapshot_valid_)
    return false;
  const auto snapshot =
      read_snapshot(path_, owned_record_.size() + 1, options_.io_hooks.get());
  if (!snapshot || !snapshot_matches(*snapshot, owned_identity_,
                                     owned_write_time_, owned_record_)) {
    clear_ownership_locked();
    return false;
  }
  return true;
}

std::string LockFile::lock_owner() const {
  // The fixed Java implementation renews with truncate-and-rewrite. A reader
  // can observe the interval before owner bytes are written, so retry that
  // transient empty read without hiding persistent failures.
  constexpr int attempts = 51;
  for (int attempt = 0; attempt < attempts; ++attempt) {
    const auto snapshot = read_snapshot(path_, 32, options_.io_hooks.get());
    if (snapshot && !snapshot->owner_record.empty()) {
      auto owner = snapshot->owner_record;
      const auto space = owner.find(' ');
      if (space != std::string::npos && space != 0)
        owner.resize(space);
      return owner;
    }
    if (attempt + 1 != attempts)
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return "<Unknown>";
}

std::string LockFile::owner_record() const {
  return current_user() + " " + std::to_string(process_id()) + ":" +
         std::to_string(owner_sequence.fetch_add(1) + 1);
}

void LockFile::write_owner(bool exclusive_create) {
  const auto record = owner_record();
  const auto phase = exclusive_create ? LockFileIoPhase::owner_create
                                      : LockFileIoPhase::owner_renew;
  auto *hooks = options_.io_hooks.get();
  std::optional<LockSnapshot> written_snapshot;
#ifdef _WIN32
  const auto disposition = exclusive_create ? CREATE_NEW : OPEN_EXISTING;
  const auto open_operation = exclusive_create ? LockFileIoOperation::create
                                               : LockFileIoOperation::open;
  if (const auto error = hook_before(hooks, phase, open_operation); error) {
    throw std::filesystem::filesystem_error("injected lock open failure", path_,
                                            error);
  }
  const auto desired_access =
      GENERIC_READ | GENERIC_WRITE | (exclusive_create ? DELETE : 0);
  const HANDLE handle = CreateFileW(
      path_.c_str(), desired_access, FILE_SHARE_READ | FILE_SHARE_DELETE,
      nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const auto error = GetLastError();
    if (exclusive_create &&
        (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)) {
      throw std::filesystem::filesystem_error(
          "lock file already exists", path_,
          std::error_code(static_cast<int>(error), std::system_category()));
    }
    throw std::filesystem::filesystem_error(
        "unable to open lock file", path_,
        std::error_code(static_cast<int>(error), std::system_category()));
  }
  if (const auto error = hook_before(hooks, phase, LockFileIoOperation::lock);
      error) {
    if (exclusive_create &&
        !hook_before(hooks, phase, LockFileIoOperation::remove)) {
      FILE_DISPOSITION_INFO disposition_info{TRUE};
      (void)SetFileInformationByHandle(handle, FileDispositionInfo,
                                       &disposition_info,
                                       sizeof(disposition_info));
    }
    (void)CloseHandle(handle);
    throw std::filesystem::filesystem_error("injected lock failure", path_,
                                            error);
  }
  if (!exclusive_create) {
    const auto current =
        snapshot_handle(handle, owned_record_.size() + 1, hooks, phase);
    if (!current || !snapshot_matches(*current, owned_identity_,
                                      owned_write_time_, owned_record_)) {
      CloseHandle(handle);
      throw std::filesystem::filesystem_error(
          "lock ownership changed before renewal", path_,
          std::make_error_code(std::errc::state_not_recoverable));
    }
  }
  LARGE_INTEGER beginning{};
  DWORD written = 0;
  std::error_code operation_error;
  const auto write_error =
      hook_before(hooks, phase, LockFileIoOperation::write);
  const auto write_size = hook_write_limit(hooks, phase, record.size());
  std::error_code pointer_error;
  bool pointer_ok = false;
  if (record.size() > (std::numeric_limits<DWORD>::max)()) {
    pointer_error =
        std::error_code(ERROR_ARITHMETIC_OVERFLOW, std::system_category());
  } else if (SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN)) {
    pointer_ok = true;
  } else {
    pointer_error = std::error_code(static_cast<int>(GetLastError()),
                                    std::system_category());
  }
  std::error_code native_write_error;
  bool write_call_ok = false;
  if (!write_error && pointer_ok) {
    write_call_ok =
        WriteFile(handle, record.data(), static_cast<DWORD>(write_size),
                  &written, nullptr) != 0;
    if (!write_call_ok) {
      native_write_error = std::error_code(static_cast<int>(GetLastError()),
                                           std::system_category());
    }
  }
  const bool complete_write =
      write_call_ok && written == record.size() && write_size == record.size();
  if (write_error)
    operation_error = write_error;
  else if (!pointer_ok)
    operation_error = pointer_error;
  else if (!write_call_ok)
    operation_error = native_write_error;
  else if (!complete_write)
    operation_error =
        std::error_code(ERROR_WRITE_FAULT, std::system_category());

  const auto truncate_error =
      complete_write ? hook_before(hooks, phase, LockFileIoOperation::truncate)
                     : std::error_code{};
  const bool truncate_ok =
      complete_write && !truncate_error && SetEndOfFile(handle);
  if (truncate_error)
    operation_error = truncate_error;
  else if (complete_write && !truncate_ok)
    operation_error = std::error_code(static_cast<int>(GetLastError()),
                                      std::system_category());

  const auto flush_error =
      truncate_ok ? hook_before(hooks, phase, LockFileIoOperation::flush)
                  : std::error_code{};
  const bool flush_ok = truncate_ok && !flush_error && FlushFileBuffers(handle);
  if (flush_error)
    operation_error = flush_error;
  else if (truncate_ok && !flush_ok)
    operation_error = std::error_code(static_cast<int>(GetLastError()),
                                      std::system_category());
  if (flush_ok)
    written_snapshot = snapshot_handle(handle, record.size() + 1, hooks, phase);
  bool content_ok = written_snapshot && written_snapshot->complete &&
                    written_snapshot->owner_record == record;
  if (!content_ok && flush_ok && !operation_error) {
    operation_error =
        std::error_code(ERROR_WRITE_FAULT, std::system_category());
  }

  const auto close_error =
      hook_before(hooks, phase, LockFileIoOperation::close);
  bool cleanup_marked = false;
  if (exclusive_create && (!content_ok || close_error)) {
    FILE_DISPOSITION_INFO disposition_info{TRUE};
    cleanup_marked =
        !hook_before(hooks, phase, LockFileIoOperation::remove) &&
        SetFileInformationByHandle(handle, FileDispositionInfo,
                                   &disposition_info, sizeof(disposition_info));
  }
  const bool native_close_ok = CloseHandle(handle) != 0;
  const bool close_ok = native_close_ok && !close_error;
  if (close_error)
    operation_error = close_error;
  else if (!native_close_ok)
    operation_error = std::error_code(static_cast<int>(GetLastError()),
                                      std::system_category());

  if (content_ok && close_ok) {
    const auto final_snapshot =
        read_snapshot(path_, record.size() + 1, hooks, phase);
    if (final_snapshot &&
        final_snapshot->identity == written_snapshot->identity &&
        final_snapshot->complete && final_snapshot->owner_record == record) {
      written_snapshot = final_snapshot;
    } else {
      const auto failed_snapshot = written_snapshot;
      written_snapshot.reset();
      operation_error =
          std::error_code(ERROR_WRITE_FAULT, std::system_category());
      if (exclusive_create && failed_snapshot && !cleanup_marked) {
        (void)delete_owned_path(path_, failed_snapshot->identity,
                                failed_snapshot->write_time, record, hooks);
      }
    }
  }
  if (!content_ok || !flush_ok || !written_snapshot || !close_ok) {
    if (!operation_error)
      operation_error =
          std::error_code(ERROR_WRITE_FAULT, std::system_category());
    throw std::filesystem::filesystem_error("unable to write lock owner", path_,
                                            operation_error);
  }
#else
  const auto open_operation = exclusive_create ? LockFileIoOperation::create
                                               : LockFileIoOperation::open;
  if (const auto error = hook_before(hooks, phase, open_operation); error) {
    throw std::filesystem::filesystem_error("injected lock open failure", path_,
                                            error);
  }
  int descriptor = -1;
  if (exclusive_create) {
    int flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    descriptor = ::open(path_.c_str(), flags, 0666);
  } else {
    descriptor = open_lock_path(path_, O_RDWR);
  }
  if (descriptor < 0) {
    throw std::filesystem::filesystem_error(
        exclusive_create ? "unable to create lock file"
                         : "unable to renew lock file",
        path_, std::error_code(errno, std::generic_category()));
  }
  std::optional<FileIdentity> created_identity;
  if (exclusive_create) {
    struct stat status {};
    if (::fstat(descriptor, &status) == 0)
      created_identity = identity_from_stat(status);
  }
  const auto lock_error = hook_before(hooks, phase, LockFileIoOperation::lock);
  if (lock_error || ::flock(descriptor, LOCK_EX) != 0) {
    const auto error = errno;
    if (exclusive_create && created_identity &&
        path_has_identity(path_, *created_identity) &&
        !hook_before(hooks, phase, LockFileIoOperation::remove)) {
      (void)::unlink(path_.c_str());
    }
    ::close(descriptor);
    throw std::filesystem::filesystem_error(
        "unable to lock owner record", path_,
        lock_error ? lock_error
                   : std::error_code(error, std::generic_category()));
  }

  const auto cleanup_created = [&] {
    if (exclusive_create && created_identity &&
        path_has_identity(path_, *created_identity) &&
        !hook_before(hooks, phase, LockFileIoOperation::remove)) {
      (void)::unlink(path_.c_str());
    }
  };
  const auto fail = [&](std::string_view message, std::error_code error) {
    cleanup_created();
    (void)::flock(descriptor, LOCK_UN);
    (void)::close(descriptor);
    throw std::filesystem::filesystem_error(std::string(message), path_, error);
  };

  if (!exclusive_create) {
    const auto current =
        snapshot_descriptor(descriptor, owned_record_.size() + 1, hooks, phase);
    if (!current || !snapshot_matches(*current, owned_identity_,
                                      owned_write_time_, owned_record_)) {
      fail("lock ownership changed before renewal",
           std::make_error_code(std::errc::state_not_recoverable));
    }
  }
  std::size_t offset = 0;
  while (offset != record.size()) {
    if (const auto error =
            hook_before(hooks, phase, LockFileIoOperation::write);
        error) {
      fail("unable to write lock owner", error);
    }
    const auto request = hook_write_limit(hooks, phase, record.size() - offset);
    if (request == 0) {
      fail("unable to write lock owner",
           std::make_error_code(std::errc::io_error));
    }
    const auto written = ::pwrite(descriptor, record.data() + offset, request,
                                  static_cast<off_t>(offset));
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0) {
      fail("unable to write lock owner",
           written == 0 ? std::make_error_code(std::errc::io_error)
                        : std::error_code(errno, std::generic_category()));
    }
    offset += static_cast<std::size_t>(written);
  }
  if (const auto error =
          hook_before(hooks, phase, LockFileIoOperation::truncate);
      error) {
    fail("unable to truncate lock owner", error);
  }
  if (::ftruncate(descriptor, static_cast<off_t>(record.size())) != 0) {
    fail("unable to truncate lock owner",
         std::error_code(errno, std::generic_category()));
  }
  if (const auto error = hook_before(hooks, phase, LockFileIoOperation::flush);
      error) {
    fail("unable to flush lock owner", error);
  }
  if (::fsync(descriptor) != 0) {
    fail("unable to flush lock owner",
         std::error_code(errno, std::generic_category()));
  }
  written_snapshot =
      snapshot_descriptor(descriptor, record.size() + 1, hooks, phase);
  if (!written_snapshot || !written_snapshot->complete ||
      written_snapshot->owner_record != record) {
    fail("unable to inspect written lock owner",
         std::make_error_code(std::errc::io_error));
  }
  if (const auto error = hook_before(hooks, phase, LockFileIoOperation::close);
      error) {
    fail("unable to close written lock owner", error);
  }
  (void)::flock(descriptor, LOCK_UN);
  if (::close(descriptor) != 0) {
    const auto error = std::error_code(errno, std::generic_category());
    cleanup_created();
    throw std::filesystem::filesystem_error(
        "unable to close written lock owner", path_, error);
  }
  const auto final_snapshot =
      read_snapshot(path_, record.size() + 1, hooks, phase);
  if (!final_snapshot ||
      final_snapshot->identity != written_snapshot->identity ||
      !final_snapshot->complete || final_snapshot->owner_record != record) {
    cleanup_created();
    throw std::filesystem::filesystem_error(
        "unable to verify written lock owner", path_,
        std::make_error_code(std::errc::io_error));
  }
  written_snapshot = final_snapshot;
#endif
  owned_identity_ = written_snapshot->identity;
  owned_write_time_ = written_snapshot->write_time;
  owned_record_ = record;
  ownership_snapshot_valid_ = true;
}

bool LockFile::reclaim_stale_lock() {
  // Match Java LockFile's lazy deltaTime calibration: do not create a probe
  // while the uncontended exclusive-create path is available.
  const auto preliminary = read_snapshot(path_, 0, options_.io_hooks.get(),
                                         LockFileIoPhase::stale_reclaim);
  if (!preliminary)
    return false;
  if (!filesystem_clock_delta_valid_) {
    const auto measured = measure_filesystem_clock_delta(
        path_.parent_path(), options_.io_hooks.get());
    if (!measured)
      return false;
    filesystem_clock_delta_ = *measured;
    filesystem_clock_delta_valid_ = true;
  }
  return reclaim_stale_path(path_, *preliminary, options_.maximum_lease,
                            filesystem_clock_delta_, options_.io_hooks.get());
}

bool LockFile::acquire_once(bool remove_stale) {
  if (remove_stale)
    (void)reclaim_stale_lock();
  try {
    write_owner(true);
    lock_count_ = 1;
    return true;
  } catch (const std::filesystem::filesystem_error &error) {
    if (exclusive_create_contention(error.code()))
      return false;
    throw;
  }
}

bool LockFile::renew_locked() {
  if (!verify_locked())
    return false;
  try {
    write_owner(false);
    return true;
  } catch (...) {
    clear_ownership_locked();
    return false;
  }
}

bool LockFile::remove_owned_file() noexcept {
  if (!ownership_snapshot_valid_)
    return false;
  return delete_owned_path(path_, owned_identity_, owned_write_time_,
                           owned_record_, options_.io_hooks.get());
}

void LockFile::clear_ownership_locked() noexcept {
  lock_count_ = 0;
  ownership_snapshot_valid_ = false;
  owned_identity_ = {};
  owned_write_time_ = {};
  owned_record_.clear();
  hold_enabled_ = false;
  condition_.notify_all();
}

void LockFile::start_hold_locked() {
  hold_enabled_ = true;
  condition_.notify_all();
  if (hold_thread_.joinable())
    return;
  const auto generation = hold_generation_;
  hold_thread_ = std::thread([this, generation] {
    std::unique_lock lock(mutex_);
    while (generation == hold_generation_) {
      if (!hold_enabled_ || lock_count_ == 0) {
        condition_.wait(lock, [this, generation] {
          return generation != hold_generation_ ||
                 (hold_enabled_ && lock_count_ != 0);
        });
        continue;
      }
      if (condition_.wait_for(lock, options_.renewal_period,
                              [this, generation] {
                                return generation != hold_generation_ ||
                                       !hold_enabled_ || lock_count_ == 0;
                              })) {
        continue;
      }
      if (!renew_locked())
        hold_enabled_ = false;
    }
  });
}

std::thread LockFile::take_hold_thread_locked() noexcept {
  ++hold_generation_;
  hold_enabled_ = false;
  condition_.notify_all();
  return std::move(hold_thread_);
}

bool LockFile::create_lock() {
  return create_lock(options_.default_timeout, false);
}

bool LockFile::create_lock(std::chrono::milliseconds timeout, bool hold) {
  if (timeout < std::chrono::milliseconds::zero()) {
    throw std::invalid_argument("lock timeout is negative");
  }
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    {
      std::lock_guard guard(mutex_);
      if (lock_count_ != 0 && renew_locked()) {
        ++lock_count_;
        if (hold)
          start_hold_locked();
        return true;
      }
      if (acquire_once(true)) {
        if (hold)
          start_hold_locked();
        return true;
      }
    }
    if (timeout == std::chrono::milliseconds::zero() ||
        std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
    std::this_thread::sleep_for((std::min)(options_.poll_interval, remaining));
  }
}

void LockFile::remove_lock() noexcept {
  std::thread thread;
  {
    std::lock_guard guard(mutex_);
    if (!verify_locked())
      return;
    --lock_count_;
    if (lock_count_ != 0)
      return;
    for (int attempt = 0; attempt < 3; ++attempt) {
      if (remove_owned_file())
        break;
    }
    clear_ownership_locked();
    thread = take_hold_thread_locked();
  }
  if (thread.joinable())
    thread.join();
}

void LockFile::dispose() noexcept {
  std::thread thread;
  {
    std::lock_guard guard(mutex_);
    if (lock_count_ != 0 && verify_locked()) {
      for (int attempt = 0; attempt < 3; ++attempt) {
        if (remove_owned_file())
          break;
      }
    }
    clear_ownership_locked();
    thread = take_hold_thread_locked();
  }
  if (thread.joinable())
    thread.join();
}

} // namespace llmghidra::db
