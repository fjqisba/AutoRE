/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/file_operations.hpp"

#include <algorithm>
#include <cerrno>
#include <exception>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#else
#include <fcntl.h>
#include <stdio.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace llmghidra::db {
namespace {

[[noreturn]] void throw_file_error(std::string_view operation,
                                   const std::filesystem::path &path,
                                   std::error_code error) {
  throw std::filesystem::filesystem_error(std::string(operation), path,
                                          std::move(error));
}

#ifdef _WIN32

std::error_code last_file_error() {
  return {static_cast<int>(GetLastError()), std::system_category()};
}

class NativeRandomAccessFile final : public RandomAccessFile {
public:
  NativeRandomAccessFile(std::filesystem::path path, RandomAccessOpenMode mode)
      : path_(std::move(path)) {
    const bool read_only = mode == RandomAccessOpenMode::read_only;
    const DWORD access = read_only ? GENERIC_READ
                                   : GENERIC_READ | GENERIC_WRITE | DELETE;
    const DWORD sharing =
        read_only ? FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                  : FILE_SHARE_READ | FILE_SHARE_DELETE;
    const DWORD disposition =
        mode == RandomAccessOpenMode::create_new ? CREATE_NEW : OPEN_EXISTING;
    handle_ =
        CreateFileW(path_.c_str(), access, sharing, nullptr, disposition,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE)
      throw_file_error("unable to open random-access file", path_,
                       last_file_error());
  }

  ~NativeRandomAccessFile() override {
    if (is_open())
      CloseHandle(handle_);
  }

  [[nodiscard]] bool is_open() const noexcept override {
    return handle_ != INVALID_HANDLE_VALUE;
  }

  [[nodiscard]] std::uint64_t size() override {
    require_open();
    LARGE_INTEGER value{};
    if (!GetFileSizeEx(handle_, &value) || value.QuadPart < 0)
      throw_file_error("unable to inspect random-access file size", path_,
                       last_file_error());
    return static_cast<std::uint64_t>(value.QuadPart);
  }

  void seek(std::uint64_t offset) override {
    require_open();
    if (offset > static_cast<std::uint64_t>(
                     (std::numeric_limits<std::int64_t>::max)())) {
      throw std::overflow_error("random-access file offset is too large");
    }
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle_, position, nullptr, FILE_BEGIN))
      throw_file_error("unable to seek random-access file", path_,
                       last_file_error());
  }

  [[nodiscard]] std::size_t read(std::span<std::uint8_t> destination) override {
    require_open();
    if (destination.empty())
      return 0;
    const auto count = static_cast<DWORD>((std::min)(
        destination.size(),
        static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    DWORD transferred = 0;
    if (!ReadFile(handle_, destination.data(), count, &transferred, nullptr))
      throw_file_error("unable to read random-access file", path_,
                       last_file_error());
    return transferred;
  }

  [[nodiscard]] std::size_t
  write(std::span<const std::uint8_t> source) override {
    require_open();
    if (source.empty())
      return 0;
    const auto count = static_cast<DWORD>((std::min)(
        source.size(),
        static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
    DWORD transferred = 0;
    if (!WriteFile(handle_, source.data(), count, &transferred, nullptr))
      throw_file_error("unable to write random-access file", path_,
                       last_file_error());
    return transferred;
  }

  void truncate(std::uint64_t length) override {
    require_open();
    LARGE_INTEGER current{};
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(handle_, zero, &current, FILE_CURRENT))
      throw_file_error("unable to inspect random-access file position", path_,
                       last_file_error());
    seek(length);
    if (!SetEndOfFile(handle_))
      throw_file_error("unable to truncate random-access file", path_,
                       last_file_error());
    seek((std::min)(static_cast<std::uint64_t>(current.QuadPart), length));
  }

  void flush() override { require_open(); }

  void sync() override {
    require_open();
    if (!FlushFileBuffers(handle_))
      throw_file_error("unable to sync random-access file", path_,
                       last_file_error());
  }

  void mark_for_deletion() override {
    require_open();
    if (deletion_marked_)
      return;
    FILE_DISPOSITION_INFO disposition{TRUE};
    if (!SetFileInformationByHandle(handle_, FileDispositionInfo, &disposition,
                                    sizeof(disposition))) {
      throw_file_error("unable to mark random-access file for deletion", path_,
                       last_file_error());
    }
    deletion_marked_ = true;
  }

  void close() override {
    if (!is_open())
      return;
    const HANDLE handle = std::exchange(handle_, INVALID_HANDLE_VALUE);
    if (!CloseHandle(handle))
      throw_file_error("unable to close random-access file", path_,
                       last_file_error());
  }

private:
  void require_open() const {
    if (!is_open())
      throw std::logic_error("random-access file is closed");
  }

  std::filesystem::path path_;
  HANDLE handle_ = INVALID_HANDLE_VALUE;
  bool deletion_marked_ = false;
};

#else

std::error_code last_file_error() { return {errno, std::generic_category()}; }

class NativeRandomAccessFile final : public RandomAccessFile {
public:
  NativeRandomAccessFile(std::filesystem::path path, RandomAccessOpenMode mode)
      : path_(std::move(path)) {
    int flags = mode == RandomAccessOpenMode::read_only ? O_RDONLY : O_RDWR;
    if (mode == RandomAccessOpenMode::create_new)
      flags |= O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    do {
      descriptor_ = ::open(path_.c_str(), flags, 0666);
    } while (descriptor_ < 0 && errno == EINTR);
    if (descriptor_ < 0)
      throw_file_error("unable to open random-access file", path_,
                       last_file_error());
  }

  ~NativeRandomAccessFile() override {
    if (is_open())
      ::close(descriptor_);
  }

  [[nodiscard]] bool is_open() const noexcept override {
    return descriptor_ >= 0;
  }

  [[nodiscard]] std::uint64_t size() override {
    require_open();
    struct stat information {};
    if (::fstat(descriptor_, &information) != 0 || information.st_size < 0)
      throw_file_error("unable to inspect random-access file size", path_,
                       last_file_error());
    return static_cast<std::uint64_t>(information.st_size);
  }

  void seek(std::uint64_t offset) override {
    require_open();
    if (offset >
        static_cast<std::uint64_t>((std::numeric_limits<off_t>::max)())) {
      throw std::overflow_error("random-access file offset is too large");
    }
    off_t result = -1;
    do {
      result = ::lseek(descriptor_, static_cast<off_t>(offset), SEEK_SET);
    } while (result < 0 && errno == EINTR);
    if (result < 0)
      throw_file_error("unable to seek random-access file", path_,
                       last_file_error());
  }

  [[nodiscard]] std::size_t read(std::span<std::uint8_t> destination) override {
    require_open();
    if (destination.empty())
      return 0;
    const auto requested = (std::min)(
        destination.size(),
        static_cast<std::size_t>((std::numeric_limits<ssize_t>::max)()));
    ssize_t count = -1;
    do {
      count = ::read(descriptor_, destination.data(), requested);
    } while (count < 0 && errno == EINTR);
    if (count < 0)
      throw_file_error("unable to read random-access file", path_,
                       last_file_error());
    return static_cast<std::size_t>(count);
  }

  [[nodiscard]] std::size_t
  write(std::span<const std::uint8_t> source) override {
    require_open();
    if (source.empty())
      return 0;
    const auto requested = (std::min)(
        source.size(),
        static_cast<std::size_t>((std::numeric_limits<ssize_t>::max)()));
    ssize_t count = -1;
    do {
      count = ::write(descriptor_, source.data(), requested);
    } while (count < 0 && errno == EINTR);
    if (count < 0)
      throw_file_error("unable to write random-access file", path_,
                       last_file_error());
    return static_cast<std::size_t>(count);
  }

  void truncate(std::uint64_t length) override {
    require_open();
    if (length >
        static_cast<std::uint64_t>((std::numeric_limits<off_t>::max)())) {
      throw std::overflow_error("random-access file length is too large");
    }
    if (::ftruncate(descriptor_, static_cast<off_t>(length)) != 0)
      throw_file_error("unable to truncate random-access file", path_,
                       last_file_error());
  }

  void flush() override { require_open(); }

  void sync() override {
    require_open();
    int result = -1;
    do {
      result = ::fsync(descriptor_);
    } while (result != 0 && errno == EINTR);
    if (result != 0)
      throw_file_error("unable to sync random-access file", path_,
                       last_file_error());
  }

  void mark_for_deletion() override {
    require_open();
    if (deletion_marked_)
      return;

    struct stat opened {};
    if (::fstat(descriptor_, &opened) != 0) {
      throw_file_error("unable to inspect open random-access file identity",
                       path_, last_file_error());
    }

    struct stat named {};
    int result = -1;
    do {
      result = ::lstat(path_.c_str(), &named);
    } while (result != 0 && errno == EINTR);
    if (result != 0) {
      throw_file_error("unable to inspect random-access file path identity",
                       path_, last_file_error());
    }
    if (opened.st_dev != named.st_dev || opened.st_ino != named.st_ino) {
      throw_file_error(
          "random-access file path identity changed before deletion", path_,
          std::make_error_code(std::errc::state_not_recoverable));
    }

    do {
      result = ::unlink(path_.c_str());
    } while (result != 0 && errno == EINTR);
    if (result != 0) {
      throw_file_error("unable to unlink open random-access file", path_,
                       last_file_error());
    }
    deletion_marked_ = true;
  }

  void close() override {
    if (!is_open())
      return;
    const int descriptor = std::exchange(descriptor_, -1);
    if (::close(descriptor) != 0)
      throw_file_error("unable to close random-access file", path_,
                       last_file_error());
  }

private:
  void require_open() const {
    if (!is_open())
      throw std::logic_error("random-access file is closed");
  }

  std::filesystem::path path_;
  int descriptor_ = -1;
  bool deletion_marked_ = false;
};

#endif

} // namespace

std::unique_ptr<RandomAccessFile>
FileOperations::open_random_access(const std::filesystem::path &path,
                                   RandomAccessOpenMode mode) const {
  return std::make_unique<NativeRandomAccessFile>(path, mode);
}

void FileOperations::rename(const std::filesystem::path &source,
                            const std::filesystem::path &destination,
                            std::error_code &error) const noexcept {
#ifdef _WIN32
  if (MoveFileExW(source.c_str(), destination.c_str(),
                  MOVEFILE_WRITE_THROUGH)) {
    error.clear();
    return;
  }
  error = last_file_error();
#else
  std::filesystem::rename(source, destination, error);
#endif
}

void FileOperations::rename_no_replace(const std::filesystem::path &source,
                                       const std::filesystem::path &destination,
                                       std::error_code &error) const noexcept {
#ifdef _WIN32
  if (MoveFileExW(source.c_str(), destination.c_str(),
                  MOVEFILE_WRITE_THROUGH)) {
    error.clear();
    return;
  }
  error = last_file_error();
#elif defined(__linux__) && defined(SYS_renameat2)
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
  if (::syscall(SYS_renameat2, AT_FDCWD, source.c_str(), AT_FDCWD,
                destination.c_str(), RENAME_NOREPLACE) == 0) {
    error.clear();
    return;
  }
  error = last_file_error();
#elif defined(__APPLE__)
  if (::renamex_np(source.c_str(), destination.c_str(), RENAME_EXCL) == 0) {
    error.clear();
    return;
  }
  error = last_file_error();
#elif defined(__FreeBSD__)
  if (::renameatx_np(AT_FDCWD, source.c_str(), AT_FDCWD, destination.c_str(),
                     RENAME_EXCL) == 0) {
    error.clear();
    return;
  }
  error = last_file_error();
#else
  (void)source;
  (void)destination;
  error = std::make_error_code(std::errc::operation_not_supported);
#endif
}

void FileOperations::sync_parent_directory(
    const std::filesystem::path &path) const {
  auto directory = path.parent_path();
  if (directory.empty())
    directory = ".";

#ifdef _WIN32
  HANDLE handle =
      CreateFileW(directory.c_str(), GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    throw_file_error("unable to open parent directory for sync", directory,
                     last_file_error());

  std::exception_ptr failure;
  if (!FlushFileBuffers(handle)) {
    failure = std::make_exception_ptr(std::filesystem::filesystem_error(
        "unable to sync parent directory", directory, last_file_error()));
  }
  if (!CloseHandle(handle) && !failure) {
    failure = std::make_exception_ptr(std::filesystem::filesystem_error(
        "unable to close parent directory after sync", directory,
        last_file_error()));
  }
  if (failure)
    std::rethrow_exception(failure);
#else
  int flags = O_RDONLY;
#ifdef O_DIRECTORY
  flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  int descriptor = -1;
  do {
    descriptor = ::open(directory.c_str(), flags);
  } while (descriptor < 0 && errno == EINTR);
  if (descriptor < 0)
    throw_file_error("unable to open parent directory for sync", directory,
                     last_file_error());

  std::exception_ptr failure;
  int result = -1;
  do {
    result = ::fsync(descriptor);
  } while (result != 0 && errno == EINTR);
  if (result != 0) {
    failure = std::make_exception_ptr(std::filesystem::filesystem_error(
        "unable to sync parent directory", directory, last_file_error()));
  }
  if (::close(descriptor) != 0 && !failure) {
    failure = std::make_exception_ptr(std::filesystem::filesystem_error(
        "unable to close parent directory after sync", directory,
        last_file_error()));
  }
  if (failure)
    std::rethrow_exception(failure);
#endif
}

} // namespace llmghidra::db
