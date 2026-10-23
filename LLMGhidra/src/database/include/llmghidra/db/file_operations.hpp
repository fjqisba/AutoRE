/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <system_error>

namespace llmghidra::db {

enum class RandomAccessOpenMode { create_new, read_only, read_write };

// Seekable file handle used by database buffer files. Implementations expose
// partial reads/writes so callers can handle native short I/O correctly.
// close() must release the native handle before reporting a close error.
class RandomAccessFile {
public:
  virtual ~RandomAccessFile() = default;

  [[nodiscard]] virtual bool is_open() const noexcept = 0;
  [[nodiscard]] virtual std::uint64_t size() = 0;
  virtual void seek(std::uint64_t offset) = 0;
  [[nodiscard]] virtual std::size_t
  read(std::span<std::uint8_t> destination) = 0;
  [[nodiscard]] virtual std::size_t
  write(std::span<const std::uint8_t> source) = 0;
  virtual void truncate(std::uint64_t size) = 0;
  // Flushes implementation-owned user-space buffers. The default native
  // implementation is unbuffered, but the boundary remains injectable.
  virtual void flush() = 0;
  // Requests durable file data and metadata persistence (FlushFileBuffers or
  // fsync). Parent-directory durability is a separate publication concern.
  virtual void sync() = 0;
  // Marks the identity represented by this exact open handle for deletion.
  // A failure leaves the handle open and retryable. On Windows the native
  // handle carries DELETE access and the implementation uses file disposition
  // information. Portable POSIX has no unlink-by-fd operation, so the
  // implementation compares fstat(handle) with lstat(path) immediately before
  // unlink. POSIX callers must therefore hold the project/directory exclusive
  // lock that prevents cooperative path replacement for the duration of this
  // operation.
  virtual void mark_for_deletion() = 0;
  virtual void close() = 0;
};

// Injectable boundary for host filesystem mutations. Product code uses the
// default implementation; reliability tests override individual operations to
// reproduce precise crash and error points without timing-dependent races.
class FileOperations {
public:
  virtual ~FileOperations() = default;

  [[nodiscard]] virtual std::unique_ptr<RandomAccessFile>
  open_random_access(const std::filesystem::path &path,
                     RandomAccessOpenMode mode) const;

  [[nodiscard]] virtual std::filesystem::file_status
  symlink_status(const std::filesystem::path &path,
                 std::error_code &error) const noexcept {
    return std::filesystem::symlink_status(path, error);
  }

  virtual bool remove(const std::filesystem::path &path,
                      std::error_code &error) const noexcept {
    return std::filesystem::remove(path, error);
  }

  virtual void rename(const std::filesystem::path &source,
                      const std::filesystem::path &destination,
                      std::error_code &error) const noexcept;

  // Atomically moves source only when destination does not exist.  Product
  // code must use this boundary when a concurrent creator must never be
  // overwritten between an existence check and publication.
  virtual void rename_no_replace(const std::filesystem::path &source,
                                 const std::filesystem::path &destination,
                                 std::error_code &error) const noexcept;

  // Persists the directory entry containing path after create, rename, or
  // remove. This is deliberately separate from RandomAccessFile::sync(): a
  // durable file body does not by itself make a newly created name durable.
  // Implementations throw filesystem_error when the host cannot provide the
  // requested publication barrier; callers must not silently downgrade it.
  virtual void sync_parent_directory(const std::filesystem::path &path) const;

  virtual bool copy_file(const std::filesystem::path &source,
                         const std::filesystem::path &destination,
                         std::filesystem::copy_options options,
                         std::error_code &error) const noexcept {
    return std::filesystem::copy_file(source, destination, options, error);
  }
};

} // namespace llmghidra::db
