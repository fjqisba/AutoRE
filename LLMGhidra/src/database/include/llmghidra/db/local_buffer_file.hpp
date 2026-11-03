/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer.hpp"
#include "llmghidra/db/file_operations.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace llmghidra::db {

class InputBlockStream;
class OutputBlockStream;
class LocalFileInputBlockStream;
class LocalBufferInputBlockStream;
class LocalRandomInputBlockStream;
class LocalOutputBlockStream;

class BufferFileBlock final {
public:
  BufferFileBlock(std::int32_t block_index,
                  std::vector<std::uint8_t> data)
      : block_index_(block_index), data_(std::move(data)) {}
  explicit BufferFileBlock(std::span<const std::uint8_t> serialized);

  [[nodiscard]] std::int32_t index() const noexcept { return block_index_; }
  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] const std::vector<std::uint8_t> &data() const noexcept {
    return data_;
  }
  [[nodiscard]] std::vector<std::uint8_t> to_bytes() const;

private:
  std::int32_t block_index_;
  std::vector<std::uint8_t> data_;
};

class LocalBufferFile {
public:
  enum class OpenMode { read_only, read_write };
  enum class PendingPublicationRecovery { none, discarded, committed };

  static constexpr std::uint64_t magic_number = 0x2f30312c34292c2aULL;
  static constexpr std::int32_t header_format_version = 1;
  static constexpr std::int32_t buffer_prefix_size = 5;
  static constexpr std::int32_t fixed_header_length = 32;
  static constexpr std::uint8_t empty_buffer_flag = 0x01;
  static constexpr std::int32_t maximum_buffer_index =
      std::numeric_limits<std::int32_t>::max() - 1;

  // Creates a new persistent v1 .gbf file. Existing paths are rejected.
  LocalBufferFile(std::filesystem::path path, std::int32_t buffer_size,
                  std::shared_ptr<FileOperations> file_operations = {});
  // Opens an existing v1 .gbf file.
  LocalBufferFile(std::filesystem::path path, OpenMode mode,
                  std::shared_ptr<FileOperations> file_operations = {});
  virtual ~LocalBufferFile();
  LocalBufferFile(const LocalBufferFile &) = delete;
  LocalBufferFile &operator=(const LocalBufferFile &) = delete;
  LocalBufferFile(LocalBufferFile &&) = delete;
  LocalBufferFile &operator=(LocalBufferFile &&) = delete;

  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }
  [[nodiscard]] virtual bool read_only() const noexcept { return read_only_; }
  [[nodiscard]] bool closed() const noexcept {
    return !handle_ || !handle_->is_open();
  }
  [[nodiscard]] virtual std::int64_t file_id() const noexcept { return file_id_; }
  virtual void set_file_id(std::int64_t value) noexcept { file_id_ = value; }
  [[nodiscard]] std::int32_t buffer_size() const noexcept { return buffer_size_; }
  [[nodiscard]] std::int32_t block_size() const noexcept { return block_size_; }
  [[nodiscard]] virtual std::int32_t index_count() const noexcept {
    return buffer_count_;
  }

  [[nodiscard]] virtual std::int32_t
  parameter(const std::string &name) const;
  virtual void set_parameter(std::string name, std::int32_t value);
  virtual void clear_parameters() noexcept { parameters_.clear(); }
  [[nodiscard]] virtual std::vector<std::string> parameter_names() const;

  [[nodiscard]] virtual const std::vector<std::int32_t> &
  free_indexes() const noexcept {
    return free_indexes_;
  }
  virtual void set_free_indexes(std::span<const std::int32_t> indexes);

  virtual DataBuffer &get(DataBuffer &buffer, std::int32_t index);
  virtual void put(const DataBuffer &buffer, std::int32_t index);
  virtual void put_free_block(std::int32_t index,
                              std::int32_t next_free_index);
  virtual void truncate(std::int32_t index_count);
  virtual bool flush();
  virtual bool set_read_only();
  virtual void close();
  [[nodiscard]] virtual std::unique_ptr<InputBlockStream> input_block_stream();
  [[nodiscard]] virtual std::unique_ptr<InputBlockStream>
  input_block_stream(std::span<const std::uint8_t> change_map_data);
  [[nodiscard]] virtual std::unique_ptr<OutputBlockStream>
  output_block_stream(std::int32_t block_count);
  bool rename_to(std::filesystem::path destination);
  bool delete_file();

  // A new file is protected by a durable sibling marker until its body and
  // directory entry have been committed.  Recovery is intentionally explicit:
  // the caller must hold the project/database exclusive lock and prove that no
  // writer still owns path before invoking this operation.
  [[nodiscard]] static std::filesystem::path
  pending_publication_path(const std::filesystem::path &path);
  [[nodiscard]] static PendingPublicationRecovery recover_pending_publication(
      const std::filesystem::path &path,
      std::shared_ptr<FileOperations> file_operations = {});

  [[nodiscard]] static std::int32_t recommended_buffer_size(
      std::int32_t requested_buffer_size) noexcept;
  [[nodiscard]] static std::optional<DataBuffer> data_buffer_from_block(
      const BufferFileBlock &block);
  [[nodiscard]] static BufferFileBlock block_from_data_buffer(
      const DataBuffer &buffer, std::int32_t buffer_size);

private:
  struct OutputStreamState final {
    OutputStreamState(std::int64_t original_id, std::int32_t size,
                      std::int32_t count)
        : original_file_id(original_id), block_size(size),
          block_count(count) {}

    std::mutex mutex;
    std::int64_t original_file_id;
    std::int32_t block_size;
    std::int32_t block_count;
    bool refresh_header = false;
    bool closed = false;
  };

  struct BlockStreamState final {
    explicit BlockStreamState(LocalBufferFile *value) : owner(value) {}

    std::mutex mutex;
    LocalBufferFile *owner;
    std::shared_ptr<OutputStreamState> active_output;
    bool output_failed = false;
    bool closing = false;
  };

  friend class LocalFileInputBlockStream;
  friend class LocalBufferInputBlockStream;
  friend class LocalRandomInputBlockStream;
  friend class LocalOutputBlockStream;
protected:
  using BlockCallback = std::function<void(std::int32_t)>;
  [[nodiscard]] std::unique_ptr<InputBlockStream>
  buffer_input_block_stream();
  [[nodiscard]] std::unique_ptr<OutputBlockStream>
  make_output_block_stream(std::int32_t block_count,
                           BlockCallback before_write,
                           BlockCallback after_write);

private:
  void require_open() const;
  void require_writable() const;
  void seek_read(std::uint64_t offset);
  void seek_write(std::uint64_t offset);
  [[nodiscard]] std::uint64_t buffer_offset(std::int32_t index) const;
  void read_header();
  void write_header();
  void build_free_index_list(std::int32_t first_free_index);
  void pad_to_block_boundary();
  bool flush_unlocked();
  [[nodiscard]] std::vector<std::uint8_t>
  read_raw_block(std::int32_t block_index);
  void write_raw_block(std::int32_t block_index,
                       std::span<const std::uint8_t> data);
  void finish_output_stream(const std::shared_ptr<OutputStreamState> &stream);
  void reopen(RandomAccessOpenMode mode);
  void begin_publication();
  void mark_publication_ready();
  void finish_publication();
  void discard_uncommitted_publication();

  enum class PublicationState { none, pending, indeterminate, ready };

  std::filesystem::path path_;
  std::shared_ptr<FileOperations> file_operations_;
  std::unique_ptr<RandomAccessFile> handle_;
  std::map<std::string, std::int32_t> parameters_;
  std::vector<std::int32_t> free_indexes_;
  std::int64_t file_id_ = 0;
  bool read_only_ = false;
  PublicationState publication_state_ = PublicationState::none;
  bool publication_target_created_ = false;
  std::int32_t block_size_ = 0;
  std::int32_t buffer_size_ = 0;
  std::int32_t buffer_count_ = 0;
  std::shared_ptr<BlockStreamState> block_stream_state_;
};

} // namespace llmghidra::db
