/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/local_buffer_file.hpp"

#include "llmghidra/db/block_stream.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <exception>
#include <limits>
#include <random>
#include <set>
#include <stdexcept>

namespace llmghidra::db {
namespace {

constexpr std::array<std::uint8_t, 16> pending_publication_marker{
    'L', 'L', 'M', 'G', 'P', 'U', 'B', '1',
    'P', 'E', 'N', 'D', 'I', 'N', 'G', 0};
constexpr std::array<std::uint8_t, 16> ready_publication_marker{
    'L', 'L', 'M', 'G', 'P', 'U', 'B', '1', 'R', 'E', 'A', 'D', 'Y', 0, 0, 0};

enum class DurableMarkerState { pending, ready };

void append_i32(std::vector<std::uint8_t> &output, std::int32_t value) {
  const auto bits = std::bit_cast<std::uint32_t>(value);
  output.push_back(static_cast<std::uint8_t>(bits >> 24));
  output.push_back(static_cast<std::uint8_t>(bits >> 16));
  output.push_back(static_cast<std::uint8_t>(bits >> 8));
  output.push_back(static_cast<std::uint8_t>(bits));
}

std::int32_t span_i32(std::span<const std::uint8_t> input, std::size_t offset) {
  if (offset > input.size() || input.size() - offset < 4) {
    throw std::invalid_argument("truncated BufferFileBlock index");
  }
  std::uint32_t bits = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    bits = (bits << 8) | input[offset + index];
  }
  return std::bit_cast<std::int32_t>(bits);
}

void write_exact(RandomAccessFile &file,
                 std::span<const std::uint8_t> source) {
  std::size_t offset = 0;
  while (offset != source.size()) {
    const auto count = file.write(source.subspan(offset));
    if (count == 0 || count > source.size() - offset)
      throw std::runtime_error("unable to write buffer file data");
    offset += count;
  }
}

void write_u8(RandomAccessFile &file, std::uint8_t value) {
  write_exact(file, std::span(&value, 1));
}

void write_i32(RandomAccessFile &file, std::int32_t value) {
  const auto bits = std::bit_cast<std::uint32_t>(value);
  const std::array<std::uint8_t, 4> bytes{
      static_cast<std::uint8_t>(bits >> 24),
      static_cast<std::uint8_t>(bits >> 16),
      static_cast<std::uint8_t>(bits >> 8), static_cast<std::uint8_t>(bits)};
  write_exact(file, bytes);
}

void write_i64(RandomAccessFile &file, std::int64_t value) {
  const auto bits = std::bit_cast<std::uint64_t>(value);
  const std::array<std::uint8_t, 8> bytes{
      static_cast<std::uint8_t>(bits >> 56),
      static_cast<std::uint8_t>(bits >> 48),
      static_cast<std::uint8_t>(bits >> 40),
      static_cast<std::uint8_t>(bits >> 32),
      static_cast<std::uint8_t>(bits >> 24),
      static_cast<std::uint8_t>(bits >> 16),
      static_cast<std::uint8_t>(bits >> 8), static_cast<std::uint8_t>(bits)};
  write_exact(file, bytes);
}

void read_exact(RandomAccessFile &file, std::span<std::uint8_t> destination) {
  std::size_t offset = 0;
  while (offset != destination.size()) {
    const auto count = file.read(destination.subspan(offset));
    if (count == 0 || count > destination.size() - offset)
      throw std::runtime_error("unexpected end of buffer file");
    offset += count;
  }
}

std::int32_t read_i32(RandomAccessFile &file);
std::int64_t read_i64(RandomAccessFile &file);

[[nodiscard]] bool path_exists(const FileOperations &operations,
                               const std::filesystem::path &path) {
  std::error_code error;
  const auto status = operations.symlink_status(path, error);
  if (error) {
    if (error == std::errc::no_such_file_or_directory)
      return false;
    throw std::filesystem::filesystem_error("unable to inspect path", path,
                                            error);
  }
  return status.type() != std::filesystem::file_type::not_found;
}

void close_after_marker_io(std::unique_ptr<RandomAccessFile> &handle,
                           std::exception_ptr &failure) {
  if (!handle || !handle->is_open())
    return;
  try {
    handle->close();
  } catch (...) {
    if (!failure)
      failure = std::current_exception();
  }
}

[[nodiscard]] DurableMarkerState
read_publication_marker(RandomAccessFile &handle) {
  std::array<std::uint8_t, pending_publication_marker.size()> pending{};
  std::array<std::uint8_t, ready_publication_marker.size()> ready{};
  const auto size = handle.size();
  if (size < pending.size() || size > pending.size() + ready.size())
    throw std::runtime_error("invalid LocalBufferFile publication marker");
  handle.seek(0);
  read_exact(handle, pending);
  if (pending != pending_publication_marker)
    throw std::runtime_error("invalid LocalBufferFile publication marker");
  if (size == pending.size() + ready.size())
    read_exact(handle, ready);
  if (size == pending.size() + ready.size()) {
    if (ready == ready_publication_marker)
      return DurableMarkerState::ready;
    throw std::runtime_error("invalid LocalBufferFile READY marker");
  }
  // A short or torn append leaves the immutable PENDING prefix intact.  Since
  // READY is written only after target fsync, treating any incomplete tail as
  // PENDING is conservative and deterministic across process/power failure.
  return DurableMarkerState::pending;
}

void mark_and_close_for_deletion(std::unique_ptr<RandomAccessFile> &handle,
                                 const FileOperations &operations,
                                 const std::filesystem::path &path) {
  handle->mark_for_deletion();
  std::exception_ptr failure;
  close_after_marker_io(handle, failure);
  try {
    operations.sync_parent_directory(path);
  } catch (...) {
    if (!failure)
      failure = std::current_exception();
  }
  if (failure)
    std::rethrow_exception(failure);
}

[[nodiscard]] bool
delete_path_current_identity(const FileOperations &operations,
                             const std::filesystem::path &path) {
  if (!path_exists(operations, path))
    return false;
  auto handle =
      operations.open_random_access(path, RandomAccessOpenMode::read_write);
  mark_and_close_for_deletion(handle, operations, path);
  return true;
}

void delete_publication_marker(const FileOperations &operations,
                               const std::filesystem::path &marker,
                               DurableMarkerState expected,
                               const std::filesystem::path &directory_anchor) {
  auto handle =
      operations.open_random_access(marker, RandomAccessOpenMode::read_write);
  std::exception_ptr failure;
  try {
    if (read_publication_marker(*handle) != expected) {
      throw std::runtime_error(
          "LocalBufferFile publication marker changed before deletion");
    }
  } catch (...) {
    failure = std::current_exception();
  }
  if (failure) {
    close_after_marker_io(handle, failure);
    std::rethrow_exception(failure);
  }
  mark_and_close_for_deletion(handle, operations, directory_anchor);
}

void write_publication_marker(
    const FileOperations &operations, const std::filesystem::path &marker,
    RandomAccessOpenMode mode,
    const std::array<std::uint8_t, pending_publication_marker.size()> &bytes) {
  auto handle = operations.open_random_access(marker, mode);
  std::exception_ptr failure;
  try {
    handle->seek(0);
    write_exact(*handle, bytes);
    handle->truncate(bytes.size());
    handle->flush();
    handle->sync();
  } catch (...) {
    failure = std::current_exception();
  }
  close_after_marker_io(handle, failure);
  if (failure)
    std::rethrow_exception(failure);
}

void append_ready_publication_marker(const FileOperations &operations,
                                     const std::filesystem::path &marker) {
  auto handle =
      operations.open_random_access(marker, RandomAccessOpenMode::read_write);
  std::exception_ptr failure;
  try {
    if (handle->size() < pending_publication_marker.size())
      throw std::runtime_error("truncated LocalBufferFile publication marker");
    handle->seek(pending_publication_marker.size());
    write_exact(*handle, ready_publication_marker);
    handle->truncate(pending_publication_marker.size() +
                     ready_publication_marker.size());
    handle->flush();
    handle->sync();
  } catch (...) {
    failure = std::current_exception();
  }
  close_after_marker_io(handle, failure);
  if (failure)
    std::rethrow_exception(failure);
}

void validate_ready_publication_target(const FileOperations &operations,
                                       const std::filesystem::path &path) {
  auto handle =
      operations.open_random_access(path, RandomAccessOpenMode::read_only);
  std::exception_ptr failure;
  try {
    if (handle->size() <
        static_cast<std::uint64_t>(LocalBufferFile::fixed_header_length)) {
      throw std::runtime_error(
          "READY publication target has a truncated header");
    }
    handle->seek(0);
    if (static_cast<std::uint64_t>(read_i64(*handle)) !=
        LocalBufferFile::magic_number) {
      throw std::runtime_error(
          "READY publication target has an invalid format");
    }
    (void)read_i64(*handle);
    if (read_i32(*handle) != LocalBufferFile::header_format_version) {
      throw std::runtime_error(
          "READY publication target has an unsupported version");
    }
    const auto block_size = read_i32(*handle);
    if (block_size <= LocalBufferFile::buffer_prefix_size ||
        handle->size() % static_cast<std::uint64_t>(block_size) != 0) {
      throw std::runtime_error("READY publication target is not block aligned");
    }
  } catch (...) {
    failure = std::current_exception();
  }
  close_after_marker_io(handle, failure);
  if (failure)
    std::rethrow_exception(failure);
}

std::uint8_t read_u8(RandomAccessFile &file) {
  std::uint8_t value = 0;
  read_exact(file, std::span(&value, 1));
  return value;
}

std::int32_t read_i32(RandomAccessFile &file) {
  std::array<std::uint8_t, 4> bytes{};
  read_exact(file, bytes);
  std::uint32_t bits = 0;
  for (const auto byte : bytes) bits = (bits << 8) | byte;
  return std::bit_cast<std::int32_t>(bits);
}

std::int64_t read_i64(RandomAccessFile &file) {
  std::array<std::uint8_t, 8> bytes{};
  read_exact(file, bytes);
  std::uint64_t bits = 0;
  for (const auto byte : bytes) bits = (bits << 8) | byte;
  return std::bit_cast<std::int64_t>(bits);
}

std::int64_t random_file_id() {
  std::random_device device;
  std::mt19937_64 generator(
      (static_cast<std::uint64_t>(device()) << 32) ^ device() ^
      static_cast<std::uint64_t>(
          std::chrono::high_resolution_clock::now().time_since_epoch().count()));
  std::int64_t value = 0;
  while (value == 0) value = std::bit_cast<std::int64_t>(generator());
  return value;
}

} // namespace

BufferFileBlock::BufferFileBlock(std::span<const std::uint8_t> serialized)
    : block_index_(span_i32(serialized, 0)),
      data_(serialized.begin() + 4, serialized.end()) {}

std::vector<std::uint8_t> BufferFileBlock::to_bytes() const {
  std::vector<std::uint8_t> result;
  result.reserve(data_.size() + 4);
  append_i32(result, block_index_);
  result.insert(result.end(), data_.begin(), data_.end());
  return result;
}

LocalBufferFile::LocalBufferFile(
    std::filesystem::path path, std::int32_t buffer_size,
    std::shared_ptr<FileOperations> file_operations)
    : path_(std::move(path)),
      file_operations_(file_operations ? std::move(file_operations)
                                       : std::make_shared<FileOperations>()),
      file_id_(random_file_id()), buffer_size_(buffer_size) {
  block_stream_state_ = std::make_shared<BlockStreamState>(this);
  if (buffer_size <= 0 ||
      buffer_size > std::numeric_limits<std::int32_t>::max() -
                        buffer_prefix_size) {
    throw std::invalid_argument("invalid LocalBufferFile buffer size");
  }
  block_size_ = buffer_size + buffer_prefix_size;
  begin_publication();
  try {
    reopen(RandomAccessOpenMode::create_new);
    publication_target_created_ = true;
  } catch (...) {
    const auto failure = std::current_exception();
    try {
      discard_uncommitted_publication();
    } catch (...) {
    }
    std::rethrow_exception(failure);
  }
}

LocalBufferFile::LocalBufferFile(std::filesystem::path path, OpenMode mode,
                                 std::shared_ptr<FileOperations> file_operations)
    : path_(std::move(path)),
      file_operations_(file_operations ? std::move(file_operations)
                                       : std::make_shared<FileOperations>()),
      read_only_(mode == OpenMode::read_only) {
  block_stream_state_ = std::make_shared<BlockStreamState>(this);
  if (path_exists(*file_operations_, pending_publication_path(path_))) {
    throw std::runtime_error("LocalBufferFile has a pending publication; "
                             "exclusive recovery is required");
  }
  reopen(read_only_ ? RandomAccessOpenMode::read_only
                    : RandomAccessOpenMode::read_write);
  read_header();
}

std::filesystem::path
LocalBufferFile::pending_publication_path(const std::filesystem::path &path) {
  auto marker = path;
  marker += ".llmghidra-publish";
  return marker;
}

LocalBufferFile::PendingPublicationRecovery
LocalBufferFile::recover_pending_publication(
    const std::filesystem::path &path,
    std::shared_ptr<FileOperations> file_operations) {
  auto operations = file_operations ? std::move(file_operations)
                                    : std::make_shared<FileOperations>();
  const auto marker = pending_publication_path(path);
  if (!path_exists(*operations, marker))
    return PendingPublicationRecovery::none;

  auto marker_handle = operations->open_random_access(
      marker, RandomAccessOpenMode::read_write);
  std::exception_ptr failure;
  DurableMarkerState state = DurableMarkerState::pending;
  try {
    state = read_publication_marker(*marker_handle);
    if (state == DurableMarkerState::ready) {
      validate_ready_publication_target(*operations, path);
    } else {
      (void)delete_path_current_identity(*operations, path);
    }
  } catch (...) {
    failure = std::current_exception();
  }
  if (failure) {
    close_after_marker_io(marker_handle, failure);
    std::rethrow_exception(failure);
  }
  mark_and_close_for_deletion(marker_handle, *operations, path);
  return state == DurableMarkerState::ready
             ? PendingPublicationRecovery::committed
             : PendingPublicationRecovery::discarded;
}

void LocalBufferFile::begin_publication() {
  const auto marker = pending_publication_path(path_);
  std::unique_ptr<RandomAccessFile> handle;
  bool marker_created = false;
  std::exception_ptr failure;
  try {
    handle = file_operations_->open_random_access(
        marker, RandomAccessOpenMode::create_new);
    marker_created = true;
    handle->seek(0);
    write_exact(*handle, pending_publication_marker);
    handle->truncate(pending_publication_marker.size());
    handle->flush();
    handle->sync();
    handle->close();
    file_operations_->sync_parent_directory(marker);
    publication_state_ = PublicationState::pending;
    return;
  } catch (...) {
    failure = std::current_exception();
  }
  close_after_marker_io(handle, failure);
  if (marker_created) {
    try {
      if (handle && handle->is_open()) {
        mark_and_close_for_deletion(handle, *file_operations_, marker);
      } else {
        (void)delete_path_current_identity(*file_operations_, marker);
      }
    } catch (...) {
    }
  }
  std::rethrow_exception(failure);
}

void LocalBufferFile::mark_publication_ready() {
  if (publication_state_ == PublicationState::ready)
    return;
  if (publication_state_ != PublicationState::pending &&
      publication_state_ != PublicationState::indeterminate) {
    throw std::logic_error("LocalBufferFile publication is not pending");
  }
  const auto marker = pending_publication_path(path_);
  publication_state_ = PublicationState::indeterminate;
  append_ready_publication_marker(*file_operations_, marker);
  publication_state_ = PublicationState::ready;
}

void LocalBufferFile::finish_publication() {
  if (publication_state_ != PublicationState::ready)
    throw std::logic_error("LocalBufferFile publication is not ready");
  const auto marker = pending_publication_path(path_);
  delete_publication_marker(*file_operations_, marker,
                            DurableMarkerState::ready, path_);
  publication_state_ = PublicationState::none;
}

void LocalBufferFile::discard_uncommitted_publication() {
  if (publication_state_ == PublicationState::ready) {
    return;
  }
  const auto marker = pending_publication_path(path_);
  if (publication_state_ == PublicationState::indeterminate) {
    write_publication_marker(*file_operations_, marker,
                             RandomAccessOpenMode::read_write,
                             pending_publication_marker);
    publication_state_ = PublicationState::pending;
  }
  if (publication_target_created_) {
    if (handle_ && handle_->is_open()) {
      mark_and_close_for_deletion(handle_, *file_operations_, path_);
    } else {
      (void)delete_path_current_identity(*file_operations_, path_);
    }
    publication_target_created_ = false;
  }
  if (publication_state_ != PublicationState::none) {
    delete_publication_marker(*file_operations_, marker,
                              DurableMarkerState::pending, marker);
    publication_state_ = PublicationState::none;
  }
}

LocalBufferFile::~LocalBufferFile() {
  try {
    close();
  }
  catch (...) {}
  if (block_stream_state_) {
    std::scoped_lock lock(block_stream_state_->mutex);
    block_stream_state_->closing = true;
    block_stream_state_->active_output = nullptr;
    block_stream_state_->owner = nullptr;
  }
}

void LocalBufferFile::require_open() const {
  if (closed()) throw std::logic_error("LocalBufferFile is closed");
}

void LocalBufferFile::require_writable() const {
  require_open();
  if (read_only_) throw std::logic_error("LocalBufferFile is read-only");
}

void LocalBufferFile::reopen(RandomAccessOpenMode mode) {
  if (!closed())
    throw std::logic_error("LocalBufferFile handle is already open");
  handle_ = file_operations_->open_random_access(path_, mode);
  if (!handle_ || !handle_->is_open())
    throw std::runtime_error("unable to open LocalBufferFile");
}

void LocalBufferFile::seek_read(std::uint64_t offset) {
  require_open();
  handle_->seek(offset);
}

void LocalBufferFile::seek_write(std::uint64_t offset) {
  require_writable();
  handle_->seek(offset);
}

std::uint64_t LocalBufferFile::buffer_offset(std::int32_t index) const {
  if (index < 0 || index > maximum_buffer_index) {
    throw std::out_of_range("LocalBufferFile buffer index is out of range");
  }
  return static_cast<std::uint64_t>(index + 1) *
         static_cast<std::uint64_t>(block_size_);
}

std::int32_t LocalBufferFile::parameter(const std::string &name) const {
  const auto found = parameters_.find(name);
  if (found == parameters_.end()) {
    throw std::out_of_range("LocalBufferFile parameter not found: " + name);
  }
  return found->second;
}

void LocalBufferFile::set_parameter(std::string name, std::int32_t value) {
  require_writable();
  parameters_[std::move(name)] = value;
}

std::vector<std::string> LocalBufferFile::parameter_names() const {
  std::vector<std::string> result;
  result.reserve(parameters_.size());
  for (const auto &[name, value] : parameters_) {
    (void)value;
    result.push_back(name);
  }
  return result;
}

void LocalBufferFile::set_free_indexes(
    std::span<const std::int32_t> indexes) {
  require_writable();
  std::vector<std::int32_t> validated(indexes.begin(), indexes.end());
  (std::sort)(validated.begin(), validated.end());
  for (std::size_t index = 0; index < validated.size(); ++index) {
    if (validated[index] < 0 || validated[index] >= buffer_count_ ||
        (index != 0 && validated[index] == validated[index - 1])) {
      throw std::invalid_argument("invalid LocalBufferFile free index list");
    }
  }
  free_indexes_ = std::move(validated);
}

void LocalBufferFile::read_header() {
  const auto file_length = handle_->size();
  if (file_length < fixed_header_length) {
    throw std::runtime_error("truncated LocalBufferFile header");
  }
  seek_read(0);
  if (static_cast<std::uint64_t>(read_i64(*handle_)) != magic_number) {
    throw std::runtime_error("unrecognized LocalBufferFile format");
  }
  file_id_ = read_i64(*handle_);
  if (read_i32(*handle_) != header_format_version) {
    throw std::runtime_error("unsupported LocalBufferFile header version");
  }
  block_size_ = read_i32(*handle_);
  if (block_size_ <= buffer_prefix_size) {
    throw std::runtime_error("invalid LocalBufferFile block size");
  }
  buffer_size_ = block_size_ - buffer_prefix_size;
  const auto first_free_index = read_i32(*handle_);
  if (file_length % static_cast<std::uint64_t>(block_size_) != 0) {
    throw std::runtime_error(
        "LocalBufferFile length is not block aligned: length=" +
        std::to_string(file_length) + ", block-size=" +
        std::to_string(block_size_));
  }
  const auto block_count = file_length / static_cast<std::uint64_t>(block_size_);
  if (block_count == 0 || block_count - 1 >
                              static_cast<std::uint64_t>(
                                  std::numeric_limits<std::int32_t>::max())) {
    throw std::runtime_error("invalid LocalBufferFile block count");
  }
  buffer_count_ = static_cast<std::int32_t>(block_count - 1);

  const auto parameter_count = read_i32(*handle_);
  if (parameter_count < 0) {
    throw std::runtime_error("negative LocalBufferFile parameter count");
  }
  parameters_.clear();
  std::size_t consumed = fixed_header_length;
  for (std::int32_t index = 0; index < parameter_count; ++index) {
    const auto name_length = read_i32(*handle_);
    if (name_length < 0 ||
        static_cast<std::size_t>(name_length) >
            static_cast<std::size_t>(buffer_size_) ||
        consumed + 8 + static_cast<std::size_t>(name_length) >
            static_cast<std::size_t>(buffer_size_)) {
      throw std::runtime_error("invalid LocalBufferFile parameter name length");
    }
    std::vector<std::uint8_t> name_bytes(static_cast<std::size_t>(name_length));
    read_exact(*handle_, name_bytes);
    const std::string name(reinterpret_cast<const char *>(name_bytes.data()),
                           name_bytes.size());
    parameters_[name] = read_i32(*handle_);
    consumed += 8 + name_bytes.size();
  }
  build_free_index_list(first_free_index);
}

void LocalBufferFile::write_header() {
  require_writable();
  std::int32_t previous = -1;
  for (const auto index : free_indexes_) {
    put_free_block(index, previous);
    previous = index;
  }

  seek_write(0);
  write_i64(*handle_, static_cast<std::int64_t>(magic_number));
  write_i64(*handle_, file_id_);
  write_i32(*handle_, header_format_version);
  write_i32(*handle_, block_size_);
  write_i32(*handle_, previous);
  if (parameters_.size() >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::length_error("too many LocalBufferFile parameters");
  }
  write_i32(*handle_, static_cast<std::int32_t>(parameters_.size()));
  std::size_t count = fixed_header_length;
  for (const auto &[name, value] : parameters_) {
    count += 8 + name.size();
    if (count > static_cast<std::size_t>(buffer_size_) ||
        name.size() >
            static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
      throw std::runtime_error("LocalBufferFile buffer size is too small for parameters");
    }
    write_i32(*handle_, static_cast<std::int32_t>(name.size()));
    write_exact(*handle_, std::span(
        reinterpret_cast<const std::uint8_t *>(name.data()), name.size()));
    write_i32(*handle_, value);
  }
}

void LocalBufferFile::build_free_index_list(std::int32_t first_free_index) {
  std::vector<std::int32_t> indexes;
  std::set<std::int32_t> seen;
  auto next = first_free_index;
  while (next >= 0) {
    if (next >= buffer_count_ || !seen.insert(next).second) {
      throw std::runtime_error("corrupt LocalBufferFile free list");
    }
    indexes.push_back(next);
    seek_read(buffer_offset(next));
    const auto flags = read_u8(*handle_);
    if ((flags & empty_buffer_flag) == 0) {
      throw std::runtime_error("free-list block is not marked empty");
    }
    next = read_i32(*handle_);
  }
  (std::sort)(indexes.begin(), indexes.end());
  free_indexes_ = std::move(indexes);
}

DataBuffer &LocalBufferFile::get(DataBuffer &buffer, std::int32_t index) {
  require_open();
  if (index < 0 || index >= buffer_count_) {
    throw std::out_of_range("LocalBufferFile buffer index exceeds file");
  }
  seek_read(buffer_offset(index));
  const auto flags = read_u8(*handle_);
  const auto stored_id = read_i32(*handle_);
  const bool is_empty = (flags & empty_buffer_flag) != 0;
  std::optional<std::vector<std::uint8_t>> new_data;
  if (!is_empty) {
    if (buffer.has_data() &&
        buffer.size() != static_cast<std::size_t>(buffer_size_)) {
      throw std::invalid_argument("DataBuffer size differs from LocalBufferFile");
    }
    new_data.emplace(static_cast<std::size_t>(buffer_size_));
    read_exact(*handle_, *new_data);
  }

  // Commit only after the complete block has been validated and read. Empty
  // blocks deliberately preserve an existing backing allocation, matching
  // Ghidra's DataBuffer reuse behavior.
  if (new_data) buffer.set_data(std::move(new_data));
  buffer.set_empty(is_empty);
  buffer.set_id(is_empty ? -1 : stored_id);
  buffer.set_dirty(false);
  return buffer;
}

void LocalBufferFile::put(const DataBuffer &buffer, std::int32_t index) {
  require_writable();
  const auto offset = buffer_offset(index);
  if (!buffer.empty() &&
      (!buffer.has_data() ||
       buffer.size() != static_cast<std::size_t>(buffer_size_))) {
    throw std::invalid_argument("DataBuffer size differs from LocalBufferFile");
  }
  seek_write(offset);
  write_u8(*handle_, buffer.empty() ? empty_buffer_flag : 0);
  write_i32(*handle_, buffer.id());
  if (!buffer.empty()) write_exact(*handle_, buffer.bytes());
  if (index >= buffer_count_) buffer_count_ = index + 1;
}

void LocalBufferFile::put_free_block(std::int32_t index,
                                     std::int32_t next_free_index) {
  require_writable();
  if (index < 0 || index > buffer_count_ ||
      next_free_index < -1 || next_free_index >= buffer_count_) {
    throw std::out_of_range("invalid LocalBufferFile free block link");
  }
  if (index == buffer_count_) ++buffer_count_;
  seek_write(buffer_offset(index));
  write_u8(*handle_, empty_buffer_flag);
  write_i32(*handle_, next_free_index);
}

void LocalBufferFile::truncate(std::int32_t index_count) {
  require_writable();
  if (index_count < 0 || index_count > buffer_count_) {
    throw std::invalid_argument("invalid LocalBufferFile truncation count");
  }
  handle_->flush();
  handle_->truncate(static_cast<std::uint64_t>(index_count + 1) *
                    static_cast<std::uint64_t>(block_size_));
  buffer_count_ = index_count;
  free_indexes_.erase(
      (std::remove_if)(free_indexes_.begin(), free_indexes_.end(),
                       [index_count](std::int32_t index) {
                         return index >= index_count;
                       }),
      free_indexes_.end());
}

void LocalBufferFile::pad_to_block_boundary() {
  handle_->flush();
  const auto length = handle_->size();
  const auto remainder = length % static_cast<std::uint64_t>(block_size_);
  if (remainder == 0) return;
  const auto target = length - remainder + static_cast<std::uint64_t>(block_size_);
  handle_->truncate(target);
}

bool LocalBufferFile::flush_unlocked() {
  if (closed() || read_only_) return false;
  write_header();
  pad_to_block_boundary();
  handle_->flush();
  handle_->sync();
  if (publication_state_ == PublicationState::pending ||
      publication_state_ == PublicationState::indeterminate)
    mark_publication_ready();
  if (publication_state_ == PublicationState::ready)
    finish_publication();
  return true;
}

bool LocalBufferFile::flush() {
  std::scoped_lock stream_lock(block_stream_state_->mutex);
  if (block_stream_state_->active_output) {
    throw std::logic_error("cannot flush with an active block stream");
  }
  if (block_stream_state_->output_failed) {
    throw std::logic_error("cannot commit a failed output block stream");
  }
  return flush_unlocked();
}

bool LocalBufferFile::set_read_only() {
  std::scoped_lock stream_lock(block_stream_state_->mutex);
  if (block_stream_state_->active_output) {
    throw std::logic_error("cannot change mode with an active block stream");
  }
  if (block_stream_state_->output_failed) {
    throw std::logic_error("cannot commit a failed output block stream");
  }
  if (!flush_unlocked()) return false;
  handle_->close();
  reopen(RandomAccessOpenMode::read_only);
  read_only_ = true;
  return true;
}

void LocalBufferFile::close() {
  if (closed()) return;
  std::exception_ptr failure;
  bool committed = read_only_;
  std::shared_ptr<OutputStreamState> active;
  bool output_failed = false;
  {
    std::scoped_lock lock(block_stream_state_->mutex);
    block_stream_state_->closing = true;
    active = block_stream_state_->active_output;
    output_failed = block_stream_state_->output_failed;
  }
  if (active) {
    try {
      std::scoped_lock stream_lock(active->mutex);
      if (!active->closed) active->closed = true;
      std::scoped_lock owner_lock(block_stream_state_->mutex);
      if (block_stream_state_->active_output == active) {
        finish_output_stream(active);
      }
    }
    catch (...) {}
    failure = std::make_exception_ptr(
        std::runtime_error("active block stream was not closed properly"));
  }
  else if (output_failed) {
    failure = std::make_exception_ptr(
        std::runtime_error("output block stream failed"));
  }
  else if (!read_only_) {
    try {
      committed = flush();
    }
    catch (...) {
      failure = std::current_exception();
    }
  }
  const bool discard_uncommitted =
      !read_only_ && !committed && publication_target_created_ &&
      publication_state_ != PublicationState::ready;
  if (discard_uncommitted) {
    try {
      discard_uncommitted_publication();
    } catch (...) {
      if (!failure)
        failure = std::current_exception();
    }
  }
  if (!closed()) {
    try {
      handle_->close();
    }
    catch (...) {
      if (!failure)
        failure = std::current_exception();
    }
  }
  if (failure) std::rethrow_exception(failure);
}

std::vector<std::uint8_t>
LocalBufferFile::read_raw_block(std::int32_t block_index) {
  require_open();
  if (block_index < 0 || block_index > buffer_count_) {
    throw std::out_of_range("LocalBufferFile raw block index is out of range");
  }
  const auto offset = static_cast<std::uint64_t>(block_index) *
                      static_cast<std::uint64_t>(block_size_);
  seek_read(offset);
  std::vector<std::uint8_t> data(static_cast<std::size_t>(block_size_));
  read_exact(*handle_, data);
  return data;
}

void LocalBufferFile::write_raw_block(
    std::int32_t block_index, std::span<const std::uint8_t> data) {
  require_writable();
  if (block_index < 0 || block_index > maximum_buffer_index + 1 ||
      data.size() != static_cast<std::size_t>(block_size_)) {
    throw std::invalid_argument("invalid LocalBufferFile raw block");
  }
  const auto offset = static_cast<std::uint64_t>(block_index) *
                      static_cast<std::uint64_t>(block_size_);
  seek_write(offset);
  write_exact(*handle_, data);
  if (block_index > buffer_count_) buffer_count_ = block_index;
}

void LocalBufferFile::finish_output_stream(
    const std::shared_ptr<OutputStreamState> &stream) {
  if (block_stream_state_->active_output != stream) {
    throw std::logic_error("output block stream is not active");
  }
  try {
    if (stream->refresh_header) {
      handle_->flush();
      read_header();
      file_id_ = stream->original_file_id;
      seek_write(8);
      write_i64(*handle_, file_id_);
    }
    block_stream_state_->active_output = nullptr;
  }
  catch (...) {
    block_stream_state_->output_failed = true;
    block_stream_state_->active_output = nullptr;
    throw;
  }
}

bool LocalBufferFile::rename_to(std::filesystem::path destination) {
  {
    std::scoped_lock lock(block_stream_state_->mutex);
    if (block_stream_state_->active_output ||
        block_stream_state_->output_failed || block_stream_state_->closing)
      return false;
  }
  if (destination.empty() || std::filesystem::exists(destination)) return false;
  const bool was_open = !closed();
  if (was_open && !read_only_) flush();
  if (was_open) handle_->close();
  const auto source = path_;
  std::error_code error;
  file_operations_->rename_no_replace(source, destination, error);
  if (error) {
    if (was_open) {
      reopen(read_only_ ? RandomAccessOpenMode::read_only
                        : RandomAccessOpenMode::read_write);
    }
    return false;
  }
  path_ = std::move(destination);
  try {
    file_operations_->sync_parent_directory(path_);
    if (source.parent_path() != path_.parent_path()) {
      file_operations_->sync_parent_directory(source);
    }
  }
  catch (...) {
    const auto failure = std::current_exception();
    if (was_open) {
      try {
        reopen(read_only_ ? RandomAccessOpenMode::read_only
                          : RandomAccessOpenMode::read_write);
      }
      catch (...) {}
    }
    std::rethrow_exception(failure);
  }
  if (was_open) {
    reopen(read_only_ ? RandomAccessOpenMode::read_only
                      : RandomAccessOpenMode::read_write);
  }
  return true;
}

bool LocalBufferFile::delete_file() {
  {
    std::scoped_lock lock(block_stream_state_->mutex);
    if (closed() || read_only_ || block_stream_state_->active_output ||
        block_stream_state_->closing)
      return false;
    block_stream_state_->closing = true;
  }
  if (publication_state_ == PublicationState::ready ||
      publication_state_ == PublicationState::indeterminate) {
    try {
      write_publication_marker(
          *file_operations_, pending_publication_path(path_),
          RandomAccessOpenMode::read_write, pending_publication_marker);
      publication_state_ = PublicationState::pending;
    } catch (...) {
      std::scoped_lock lock(block_stream_state_->mutex);
      block_stream_state_->closing = false;
      throw;
    }
  }
  try {
    handle_->mark_for_deletion();
  } catch (...) {
    std::scoped_lock lock(block_stream_state_->mutex);
    block_stream_state_->closing = false;
    throw;
  }
  std::exception_ptr failure;
  try {
    handle_->close();
  }
  catch (...) {
    failure = std::current_exception();
  }
  try {
    file_operations_->sync_parent_directory(path_);
  } catch (...) {
    if (!failure)
      failure = std::current_exception();
    std::rethrow_exception(failure);
  }
  publication_target_created_ = false;
  if (publication_state_ == PublicationState::pending) {
    const auto marker = pending_publication_path(path_);
    try {
      delete_publication_marker(*file_operations_, marker,
                                DurableMarkerState::pending, marker);
      publication_state_ = PublicationState::none;
    } catch (...) {
      if (!failure)
        failure = std::current_exception();
    }
  }
  if (failure)
    std::rethrow_exception(failure);
  return true;
}

std::int32_t LocalBufferFile::recommended_buffer_size(
    std::int32_t requested_buffer_size) noexcept {
  constexpr std::int32_t minimum_block_size = 128;
  const auto adjusted = static_cast<std::int64_t>(requested_buffer_size) +
                        buffer_prefix_size;
  auto size = static_cast<std::int32_t>(
      adjusted > std::numeric_limits<std::int32_t>::max()
          ? std::numeric_limits<std::int32_t>::max() & -minimum_block_size
          : adjusted & -static_cast<std::int64_t>(minimum_block_size));
  if (size <= 0) size = minimum_block_size;
  return size - buffer_prefix_size;
}

std::optional<DataBuffer> LocalBufferFile::data_buffer_from_block(
    const BufferFileBlock &block) {
  if (block.index() <= 0) return std::nullopt;
  if (block.data().size() < static_cast<std::size_t>(buffer_prefix_size)) {
    throw std::invalid_argument("BufferFileBlock is smaller than buffer prefix");
  }
  const auto flags = block.data()[0];
  DataBuffer buffer;
  if (flags == empty_buffer_flag) {
    buffer.set_id(-1);
    buffer.set_empty(true);
    return buffer;
  }
  buffer.set_id(span_i32(block.data(), 1));
  buffer.set_data(std::vector<std::uint8_t>(
      block.data().begin() + buffer_prefix_size, block.data().end()));
  return buffer;
}

BufferFileBlock LocalBufferFile::block_from_data_buffer(
    const DataBuffer &buffer, std::int32_t buffer_size) {
  if (buffer_size < 0 ||
      (!buffer.empty() &&
       (!buffer.has_data() ||
        buffer.size() != static_cast<std::size_t>(buffer_size)))) {
    throw std::invalid_argument("DataBuffer size differs from BufferFileBlock");
  }
  std::vector<std::uint8_t> data(
      static_cast<std::size_t>(buffer_size + buffer_prefix_size));
  data[0] = buffer.empty() ? empty_buffer_flag : 0;
  const auto id = std::bit_cast<std::uint32_t>(buffer.id());
  data[1] = static_cast<std::uint8_t>(id >> 24);
  data[2] = static_cast<std::uint8_t>(id >> 16);
  data[3] = static_cast<std::uint8_t>(id >> 8);
  data[4] = static_cast<std::uint8_t>(id);
  if (!buffer.empty()) {
    (std::copy)(buffer.bytes().begin(), buffer.bytes().end(),
                data.begin() + buffer_prefix_size);
  }
  return BufferFileBlock(buffer.id() + 1, std::move(data));
}

} // namespace llmghidra::db
