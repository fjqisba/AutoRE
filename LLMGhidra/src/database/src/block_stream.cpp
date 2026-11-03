/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/block_stream.hpp"

#include "llmghidra/db/change_map.hpp"

#include <algorithm>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

namespace llmghidra::db {

class LocalFileInputBlockStream final : public InputBlockStream {
public:
  explicit LocalFileInputBlockStream(LocalBufferFile &file)
      : block_size_(file.block_size()) {
    if (!file.read_only()) {
      throw std::logic_error(
          "block input requires a read-only LocalBufferFile");
    }
    input_ = file.file_operations_->open_random_access(
        file.path(), RandomAccessOpenMode::read_only);
    const auto length = input_->size();
    if (length == 0 || length % static_cast<std::uint64_t>(block_size_) != 0 ||
        length / static_cast<std::uint64_t>(block_size_) >
            static_cast<std::uint64_t>(
                std::numeric_limits<std::int32_t>::max())) {
      throw std::runtime_error("corrupt LocalBufferFile block length");
    }
    block_count_ = static_cast<std::int32_t>(
        length / static_cast<std::uint64_t>(block_size_));
    if (!input_ || !input_->is_open())
      throw std::runtime_error("unable to open block input stream");
  }

  ~LocalFileInputBlockStream() override {
    try {
      close();
    } catch (...) {
    }
  }
  std::int32_t block_count() const noexcept override { return block_count_; }
  std::int32_t block_size() const noexcept override { return block_size_; }
  bool includes_header_block() const noexcept override { return true; }
  std::optional<BufferFileBlock> read_block() override {
    std::scoped_lock lock(mutex_);
    if (!input_ || !input_->is_open())
      throw std::logic_error("block input stream is closed");
    if (next_index_ == block_count_)
      return std::nullopt;
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(block_size_));
    std::size_t offset = 0;
    while (offset != bytes.size()) {
      const auto count = input_->read(std::span(bytes).subspan(offset));
      if (count == 0)
        throw std::runtime_error("unexpected end of block input stream");
      offset += count;
    }
    return BufferFileBlock(next_index_++, std::move(bytes));
  }
  void close() override {
    std::scoped_lock lock(mutex_);
    if (input_ && input_->is_open())
      input_->close();
  }

private:
  std::mutex mutex_;
  std::unique_ptr<RandomAccessFile> input_;
  std::int32_t block_count_ = 0;
  std::int32_t block_size_ = 0;
  std::int32_t next_index_ = 0;
};

class LocalBufferInputBlockStream final : public InputBlockStream {
public:
  explicit LocalBufferInputBlockStream(LocalBufferFile &file)
      : state_(file.block_stream_state_), block_count_(file.index_count()),
        block_size_(file.block_size()), buffer_size_(file.buffer_size()) {
    std::scoped_lock lock(state_->mutex);
    if (!state_->owner || state_->closing || !state_->owner->read_only()) {
      throw std::logic_error(
          "block input requires a read-only LocalBufferFile");
    }
  }
  std::int32_t block_count() const noexcept override { return block_count_; }
  std::int32_t block_size() const noexcept override { return block_size_; }
  bool includes_header_block() const noexcept override { return false; }
  std::optional<BufferFileBlock> read_block() override {
    std::scoped_lock lock(mutex_);
    if (closed_)
      throw std::logic_error("block input stream is closed");
    if (next_index_ == block_count_)
      return std::nullopt;
    std::scoped_lock owner_lock(state_->mutex);
    if (!state_->owner || state_->closing)
      throw std::logic_error("block input owner is closed");
    DataBuffer buffer;
    state_->owner->get(buffer, next_index_);
    auto block =
        LocalBufferFile::block_from_data_buffer(buffer, buffer_size_);
    return BufferFileBlock(++next_index_, block.data());
  }
  void close() override {
    std::scoped_lock lock(mutex_);
    closed_ = true;
  }

private:
  std::mutex mutex_;
  std::shared_ptr<LocalBufferFile::BlockStreamState> state_;
  std::int32_t block_count_ = 0;
  std::int32_t block_size_ = 0;
  std::int32_t buffer_size_ = 0;
  std::int32_t next_index_ = 0;
  bool closed_ = false;
};

class LocalRandomInputBlockStream final : public InputBlockStream {
public:
  LocalRandomInputBlockStream(LocalBufferFile &file,
                              std::span<const std::uint8_t> change_data)
      : state_(file.block_stream_state_), block_size_(file.block_size()),
        buffer_size_(file.buffer_size()) {
    std::scoped_lock lock(state_->mutex);
    auto *owner = state_->owner;
    if (!owner || state_->closing || !owner->read_only()) {
      throw std::logic_error(
          "block input requires a read-only LocalBufferFile");
    }
    ChangeMap changes(
        std::vector<std::uint8_t>(change_data.begin(), change_data.end()));
    for (std::int32_t index = 0; index < owner->index_count(); ++index) {
      if (!owner->free_indexes().empty() &&
          (std::find)(owner->free_indexes().begin(), owner->free_indexes().end(),
                      index) != owner->free_indexes().end()) {
        continue;
      }
      if (!changes.contains(index) || changes.changed(index)) {
        indexes_.push_back(index);
      }
    }
  }
  std::int32_t block_count() const noexcept override {
    return static_cast<std::int32_t>(indexes_.size());
  }
  std::int32_t block_size() const noexcept override {
    return block_size_;
  }
  bool includes_header_block() const noexcept override { return false; }
  std::optional<BufferFileBlock> read_block() override {
    std::scoped_lock lock(mutex_);
    if (closed_)
      throw std::logic_error("block input stream is closed");
    if (next_ == indexes_.size())
      return std::nullopt;
    std::scoped_lock owner_lock(state_->mutex);
    if (!state_->owner || state_->closing)
      throw std::logic_error("block input owner is closed");
    const auto buffer_index = indexes_[next_++];
    DataBuffer buffer;
    state_->owner->get(buffer, buffer_index);
    auto block =
        LocalBufferFile::block_from_data_buffer(buffer, buffer_size_);
    return BufferFileBlock(buffer_index + 1, block.data());
  }
  void close() override {
    std::scoped_lock lock(mutex_);
    closed_ = true;
  }

private:
  std::mutex mutex_;
  std::shared_ptr<LocalBufferFile::BlockStreamState> state_;
  std::int32_t block_size_ = 0;
  std::int32_t buffer_size_ = 0;
  std::vector<std::int32_t> indexes_;
  std::size_t next_ = 0;
  bool closed_ = false;
};

class LocalOutputBlockStream final : public OutputBlockStream {
public:
  LocalOutputBlockStream(LocalBufferFile &file, std::int32_t block_count,
                         LocalBufferFile::BlockCallback before,
                         LocalBufferFile::BlockCallback after)
      : state_(file.block_stream_state_), before_(std::move(before)),
        after_(std::move(after)) {
    if (block_count < 0)
      throw std::invalid_argument("negative block count");
    std::scoped_lock lock(state_->mutex);
    if (!state_->owner || state_->closing || state_->output_failed ||
        state_->owner->read_only()) {
      throw std::logic_error(
          "block output requires a writable LocalBufferFile");
    }
    if (state_->active_output) {
      throw std::logic_error(
          "LocalBufferFile already has an output block stream");
    }
    output_state_ = std::make_shared<LocalBufferFile::OutputStreamState>(
        state_->owner->file_id(), state_->owner->block_size(), block_count);
    state_->active_output = output_state_;
  }
  ~LocalOutputBlockStream() override {
    try {
      close();
    } catch (...) {
    }
  }
  std::int32_t block_count() const noexcept override {
    return output_state_->block_count;
  }
  std::int32_t block_size() const noexcept override {
    return output_state_->block_size;
  }
  void write_block(const BufferFileBlock &block) override {
    std::scoped_lock lock(output_state_->mutex);
    if (output_state_->closed)
      throw std::logic_error("block output stream is closed");
    std::scoped_lock owner_lock(state_->mutex);
    if (!state_->owner || state_->closing ||
        state_->active_output != output_state_)
      throw std::logic_error("block output owner is closed");
    if (block.size() !=
        static_cast<std::size_t>(output_state_->block_size)) {
      throw std::invalid_argument("incompatible output block size");
    }
    try {
      if (before_)
        before_(block.index());
      state_->owner->write_raw_block(block.index(), block.data());
      if (block.index() == 0)
        output_state_->refresh_header = true;
      if (after_)
        after_(block.index());
    }
    catch (...) {
      state_->output_failed = true;
      throw;
    }
  }
  void close() override {
    std::scoped_lock lock(output_state_->mutex);
    if (output_state_->closed)
      return;
    output_state_->closed = true;
    std::scoped_lock owner_lock(state_->mutex);
    if (!state_->owner || state_->active_output != output_state_)
      return;
    state_->owner->finish_output_stream(output_state_);
  }

private:
  std::shared_ptr<LocalBufferFile::BlockStreamState> state_;
  std::shared_ptr<LocalBufferFile::OutputStreamState> output_state_;
  LocalBufferFile::BlockCallback before_;
  LocalBufferFile::BlockCallback after_;
};

std::unique_ptr<InputBlockStream> LocalBufferFile::input_block_stream() {
  return std::make_unique<LocalFileInputBlockStream>(*this);
}

std::unique_ptr<InputBlockStream> LocalBufferFile::buffer_input_block_stream() {
  return std::make_unique<LocalBufferInputBlockStream>(*this);
}

std::unique_ptr<InputBlockStream> LocalBufferFile::input_block_stream(
    std::span<const std::uint8_t> change_map_data) {
  return std::make_unique<LocalRandomInputBlockStream>(*this, change_map_data);
}

std::unique_ptr<OutputBlockStream>
LocalBufferFile::output_block_stream(std::int32_t block_count) {
  return make_output_block_stream(block_count, {}, {});
}

std::unique_ptr<OutputBlockStream>
LocalBufferFile::make_output_block_stream(std::int32_t block_count,
                                          BlockCallback before_write,
                                          BlockCallback after_write) {
  return std::make_unique<LocalOutputBlockStream>(
      *this, block_count, std::move(before_write), std::move(after_write));
}

void transfer_blocks(InputBlockStream &input, OutputBlockStream &output,
                     const TaskContext &task) {
  if (input.block_size() != output.block_size() ||
      input.block_count() != output.block_count()) {
    throw std::invalid_argument("incompatible block streams");
  }

  auto cancel_registration = task.cancellation.register_callback([&] {
    try {
      input.close();
    } catch (...) {
    }
    try {
      output.close();
    } catch (...) {
    }
  });

  const auto total = static_cast<std::uint64_t>(
      (std::max)(input.block_count(), std::int32_t{0}));
  std::int32_t transferred = 0;
  try {
    task.report("block-transfer", 0, total);
    while (auto block = input.read_block()) {
      task.checkpoint();
      output.write_block(*block);
      ++transferred;
      task.report("block-transfer", static_cast<std::uint64_t>(transferred),
                  total);
    }
    task.checkpoint();
  } catch (...) {
    // Match fixed Java's finally check: cancellation is the externally visible
    // result even if closing a blocked stream surfaced another exception.
    task.checkpoint();
    throw;
  }
  if (transferred != input.block_count()) {
    throw std::runtime_error("unexpected block transfer count");
  }
}

} // namespace llmghidra::db
