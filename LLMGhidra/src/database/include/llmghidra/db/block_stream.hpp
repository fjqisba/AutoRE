/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/local_buffer_file.hpp"
#include "llmghidra/task_control.hpp"

#include <cstdint>
#include <optional>

namespace llmghidra::db {

class InputBlockStream {
public:
  virtual ~InputBlockStream() = default;
  InputBlockStream(const InputBlockStream &) = delete;
  InputBlockStream &operator=(const InputBlockStream &) = delete;

  [[nodiscard]] virtual std::int32_t block_count() const noexcept = 0;
  [[nodiscard]] virtual std::int32_t block_size() const noexcept = 0;
  [[nodiscard]] virtual bool includes_header_block() const noexcept = 0;
  virtual std::optional<BufferFileBlock> read_block() = 0;
  virtual void close() = 0;

protected:
  InputBlockStream() = default;
};

class OutputBlockStream {
public:
  virtual ~OutputBlockStream() = default;
  OutputBlockStream(const OutputBlockStream &) = delete;
  OutputBlockStream &operator=(const OutputBlockStream &) = delete;

  [[nodiscard]] virtual std::int32_t block_count() const noexcept = 0;
  [[nodiscard]] virtual std::int32_t block_size() const noexcept = 0;
  virtual void write_block(const BufferFileBlock &block) = 0;
  virtual void close() = 0;

protected:
  OutputBlockStream() = default;
};

// Transfers exactly the advertised number of blocks. Normal completion closes
// neither side. Cancellation closes both streams before reporting
// OperationCancelled so a blocking/remote implementation can release I/O.
// Header-less streams require the caller to copy parameters and free indexes.
void transfer_blocks(InputBlockStream &input, OutputBlockStream &output,
                     const TaskContext &task = {});

} // namespace llmghidra::db
