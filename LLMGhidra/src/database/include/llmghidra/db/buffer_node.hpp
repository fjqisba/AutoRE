/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace llmghidra::db {

// Intrusive list node used independently by cache, version and checkpoint
// chains. List ownership remains with BufferManager; links never own nodes.
class BufferNode final {
public:
  BufferNode(std::int32_t id, std::int32_t checkpoint)
      : id(id), checkpoint(checkpoint) {}
  BufferNode(const BufferNode &) = delete;
  BufferNode &operator=(const BufferNode &) = delete;
  BufferNode(BufferNode &&) = delete;
  BufferNode &operator=(BufferNode &&) = delete;

  void clear_snapshot_taken() noexcept { snapshot_taken = {false, false}; }
  void remove_from_cache();
  void add_to_cache(BufferNode &head);
  void remove_from_checkpoint();
  void add_to_checkpoint(BufferNode &head);
  void remove_from_version();
  void add_to_version(BufferNode &head);

  BufferNode *next_cached = nullptr;
  BufferNode *previous_cached = nullptr;
  BufferNode *next_version = nullptr;
  BufferNode *previous_version = nullptr;
  BufferNode *next_in_checkpoint = nullptr;
  BufferNode *previous_in_checkpoint = nullptr;

  const std::int32_t id;
  std::int32_t checkpoint;
  std::unique_ptr<DataBuffer> buffer;
  std::int32_t disk_cache_index = -1;
  bool locked = false;
  bool empty = false;
  bool modified = false;
  bool dirty = false;
  std::array<bool, 2> snapshot_taken{false, false};
};

} // namespace llmghidra::db
