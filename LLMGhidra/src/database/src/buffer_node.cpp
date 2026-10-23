/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/buffer_node.hpp"

#include <stdexcept>
#include <string>

namespace llmghidra::db {
namespace {

void require_unlinked(BufferNode *previous, BufferNode *next,
                      const char *list_name) {
  if (previous || next) {
    throw std::logic_error(std::string("BufferNode is already linked in ") +
                           list_name);
  }
}

void require_linked(BufferNode *previous, BufferNode *next,
                    const char *list_name) {
  if (!previous || !next) {
    throw std::logic_error(std::string("BufferNode is not linked in ") +
                           list_name);
  }
}

} // namespace

void BufferNode::remove_from_cache() {
  require_linked(previous_cached, next_cached, "cache list");
  previous_cached->next_cached = next_cached;
  next_cached->previous_cached = previous_cached;
  next_cached = nullptr;
  previous_cached = nullptr;
}

void BufferNode::add_to_cache(BufferNode &head) {
  require_unlinked(previous_cached, next_cached, "cache list");
  if (!head.next_cached || !head.next_cached->previous_cached) {
    throw std::logic_error("cache head is not initialized");
  }
  previous_cached = &head;
  next_cached = head.next_cached;
  head.next_cached->previous_cached = this;
  head.next_cached = this;
}

void BufferNode::remove_from_checkpoint() {
  require_linked(previous_in_checkpoint, next_in_checkpoint,
                 "checkpoint list");
  previous_in_checkpoint->next_in_checkpoint = next_in_checkpoint;
  next_in_checkpoint->previous_in_checkpoint = previous_in_checkpoint;
  next_in_checkpoint = nullptr;
  previous_in_checkpoint = nullptr;
}

void BufferNode::add_to_checkpoint(BufferNode &head) {
  require_unlinked(previous_in_checkpoint, next_in_checkpoint,
                   "checkpoint list");
  if (!head.next_in_checkpoint ||
      !head.next_in_checkpoint->previous_in_checkpoint) {
    throw std::logic_error("checkpoint head is not initialized");
  }
  previous_in_checkpoint = &head;
  next_in_checkpoint = head.next_in_checkpoint;
  head.next_in_checkpoint->previous_in_checkpoint = this;
  head.next_in_checkpoint = this;
}

void BufferNode::remove_from_version() {
  require_linked(previous_version, next_version, "version list");
  previous_version->next_version = next_version;
  next_version->previous_version = previous_version;
  next_version = nullptr;
  previous_version = nullptr;
}

void BufferNode::add_to_version(BufferNode &head) {
  require_unlinked(previous_version, next_version, "version list");
  if (!head.next_version || !head.next_version->previous_version) {
    throw std::logic_error("version head is not initialized");
  }
  previous_version = &head;
  next_version = head.next_version;
  head.next_version->previous_version = this;
  head.next_version = this;
}

} // namespace llmghidra::db
