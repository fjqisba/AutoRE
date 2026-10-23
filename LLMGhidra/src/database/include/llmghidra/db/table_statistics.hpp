/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llmghidra::db {

// Diagnostic counters matching db.TableStatistics.  size_bytes includes both
// B-Tree node buffers and buffers owned by indirect ChainedBuffer records.
struct TableStatistics {
  std::string name;
  std::int32_t index_column = -1;
  std::size_t buffer_count = 0;
  std::size_t size_bytes = 0;
  std::size_t interior_node_count = 0;
  std::size_t record_node_count = 0;
  std::size_t chained_buffer_count = 0;
};

} // namespace llmghidra::db
