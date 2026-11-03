/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/index_provider.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace llmghidra::db {

IndexProvider::IndexProvider(
    std::int32_t index_count,
    std::span<const std::int32_t> free_indexes)
    : next_index_(index_count),
      free_indexes_(free_indexes.begin(), free_indexes.end()) {
  if (index_count < 0) {
    throw std::invalid_argument("negative allocated index count");
  }
  for (const auto index : free_indexes_) {
    if (index < 0 || index >= next_index_) {
      throw std::invalid_argument("free index is outside allocated range");
    }
  }
}

std::int32_t IndexProvider::allocate() {
  if (!free_indexes_.empty()) {
    const auto index = free_indexes_.back();
    free_indexes_.pop_back();
    return index;
  }
  if (next_index_ == std::numeric_limits<std::int32_t>::max()) {
    throw std::overflow_error("buffer index space exhausted");
  }
  return next_index_++;
}

bool IndexProvider::allocate(std::int32_t index) {
  if (index < 0) throw std::invalid_argument("negative buffer index");
  if (index >= next_index_) {
    if (index == std::numeric_limits<std::int32_t>::max()) {
      throw std::overflow_error("buffer index space exhausted");
    }
    for (auto gap = next_index_; gap < index; ++gap) {
      free_indexes_.push_back(gap);
    }
    next_index_ = index + 1;
    return true;
  }
  const auto found = (std::find)(free_indexes_.begin(), free_indexes_.end(), index);
  if (found == free_indexes_.end()) return false;
  free_indexes_.erase(found);
  return true;
}

bool IndexProvider::is_free(std::int32_t index) const noexcept {
  return (std::find)(free_indexes_.begin(), free_indexes_.end(), index) !=
         free_indexes_.end();
}

void IndexProvider::free(std::int32_t index) {
  if (index < 0 || index >= next_index_) {
    throw std::invalid_argument("freed index is outside allocated range");
  }
  free_indexes_.push_back(index);
}

bool IndexProvider::truncate(std::int32_t new_index_count) {
  if (new_index_count < 0) {
    throw std::invalid_argument("negative truncated index count");
  }
  if (new_index_count >= next_index_) return false;
  next_index_ = new_index_count;
  free_indexes_.erase(
      (std::remove_if)(free_indexes_.begin(), free_indexes_.end(),
                       [new_index_count](std::int32_t index) {
                         return index >= new_index_count;
                       }),
      free_indexes_.end());
  return true;
}

} // namespace llmghidra::db
