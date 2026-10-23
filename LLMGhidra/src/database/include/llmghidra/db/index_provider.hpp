/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace llmghidra::db {

class IndexProvider final {
public:
  IndexProvider() = default;
  IndexProvider(std::int32_t index_count,
                std::span<const std::int32_t> free_indexes);

  [[nodiscard]] std::int32_t index_count() const noexcept { return next_index_; }
  [[nodiscard]] std::size_t free_index_count() const noexcept {
    return free_indexes_.size();
  }
  [[nodiscard]] std::int32_t allocate();
  [[nodiscard]] bool allocate(std::int32_t index);
  [[nodiscard]] bool is_free(std::int32_t index) const noexcept;
  void free(std::int32_t index);
  [[nodiscard]] bool truncate(std::int32_t new_index_count);
  [[nodiscard]] const std::vector<std::int32_t> &free_indexes() const noexcept {
    return free_indexes_;
  }

private:
  std::int32_t next_index_ = 0;
  std::vector<std::int32_t> free_indexes_;
};

} // namespace llmghidra::db
