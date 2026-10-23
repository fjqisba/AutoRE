/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstdint>
#include <limits>

namespace llmghidra::db::detail {

constexpr std::int64_t saturated_multiply(std::int64_t value,
                                          std::int64_t factor) noexcept {
  if (value > 0 && value > (std::numeric_limits<std::int64_t>::max)() / factor)
    return (std::numeric_limits<std::int64_t>::max)();
  if (value < 0 && value < (std::numeric_limits<std::int64_t>::min)() / factor)
    return (std::numeric_limits<std::int64_t>::min)();
  return value * factor;
}

constexpr std::int64_t saturated_subtract(std::int64_t left,
                                          std::int64_t right) noexcept {
  if (right > 0 && left < (std::numeric_limits<std::int64_t>::min)() + right)
    return (std::numeric_limits<std::int64_t>::min)();
  if (right < 0 && left > (std::numeric_limits<std::int64_t>::max)() + right)
    return (std::numeric_limits<std::int64_t>::max)();
  return left - right;
}

constexpr std::int64_t saturated_add(std::int64_t left,
                                     std::int64_t right) noexcept {
  if (right > 0 && left > (std::numeric_limits<std::int64_t>::max)() - right)
    return (std::numeric_limits<std::int64_t>::max)();
  if (right < 0 && left < (std::numeric_limits<std::int64_t>::min)() - right)
    return (std::numeric_limits<std::int64_t>::min)();
  return left + right;
}

constexpr bool
lock_timestamp_is_stale(std::int64_t modified, std::int64_t local_now,
                        std::int64_t lease_duration,
                        std::int64_t filesystem_clock_delta) noexcept {
  const auto filesystem_now =
      saturated_subtract(local_now, filesystem_clock_delta);
  const auto stale_before = saturated_subtract(filesystem_now, lease_duration);
  return modified < stale_before;
}

} // namespace llmghidra::db::detail
