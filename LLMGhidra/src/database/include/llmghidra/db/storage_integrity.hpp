/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace llmghidra::db {

// Stable, machine-readable categories for native database storage audits.
// Callers should branch on the enum rather than parsing exception text.
enum class StorageIntegrityCode : std::uint8_t {
  invalid_buffer_reference,
  wrong_node_family,
  node_cycle,
  duplicate_node_ownership,
  leaf_link_mismatch,
  chained_buffer_invalid_length,
  chained_buffer_truncated,
  chained_buffer_cycle,
  chained_buffer_node_family,
  duplicate_buffer_ownership,
  orphan_buffer,
  btree_invariant,
  record_count_mismatch,
  index_content_mismatch,
};

[[nodiscard]] std::string_view
storage_integrity_code_name(StorageIntegrityCode code) noexcept;

class StorageIntegrityError final : public std::runtime_error {
public:
  StorageIntegrityError(StorageIntegrityCode code, std::int32_t buffer_id,
                        std::string owner, std::string detail = {});

  [[nodiscard]] StorageIntegrityCode code() const noexcept { return code_; }
  [[nodiscard]] std::int32_t buffer_id() const noexcept { return buffer_id_; }
  [[nodiscard]] const std::string &owner() const noexcept { return owner_; }

private:
  StorageIntegrityCode code_;
  std::int32_t buffer_id_;
  std::string owner_;
};

struct StorageGraphAudit final {
  std::vector<std::int32_t> buffer_ids;
  std::size_t interior_node_count = 0;
  std::size_t record_node_count = 0;
  std::size_t chained_buffer_count = 0;
  std::size_t record_count = 0;
};

struct StorageAuditOptions final {
  // DBHandle::consistent preserves the fixed Java contract and checks table
  // graphs without rejecting application-owned raw buffers. A strict storage
  // audit enables this and/or supplies the complete set of buffer IDs owned by
  // ProgramDB or another application-level manager below.
  bool reject_unclaimed_buffers = true;
  std::vector<std::int32_t> externally_owned_buffer_ids;
};

} // namespace llmghidra::db
