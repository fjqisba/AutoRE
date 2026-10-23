/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/storage_integrity.hpp"

#include <sstream>
#include <utility>

namespace llmghidra::db {
namespace {

std::string make_message(StorageIntegrityCode code, std::int32_t buffer_id,
                         std::string_view owner, std::string_view detail) {
  std::ostringstream message;
  message << storage_integrity_code_name(code) << ": buffer=" << buffer_id
          << "; owner=" << owner;
  if (!detail.empty())
    message << "; detail=" << detail;
  return message.str();
}

} // namespace

std::string_view
storage_integrity_code_name(StorageIntegrityCode code) noexcept {
  switch (code) {
  case StorageIntegrityCode::invalid_buffer_reference:
    return "invalid-buffer-reference";
  case StorageIntegrityCode::wrong_node_family:
    return "wrong-node-family";
  case StorageIntegrityCode::node_cycle:
    return "node-cycle";
  case StorageIntegrityCode::duplicate_node_ownership:
    return "duplicate-node-ownership";
  case StorageIntegrityCode::leaf_link_mismatch:
    return "leaf-link-mismatch";
  case StorageIntegrityCode::chained_buffer_invalid_length:
    return "chained-buffer-invalid-length";
  case StorageIntegrityCode::chained_buffer_truncated:
    return "chained-buffer-truncated";
  case StorageIntegrityCode::chained_buffer_cycle:
    return "chained-buffer-cycle";
  case StorageIntegrityCode::chained_buffer_node_family:
    return "chained-buffer-node-family";
  case StorageIntegrityCode::duplicate_buffer_ownership:
    return "duplicate-buffer-ownership";
  case StorageIntegrityCode::orphan_buffer:
    return "orphan-buffer";
  case StorageIntegrityCode::btree_invariant:
    return "btree-invariant";
  case StorageIntegrityCode::record_count_mismatch:
    return "record-count-mismatch";
  case StorageIntegrityCode::index_content_mismatch:
    return "index-content-mismatch";
  }
  return "unknown-storage-integrity-error";
}

StorageIntegrityError::StorageIntegrityError(StorageIntegrityCode code,
                                             std::int32_t buffer_id,
                                             std::string owner,
                                             std::string detail)
    : std::runtime_error(make_message(code, buffer_id, owner, detail)),
      code_(code), buffer_id_(buffer_id), owner_(std::move(owner)) {}

} // namespace llmghidra::db
