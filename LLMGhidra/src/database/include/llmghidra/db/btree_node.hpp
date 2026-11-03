/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/task_control.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace llmghidra::db {

class InteriorNode;

class BTreeNode {
public:
  virtual ~BTreeNode() = default;
  [[nodiscard]] virtual InteriorNode *parent() const noexcept = 0;
  [[nodiscard]] virtual std::int32_t buffer_id() const noexcept = 0;
  [[nodiscard]] virtual const std::shared_ptr<DataBuffer> &
  buffer_handle() const noexcept = 0;
  [[nodiscard]] virtual std::size_t key_count() const noexcept = 0;
  virtual void set_key_count(std::size_t count) = 0;
  [[nodiscard]] virtual std::unique_ptr<Field>
  key_field(std::size_t index) const = 0;
  [[nodiscard]] virtual std::ptrdiff_t key_index(const Field &key) const = 0;
  virtual void delete_tree() = 0;
  [[nodiscard]] virtual std::vector<std::int32_t> buffer_references() const = 0;
  [[nodiscard]] virtual bool consistent(const TaskContext &task = {}) = 0;
};

class InteriorNode {
public:
  virtual ~InteriorNode() = default;
};

class RecordNode {
public:
  virtual ~RecordNode() = default;
  [[nodiscard]] virtual std::ptrdiff_t
  record_offset(std::size_t index) const = 0;
  [[nodiscard]] virtual std::size_t key_offset(std::size_t index) const = 0;
};

} // namespace llmghidra::db
