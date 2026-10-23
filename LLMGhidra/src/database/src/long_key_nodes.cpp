/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/long_key_nodes.hpp"

#include "llmghidra/db/chained_buffer.hpp"
#include "llmghidra/db/node_manager.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {
namespace {

std::int32_t checked_chained_length(std::size_t length) {
  if (length == 0 || length > static_cast<std::size_t>(
                                  std::numeric_limits<std::int32_t>::max())) {
    throw std::length_error(
        "record length cannot be represented by ChainedBuffer");
  }
  return static_cast<std::int32_t>(length);
}

} // namespace

LongKeyNode::LongKeyNode(NodeManager &manager,
                         std::shared_ptr<DataBuffer> buffer)
    : manager_(manager), buffer_(std::move(buffer)) {
  const auto stored_count = buffer_->get_i32(key_count_offset);
  if (stored_count < 0)
    throw std::runtime_error("negative B-Tree key count");
  key_count_ = static_cast<std::size_t>(stored_count);
}

LongKeyNode::LongKeyNode(NodeManager &manager, std::uint8_t node_type)
    : manager_(manager), buffer_(manager.buffer_manager().create_buffer()) {
  NodeManager::set_node_type(*buffer_,
                             static_cast<NodeManager::NodeType>(node_type));
  set_key_count(0);
}

InteriorNode *LongKeyNode::parent() const noexcept { return parent_; }

void LongKeyNode::set_key_count(std::size_t count) {
  if (!buffer_)
    throw std::logic_error("invalidated B-Tree node");
  if (count >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::overflow_error("B-Tree key count exceeds int32");
  }
  buffer_->put_i32(key_count_offset, static_cast<std::int32_t>(count));
  key_count_ = count;
}

std::unique_ptr<Field> LongKeyNode::key_field(std::size_t index) const {
  if (!buffer_)
    throw std::logic_error("invalidated long-key B-Tree node");
  return std::make_unique<IntegerField>(FieldType::int64, key_at(index));
}

std::shared_ptr<LongKeyNode> LongKeyNode::root() {
  if (parent_)
    return parent_->root();
  return shared_from_this();
}

LongKeyInteriorNode::LongKeyInteriorNode(NodeManager &manager,
                                         std::shared_ptr<DataBuffer> existing)
    : LongKeyNode(manager, std::move(existing)) {
  maximum_key_count_ = (buffer_->size() - entry_base_offset) / entry_size;
  if (key_count_ > maximum_key_count_) {
    throw std::runtime_error(
        "long-key interior node key count exceeds capacity");
  }
}

LongKeyInteriorNode::LongKeyInteriorNode(NodeManager &manager,
                                         std::int64_t left_key,
                                         std::int32_t left_id,
                                         std::int64_t right_key,
                                         std::int32_t right_id)
    : LongKeyNode(manager, static_cast<std::uint8_t>(
                               NodeManager::NodeType::long_key_interior)) {
  maximum_key_count_ = (buffer_->size() - entry_base_offset) / entry_size;
  if (maximum_key_count_ < 2 || left_key >= right_key || left_id < 0 ||
      right_id < 0) {
    throw std::invalid_argument("invalid initial long-key interior entries");
  }
  put_entry(0, left_key, left_id);
  put_entry(1, right_key, right_id);
  set_key_count(2);
}

LongKeyInteriorNode::LongKeyInteriorNode(NodeManager &manager)
    : LongKeyNode(manager, static_cast<std::uint8_t>(
                               NodeManager::NodeType::long_key_interior)) {
  maximum_key_count_ = (buffer_->size() - entry_base_offset) / entry_size;
  if (maximum_key_count_ < 2) {
    throw std::runtime_error("buffer is too small for long-key interior node");
  }
}

std::int64_t LongKeyInteriorNode::key_at(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("interior key index");
  return buffer_->get_i64(entry_base_offset + index * entry_size);
}

std::int32_t LongKeyInteriorNode::child_id(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("interior child index");
  return buffer_->get_i32(entry_base_offset + index * entry_size + key_size);
}

std::ptrdiff_t LongKeyInteriorNode::key_index(std::int64_t key) const {
  std::size_t minimum = 0;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    const auto candidate = key_at(index);
    if (candidate == key)
      return static_cast<std::ptrdiff_t>(index);
    if (candidate < key)
      minimum = index + 1;
    else
      maximum = index;
  }
  return -static_cast<std::ptrdiff_t>(minimum) - 1;
}

std::ptrdiff_t LongKeyInteriorNode::key_index(const Field &key) const {
  return key_index(key.as_integer());
}

std::size_t LongKeyInteriorNode::child_index(std::int64_t key) const {
  if (key_count_ == 0)
    throw std::logic_error("empty interior node");
  std::size_t minimum = 1;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    if (key_at(index) <= key)
      minimum = index + 1;
    else
      maximum = index;
  }
  return minimum - 1;
}

void LongKeyInteriorNode::put_key(std::size_t index, std::int64_t key) {
  if (index >= key_count_)
    throw std::out_of_range("interior key index");
  buffer_->put_i64(entry_base_offset + index * entry_size, key);
}

void LongKeyInteriorNode::put_entry(std::size_t index, std::int64_t key,
                                    std::int32_t id) {
  const auto offset = entry_base_offset + index * entry_size;
  buffer_->put_i64(offset, key);
  buffer_->put_i32(offset + key_size, id);
}

void LongKeyInteriorNode::insert_entry(std::size_t index, std::int64_t key,
                                       std::int32_t id) {
  if (index > key_count_ || key_count_ >= maximum_key_count_) {
    throw std::logic_error("invalid interior insertion");
  }
  const auto start = entry_base_offset + index * entry_size;
  const auto length = (key_count_ - index) * entry_size;
  buffer_->move(start, start + entry_size, length);
  put_entry(index, key, id);
  set_key_count(key_count_ + 1);
}

void LongKeyInteriorNode::delete_entry(std::size_t index) {
  if (key_count_ < 3 || index >= key_count_) {
    throw std::logic_error("invalid interior deletion");
  }
  if (index + 1 < key_count_) {
    const auto start = entry_base_offset + (index + 1) * entry_size;
    buffer_->move(start, start - entry_size,
                  (key_count_ - index - 1) * entry_size);
  }
  set_key_count(key_count_ - 1);
}

void LongKeyInteriorNode::child_key_changed(std::int64_t old_key,
                                            std::int64_t new_key) {
  const auto found = key_index(old_key);
  if (found < 0)
    throw std::logic_error("old child key not found");
  const auto index = static_cast<std::size_t>(found);
  put_key(index, new_key);
  if (index == 0 && parent_)
    parent_->child_key_changed(old_key, new_key);
}

std::shared_ptr<LongKeyRecordNode>
LongKeyInteriorNode::leaf_for(std::int64_t key) {
  auto child = manager_.get_long_key_node(child_id(child_index(key)));
  child->parent_ = this;
  return child->leaf_for(key);
}

std::shared_ptr<LongKeyNode>
LongKeyInteriorNode::insert_child(std::int32_t id, std::int64_t key) {
  if (key_count_ == maximum_key_count_)
    return split_and_insert(key, id);
  const auto result = key_index(key);
  if (result >= 0 || id < 0) {
    throw std::logic_error("duplicate key or invalid child id");
  }
  const auto index = static_cast<std::size_t>(-result - 1);
  insert_entry(index, key, id);
  if (index == 0 && parent_) {
    parent_->child_key_changed(key_at(1), key);
  }
  return root();
}

void LongKeyInteriorNode::move_keys_right(LongKeyInteriorNode &left,
                                          LongKeyInteriorNode &right,
                                          std::size_t count) {
  if (count == 0 || count > left.key_count_) {
    throw std::logic_error("invalid rightward key move");
  }
  const auto left_offset =
      entry_base_offset + (left.key_count_ - count) * entry_size;
  const auto length = count * entry_size;
  right.buffer_->move(entry_base_offset, entry_base_offset + length,
                      right.key_count_ * entry_size);
  right.buffer_->copy(entry_base_offset, *left.buffer_, left_offset, length);
  left.set_key_count(left.key_count_ - count);
  right.set_key_count(right.key_count_ + count);
}

void LongKeyInteriorNode::move_keys_left(LongKeyInteriorNode &left,
                                         LongKeyInteriorNode &right,
                                         std::size_t count) {
  if (count == 0 || count > right.key_count_) {
    throw std::logic_error("invalid leftward key move");
  }
  const auto left_offset = entry_base_offset + left.key_count_ * entry_size;
  const auto length = count * entry_size;
  left.buffer_->copy(left_offset, *right.buffer_, entry_base_offset, length);
  left.set_key_count(left.key_count_ + count);
  if (count < right.key_count_) {
    const auto remaining = right.key_count_ - count;
    right.buffer_->move(entry_base_offset + length, entry_base_offset,
                        remaining * entry_size);
    right.set_key_count(remaining);
  }
}

std::shared_ptr<LongKeyNode>
LongKeyInteriorNode::split_and_insert(std::int64_t key, std::int32_t id) {
  auto right = manager_.create_empty_long_key_interior();
  move_keys_right(*this, *right, key_count_ / 2);
  const auto right_key = right->key_at(0);
  if (key < right_key)
    (void)insert_child(id, key);
  else
    (void)right->insert_child(id, key);

  if (parent_)
    return parent_->insert_child(right->buffer_id(), right_key);
  return manager_.create_long_key_interior(key_at(0), buffer_id(), right_key,
                                           right->buffer_id());
}

std::shared_ptr<LongKeyNode>
LongKeyInteriorNode::delete_child(std::int64_t key) {
  const auto found = key_index(key);
  if (found < 0)
    throw std::logic_error("child key not found for deletion");
  const auto index = static_cast<std::size_t>(found);
  if (key_count_ == 2) {
    if (parent_)
      throw std::logic_error("non-root interior has two children");
    auto new_root = manager_.get_long_key_node(child_id(1 - index));
    new_root->parent_ = nullptr;
    manager_.delete_node(shared_from_this());
    return new_root;
  }
  delete_entry(index);
  if (index == 0 && parent_)
    parent_->child_key_changed(key, key_at(0));
  return parent_ ? parent_->balance_child(*this) : shared_from_this();
}

std::shared_ptr<LongKeyNode>
LongKeyInteriorNode::balance_child(LongKeyInteriorNode &node) {
  if (node.key_count_ > maximum_key_count_ / 2)
    return root();
  const auto index = child_index(node.key_at(0));
  if (index == key_count_ - 1) {
    auto left = std::dynamic_pointer_cast<LongKeyInteriorNode>(
        manager_.get_long_key_node(child_id(index - 1)));
    if (!left)
      throw std::logic_error("interior sibling type mismatch");
    return balance_pair(*left, node);
  }
  auto right = std::dynamic_pointer_cast<LongKeyInteriorNode>(
      manager_.get_long_key_node(child_id(index + 1)));
  if (!right)
    throw std::logic_error("interior sibling type mismatch");
  return balance_pair(node, *right);
}

std::shared_ptr<LongKeyNode>
LongKeyInteriorNode::balance_pair(LongKeyInteriorNode &left,
                                  LongKeyInteriorNode &right) {
  const auto right_key = right.key_at(0);
  const auto total = left.key_count_ + right.key_count_;
  if (total <= maximum_key_count_) {
    move_keys_left(left, right, right.key_count_);
    manager_.delete_node(right.shared_from_this());
    return delete_child(right_key);
  }
  const auto new_left_count = total / 2;
  if (new_left_count < left.key_count_) {
    move_keys_right(left, right, left.key_count_ - new_left_count);
  } else if (new_left_count > left.key_count_) {
    move_keys_left(left, right, new_left_count - left.key_count_);
  }
  child_key_changed(right_key, right.key_at(0));
  return root();
}

void LongKeyInteriorNode::delete_tree() {
  const auto ids = buffer_references();
  for (const auto id : ids)
    manager_.get_long_key_node(id)->delete_tree();
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t> LongKeyInteriorNode::buffer_references() const {
  std::vector<std::int32_t> result;
  result.reserve(key_count_);
  for (std::size_t index = 0; index < key_count_; ++index) {
    result.push_back(child_id(index));
  }
  return result;
}

bool LongKeyInteriorNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  task.checkpoint();
  if (key_count_ < 2 || key_count_ > maximum_key_count_)
    return false;
  std::int64_t previous_maximum = 0;
  for (std::size_t index = 0; index < key_count_; ++index) {
    task.checkpoint();
    if (index != 0 && key_at(index) <= previous_maximum)
      return false;
    auto child = manager_.get_long_key_node(child_id(index));
    if (child->key_count() == 0 || child->key_at(0) != key_at(index)) {
      return false;
    }
    child->parent_ = this;
    if (!child->consistent(task))
      return false;
    previous_maximum = child->key_at(child->key_count() - 1);
    task.checkpoint();
  }
  task.checkpoint();
  return true;
}

bool LongKeyInteriorNode::is_leftmost_key(std::int64_t key) const {
  if (child_index(key) != 0)
    return false;
  return parent_ ? parent_->is_leftmost_key(key) : true;
}

bool LongKeyInteriorNode::is_rightmost_key(std::int64_t key) const {
  if (child_index(key) != key_count_ - 1)
    return false;
  return parent_ ? parent_->is_rightmost_key(key_at(0)) : true;
}

LongKeyRecordNode::LongKeyRecordNode(NodeManager &manager,
                                     std::shared_ptr<DataBuffer> existing)
    : LongKeyNode(manager, std::move(existing)) {}

LongKeyRecordNode::LongKeyRecordNode(NodeManager &manager,
                                     std::uint8_t node_type,
                                     std::int32_t previous_leaf_id,
                                     std::int32_t next_leaf_id)
    : LongKeyNode(manager, node_type) {
  buffer_->put_i32(previous_leaf_id_offset, previous_leaf_id);
  buffer_->put_i32(next_leaf_id_offset, next_leaf_id);
}

std::ptrdiff_t LongKeyRecordNode::key_index(std::int64_t key) const {
  std::size_t minimum = 0;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    const auto candidate = key_at(index);
    if (candidate == key)
      return static_cast<std::ptrdiff_t>(index);
    if (candidate < key)
      minimum = index + 1;
    else
      maximum = index;
  }
  return -static_cast<std::ptrdiff_t>(minimum) - 1;
}

std::ptrdiff_t LongKeyRecordNode::key_index(const Field &key) const {
  return key_index(key.as_integer());
}

std::shared_ptr<LongKeyRecordNode>
LongKeyRecordNode::leaf_for(std::int64_t key) {
  (void)key;
  return std::static_pointer_cast<LongKeyRecordNode>(shared_from_this());
}

std::unique_ptr<Record> LongKeyRecordNode::record(std::int64_t key) const {
  const auto found = key_index(key);
  return found < 0 ? nullptr : record_at(static_cast<std::size_t>(found));
}

std::shared_ptr<LongKeyRecordNode> LongKeyRecordNode::next_leaf() const {
  const auto id = buffer_->get_i32(next_leaf_id_offset);
  if (id < 0)
    return nullptr;
  auto result = std::dynamic_pointer_cast<LongKeyRecordNode>(
      manager_.get_long_key_node(id));
  if (!result)
    throw std::logic_error("next leaf type mismatch");
  return result;
}

std::shared_ptr<LongKeyRecordNode> LongKeyRecordNode::previous_leaf() const {
  const auto id = buffer_->get_i32(previous_leaf_id_offset);
  if (id < 0)
    return nullptr;
  auto result = std::dynamic_pointer_cast<LongKeyRecordNode>(
      manager_.get_long_key_node(id));
  if (!result)
    throw std::logic_error("previous leaf type mismatch");
  return result;
}

std::unique_ptr<Record>
LongKeyRecordNode::record_before(std::int64_t key) const {
  auto index = key_index(key);
  index = index < 0 ? -index - 2 : index - 1;
  if (index < 0) {
    auto leaf = previous_leaf();
    return leaf ? leaf->record_at(leaf->key_count_ - 1) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::unique_ptr<Record>
LongKeyRecordNode::record_after(std::int64_t key) const {
  auto index = key_index(key);
  index = index < 0 ? -index - 1 : index + 1;
  if (static_cast<std::size_t>(index) == key_count_) {
    auto leaf = next_leaf();
    return leaf ? leaf->record_at(0) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::unique_ptr<Record>
LongKeyRecordNode::record_at_or_before(std::int64_t key) const {
  auto index = key_index(key);
  if (index < 0)
    index = -index - 2;
  if (index < 0) {
    auto leaf = previous_leaf();
    return leaf ? leaf->record_at(leaf->key_count_ - 1) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::unique_ptr<Record>
LongKeyRecordNode::record_at_or_after(std::int64_t key) const {
  auto index = key_index(key);
  if (index < 0)
    index = -index - 1;
  if (static_cast<std::size_t>(index) == key_count_) {
    auto leaf = next_leaf();
    return leaf ? leaf->record_at(0) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::shared_ptr<LongKeyNode> LongKeyRecordNode::split_leaf() {
  const auto old_next = buffer_->get_i32(next_leaf_id_offset);
  auto right = create_leaf(buffer_id(), old_next);
  buffer_->put_i32(next_leaf_id_offset, right->buffer_id());
  if (old_next >= 0) {
    auto old_sibling = std::dynamic_pointer_cast<LongKeyRecordNode>(
        manager_.get_long_key_node(old_next));
    if (!old_sibling)
      throw std::logic_error("leaf sibling type mismatch");
    old_sibling->buffer_->put_i32(previous_leaf_id_offset, right->buffer_id());
  }
  split_data(*right);
  if (parent_)
    return parent_->insert_child(right->buffer_id(), right->key_at(0));
  return manager_.create_long_key_interior(
      key_at(0), buffer_id(), right->key_at(0), right->buffer_id());
}

std::shared_ptr<LongKeyNode>
LongKeyRecordNode::append_leaf(const std::shared_ptr<LongKeyRecordNode> &leaf) {
  if (!leaf || leaf.get() == this || leaf->key_count_ == 0) {
    throw std::invalid_argument("invalid appended leaf");
  }
  leaf->buffer_->put_i32(previous_leaf_id_offset, buffer_id());
  const auto old_next = buffer_->get_i32(next_leaf_id_offset);
  leaf->buffer_->put_i32(next_leaf_id_offset, old_next);
  buffer_->put_i32(next_leaf_id_offset, leaf->buffer_id());
  if (old_next >= 0) {
    auto right = std::dynamic_pointer_cast<LongKeyRecordNode>(
        manager_.get_long_key_node(old_next));
    if (!right)
      throw std::logic_error("leaf sibling type mismatch");
    right->buffer_->put_i32(previous_leaf_id_offset, leaf->buffer_id());
  }
  if (parent_)
    return parent_->insert_child(leaf->buffer_id(), leaf->key_at(0));
  return manager_.create_long_key_interior(key_at(0), buffer_id(),
                                           leaf->key_at(0), leaf->buffer_id());
}

std::shared_ptr<LongKeyNode> LongKeyRecordNode::remove_leaf() {
  if (key_count_ == 0)
    throw std::logic_error("cannot remove empty leaf by key");
  const auto key = key_at(0);
  const auto previous_id = buffer_->get_i32(previous_leaf_id_offset);
  const auto next_id = buffer_->get_i32(next_leaf_id_offset);
  if (previous_id >= 0) {
    auto previous = std::dynamic_pointer_cast<LongKeyRecordNode>(
        manager_.get_long_key_node(previous_id));
    if (!previous)
      throw std::logic_error("leaf sibling type mismatch");
    previous->buffer_->put_i32(next_leaf_id_offset, next_id);
  }
  if (next_id >= 0) {
    auto next = std::dynamic_pointer_cast<LongKeyRecordNode>(
        manager_.get_long_key_node(next_id));
    if (!next)
      throw std::logic_error("leaf sibling type mismatch");
    next->buffer_->put_i32(previous_leaf_id_offset, previous_id);
  }
  auto old_parent = parent_;
  manager_.delete_node(shared_from_this());
  return old_parent ? old_parent->delete_child(key) : nullptr;
}

std::shared_ptr<LongKeyNode>
LongKeyRecordNode::put_record(Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("record schema differs from leaf schema");
  }
  const auto key = record_value.key().as_integer();
  auto index = key_index(key);
  if (index >= 0) {
    return update_record(static_cast<std::size_t>(index), record_value);
  }
  const auto insertion = static_cast<std::size_t>(-index - 1);
  if (insert_record(insertion, record_value)) {
    if (insertion == 0 && parent_) {
      parent_->child_key_changed(key_at(1), key);
    }
    return root();
  }
  if (insertion == key_count_) {
    auto leaf = create_leaf(-1, -1);
    if (!leaf->insert_record(0, record_value)) {
      throw std::logic_error("empty leaf rejected record");
    }
    return append_leaf(leaf);
  }
  auto new_root = split_leaf();
  return new_root->leaf_for(key)->put_record(record_value);
}

std::shared_ptr<LongKeyNode>
LongKeyRecordNode::delete_record(std::int64_t key) {
  const auto found = key_index(key);
  if (found < 0)
    return root();
  const auto index = static_cast<std::size_t>(found);
  if (key_count_ == 1)
    return remove_leaf();
  remove_record(index);
  if (index == 0 && parent_)
    parent_->child_key_changed(key, key_at(0));
  return root();
}

bool LongKeyRecordNode::leaf_links_and_keys_consistent(
    const TaskContext &task) {
  task.checkpoint();
  if (key_count_ == 0)
    return false;
  for (std::size_t index = 1; index < key_count_; ++index) {
    task.checkpoint();
    if (key_at(index) <= key_at(index - 1))
      return false;
  }
  task.checkpoint();
  auto previous = previous_leaf();
  auto next = next_leaf();
  if (previous &&
      previous->buffer_->get_i32(next_leaf_id_offset) != buffer_id()) {
    return false;
  }
  if (next && next->buffer_->get_i32(previous_leaf_id_offset) != buffer_id()) {
    return false;
  }
  if (parent_) {
    if (parent_->is_leftmost_key(key_at(0)) != (previous == nullptr))
      return false;
    if (parent_->is_rightmost_key(key_at(0)) != (next == nullptr))
      return false;
  }
  task.checkpoint();
  return true;
}

FixedRecordNode::FixedRecordNode(NodeManager &manager,
                                 std::shared_ptr<DataBuffer> existing,
                                 std::size_t record_length)
    : LongKeyRecordNode(manager, std::move(existing)),
      record_length_(record_length), entry_size_(key_size + record_length) {
  const auto capacity = (buffer_->size() - entry_base_offset) / entry_size_;
  if (entry_size_ == 0 || key_count_ > capacity) {
    throw std::runtime_error("fixed record node key count exceeds capacity");
  }
}

FixedRecordNode::FixedRecordNode(NodeManager &manager,
                                 std::size_t record_length,
                                 std::int32_t previous_leaf_id,
                                 std::int32_t next_leaf_id)
    : LongKeyRecordNode(manager,
                        static_cast<std::uint8_t>(
                            NodeManager::NodeType::long_key_fixed_record),
                        previous_leaf_id, next_leaf_id),
      record_length_(record_length), entry_size_(key_size + record_length) {
  if ((buffer_->size() - entry_base_offset) / entry_size_ == 0) {
    throw std::runtime_error("record is too large for fixed record node");
  }
}

std::size_t FixedRecordNode::key_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("record key index");
  return entry_base_offset + index * entry_size_;
}

std::ptrdiff_t FixedRecordNode::record_offset(std::size_t index) const {
  return static_cast<std::ptrdiff_t>(key_offset(index));
}

std::int64_t FixedRecordNode::key_at(std::size_t index) const {
  return buffer_->get_i64(key_offset(index));
}

std::unique_ptr<Record> FixedRecordNode::record_at(std::size_t index) const {
  const auto key = key_at(index);
  auto result = manager_.schema().create_record(key);
  result->read(*buffer_, key_offset(index) + key_size);
  return result;
}

void FixedRecordNode::shift_records(std::size_t index, bool right) {
  if (index == key_count_)
    return;
  const auto start = entry_base_offset + index * entry_size_;
  const auto length = (key_count_ - index) * entry_size_;
  buffer_->move(start, right ? start + entry_size_ : start - entry_size_,
                length);
}

bool FixedRecordNode::insert_record(std::size_t index, Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema()) ||
      record_value.storage_length() != record_length_) {
    throw std::invalid_argument("record schema differs from fixed leaf schema");
  }
  const auto capacity = (buffer_->size() - entry_base_offset) / entry_size_;
  if (key_count_ == capacity)
    return false;
  if (index > key_count_)
    throw std::out_of_range("record insertion index");
  shift_records(index, true);
  const auto offset = entry_base_offset + index * entry_size_;
  buffer_->put_i64(offset, record_value.key().as_integer());
  record_value.write(*buffer_, offset + key_size);
  set_key_count(key_count_ + 1);
  return true;
}

void FixedRecordNode::remove_record(std::size_t index) {
  if (index >= key_count_)
    throw std::out_of_range("record removal index");
  shift_records(index + 1, false);
  set_key_count(key_count_ - 1);
}

std::shared_ptr<LongKeyNode>
FixedRecordNode::update_record(std::size_t index, Record &record_value) {
  if (record_value.key().as_integer() != key_at(index) ||
      !record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("updated record key or schema differs");
  }
  record_value.write(*buffer_, key_offset(index) + key_size);
  return root();
}

std::shared_ptr<LongKeyRecordNode>
FixedRecordNode::create_leaf(std::int32_t previous_leaf_id,
                             std::int32_t next_leaf_id) {
  return manager_.create_fixed_record_node(previous_leaf_id, next_leaf_id);
}

void FixedRecordNode::split_data(LongKeyRecordNode &right_leaf) {
  auto *right = dynamic_cast<FixedRecordNode *>(&right_leaf);
  if (!right)
    throw std::logic_error("fixed leaf split type mismatch");
  const auto split_index = key_count_ / 2;
  const auto count = key_count_ - split_index;
  const auto start = entry_base_offset + split_index * entry_size_;
  const auto length = count * entry_size_;
  right->buffer_->copy(entry_base_offset, *buffer_, start, length);
  set_key_count(split_index);
  right->set_key_count(count);
}

void FixedRecordNode::delete_tree() {
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t> FixedRecordNode::buffer_references() const {
  return {};
}

bool FixedRecordNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  task.checkpoint();
  const auto capacity = (buffer_->size() - entry_base_offset) / entry_size_;
  return key_count_ <= capacity && leaf_links_and_keys_consistent(task);
}

VariableRecordNode::VariableRecordNode(NodeManager &manager,
                                       std::shared_ptr<DataBuffer> existing)
    : LongKeyRecordNode(manager, std::move(existing)) {
  if (key_count_ > (buffer_->size() - entry_base_offset) / entry_size) {
    throw std::runtime_error("variable record node key count exceeds capacity");
  }
}

VariableRecordNode::VariableRecordNode(NodeManager &manager,
                                       std::int32_t previous_leaf_id,
                                       std::int32_t next_leaf_id)
    : LongKeyRecordNode(manager,
                        static_cast<std::uint8_t>(
                            NodeManager::NodeType::long_key_variable_record),
                        previous_leaf_id, next_leaf_id) {
  if (buffer_->size() < entry_base_offset + entry_size + 1) {
    throw std::runtime_error("buffer is too small for variable record node");
  }
}

std::size_t VariableRecordNode::key_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("record key index");
  return entry_base_offset + index * entry_size;
}

std::int64_t VariableRecordNode::key_at(std::size_t index) const {
  return buffer_->get_i64(key_offset(index));
}

std::size_t VariableRecordNode::data_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("record data index");
  const auto value = buffer_->get_i32(record_offset_base + index * entry_size);
  if (value < 0)
    throw std::runtime_error("negative variable record offset");
  return static_cast<std::size_t>(value);
}

void VariableRecordNode::put_data_offset(std::size_t index,
                                         std::size_t offset) {
  if (index > key_count_ ||
      offset >
          static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::out_of_range("variable record offset");
  }
  buffer_->put_i32(record_offset_base + index * entry_size,
                   static_cast<std::int32_t>(offset));
}

bool VariableRecordNode::indirect(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("record indirect index");
  return buffer_->get_u8(indirect_flag_base + index * entry_size) != 0;
}

void VariableRecordNode::set_indirect(std::size_t index, bool state) {
  if (index >= key_count_)
    throw std::out_of_range("record indirect index");
  buffer_->put_u8(indirect_flag_base + index * entry_size,
                  state ? std::uint8_t{1} : std::uint8_t{0});
}

std::size_t VariableRecordNode::free_space() const {
  const auto data_begin =
      key_count_ == 0 ? buffer_->size() : data_offset(key_count_ - 1);
  const auto entries_end = entry_base_offset + key_count_ * entry_size;
  if (data_begin < entries_end) {
    throw std::runtime_error("variable record node entries overlap data");
  }
  return data_begin - entries_end;
}

std::size_t VariableRecordNode::stored_length(std::size_t index) const {
  return stored_length(index, data_offset(index));
}

std::size_t VariableRecordNode::stored_length(std::size_t index,
                                              std::size_t offset) const {
  if (index >= key_count_)
    throw std::out_of_range("record length index");
  const auto end = index == 0 ? buffer_->size() : data_offset(index - 1);
  if (offset > end)
    throw std::runtime_error("invalid variable record offsets");
  return end - offset;
}

std::size_t VariableRecordNode::move_records(std::size_t index,
                                             std::ptrdiff_t shift) {
  if (index > key_count_)
    throw std::out_of_range("record movement index");
  const auto shifted = [shift](std::size_t value) -> std::size_t {
    if (shift < 0) {
      const auto magnitude = static_cast<std::size_t>(-shift);
      if (magnitude > value)
        throw std::out_of_range("negative record movement");
      return value - magnitude;
    }
    const auto magnitude = static_cast<std::size_t>(shift);
    if (magnitude > std::numeric_limits<std::size_t>::max() - value) {
      throw std::overflow_error("record movement overflow");
    }
    return value + magnitude;
  };

  if (index == key_count_) {
    const auto end = index == 0 ? buffer_->size() : data_offset(key_count_ - 1);
    return shifted(end);
  }

  const auto start = data_offset(key_count_ - 1);
  const auto end = index == 0 ? buffer_->size() : data_offset(index - 1);
  if (start > end)
    throw std::runtime_error("invalid variable record block");
  buffer_->move(start, shifted(start), end - start);
  for (auto current = index; current < key_count_; ++current) {
    put_data_offset(current, shifted(data_offset(current)));
  }
  return shifted(end);
}

std::ptrdiff_t VariableRecordNode::record_offset(std::size_t index) const {
  const auto offset = data_offset(index);
  if (!indirect(index))
    return static_cast<std::ptrdiff_t>(offset);
  return -static_cast<std::ptrdiff_t>(buffer_->get_i32(offset));
}

std::unique_ptr<Record> VariableRecordNode::record_at(std::size_t index) const {
  auto result = manager_.schema().create_record(key_at(index));
  const auto offset = data_offset(index);
  if (indirect(index)) {
    const auto id = buffer_->get_i32(offset);
    ChainedBuffer chained(manager_.buffer_manager(), id);
    result->read(chained, 0);
  } else {
    result->read(*buffer_, offset);
  }
  return result;
}

std::size_t VariableRecordNode::maximum_inline_record_length() const {
  const auto quarter = (buffer_->size() - entry_base_offset) >> 2;
  return quarter > entry_size ? quarter - entry_size : 0;
}

bool VariableRecordNode::insert_record(std::size_t index,
                                       Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument(
        "record schema differs from variable leaf schema");
  }
  if (index > key_count_)
    throw std::out_of_range("record insertion index");
  const auto logical_length = record_value.storage_length();
  const auto use_indirect = logical_length > maximum_inline_record_length();
  const auto physical_length = use_indirect ? std::size_t{4} : logical_length;
  if (physical_length + entry_size > free_space())
    return false;

  const auto offset =
      move_records(index, -static_cast<std::ptrdiff_t>(physical_length));
  const auto entry_offset = entry_base_offset + index * entry_size;
  buffer_->move(entry_offset, entry_offset + entry_size,
                (key_count_ - index) * entry_size);
  buffer_->put_i64(entry_offset, record_value.key().as_integer());
  buffer_->put_i32(entry_offset + key_size, static_cast<std::int32_t>(offset));
  set_key_count(key_count_ + 1);

  if (use_indirect) {
    ChainedBuffer chained(checked_chained_length(logical_length),
                          manager_.buffer_manager());
    buffer_->put_i32(offset, chained.id());
    record_value.write(chained, 0);
  } else {
    record_value.write(*buffer_, offset);
  }
  set_indirect(index, use_indirect);
  return true;
}

std::shared_ptr<LongKeyNode>
VariableRecordNode::update_record(std::size_t index, Record &record_value) {
  if (index >= key_count_ || record_value.key().as_integer() != key_at(index) ||
      !record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("updated record key or schema differs");
  }

  auto offset = data_offset(index);
  const auto old_length = stored_length(index, offset);
  const auto logical_length = record_value.storage_length();
  const auto was_indirect = indirect(index);
  const auto use_indirect = logical_length > maximum_inline_record_length();
  auto physical_length = logical_length;

  if (use_indirect) {
    physical_length = 4;
    if (was_indirect) {
      ChainedBuffer chained(manager_.buffer_manager(),
                            buffer_->get_i32(offset));
      chained.set_size(checked_chained_length(logical_length), false);
      record_value.write(chained, 0);
    } else {
      if (offset + old_length < 4) {
        throw std::runtime_error("invalid inline record offset");
      }
      ChainedBuffer chained(checked_chained_length(logical_length),
                            manager_.buffer_manager());
      buffer_->put_i32(offset + old_length - 4, chained.id());
      set_indirect(index, true);
      record_value.write(chained, 0);
    }
  } else if (was_indirect) {
    remove_indirect(buffer_->get_i32(offset));
    set_indirect(index, false);
  }

  if (use_indirect || physical_length <= free_space() + old_length) {
    const auto shift = static_cast<std::ptrdiff_t>(old_length) -
                       static_cast<std::ptrdiff_t>(physical_length);
    if (shift != 0) {
      offset = move_records(index + 1, shift);
      put_data_offset(index, offset);
    }
    if (!use_indirect)
      record_value.write(*buffer_, offset);
    return root();
  }

  const auto key = record_value.key().as_integer();
  auto new_root = delete_record(key);
  if (!new_root) {
    auto leaf = manager_.create_variable_record_node();
    if (!leaf->insert_record(0, record_value)) {
      throw std::logic_error("empty variable leaf rejected updated record");
    }
    return leaf;
  }
  return new_root->leaf_for(key)->put_record(record_value);
}

void VariableRecordNode::remove_indirect(std::int32_t buffer_id) {
  ChainedBuffer chained(manager_.buffer_manager(), buffer_id);
  chained.remove();
}

void VariableRecordNode::remove_record(std::size_t index) {
  if (index >= key_count_)
    throw std::out_of_range("record removal index");
  if (indirect(index)) {
    remove_indirect(buffer_->get_i32(data_offset(index)));
    set_indirect(index, false);
  }
  const auto length = stored_length(index);
  (void)move_records(index + 1, static_cast<std::ptrdiff_t>(length));
  const auto following = entry_base_offset + (index + 1) * entry_size;
  buffer_->move(following, following - entry_size,
                (key_count_ - index - 1) * entry_size);
  set_key_count(key_count_ - 1);
}

std::size_t VariableRecordNode::split_index() const {
  if (key_count_ < 2)
    throw std::logic_error("cannot split one-record leaf");
  const auto halfway = (data_offset(key_count_ - 1) + buffer_->size()) / 2;
  std::size_t minimum = 1;
  std::size_t maximum = key_count_ - 1;
  while (minimum < maximum) {
    const auto index = (minimum + maximum) / 2;
    const auto offset = data_offset(index);
    if (offset == halfway)
      return index;
    if (offset < halfway)
      maximum = index - 1;
    else
      minimum = index + 1;
  }
  return minimum;
}

void VariableRecordNode::split_data(LongKeyRecordNode &right_leaf) {
  auto *right = dynamic_cast<VariableRecordNode *>(&right_leaf);
  if (!right)
    throw std::logic_error("variable leaf split type mismatch");
  const auto split = split_index();
  const auto count = key_count_ - split;
  const auto start = data_offset(key_count_ - 1);
  const auto end = data_offset(split - 1);
  if (start > end)
    throw std::runtime_error("invalid split record block");
  const auto length = end - start;
  const auto right_offset = buffer_->size() - length;
  right->buffer_->copy(right_offset, *buffer_, start, length);
  right->buffer_->copy(entry_base_offset, *buffer_,
                       entry_base_offset + split * entry_size,
                       count * entry_size);
  const auto correction = buffer_->size() - end;
  right->set_key_count(count);
  for (std::size_t index = 0; index < count; ++index) {
    right->put_data_offset(index, right->data_offset(index) + correction);
  }
  set_key_count(split);
}

std::shared_ptr<LongKeyRecordNode>
VariableRecordNode::create_leaf(std::int32_t previous_leaf_id,
                                std::int32_t next_leaf_id) {
  return manager_.create_variable_record_node(previous_leaf_id, next_leaf_id);
}

void VariableRecordNode::remove_all_indirect() {
  for (std::size_t index = 0; index < key_count_; ++index) {
    if (indirect(index)) {
      const auto offset = data_offset(index);
      remove_indirect(buffer_->get_i32(offset));
      buffer_->put_i32(offset, -1);
      set_indirect(index, false);
    }
  }
}

std::shared_ptr<LongKeyNode> VariableRecordNode::remove_leaf() {
  remove_all_indirect();
  return LongKeyRecordNode::remove_leaf();
}

void VariableRecordNode::delete_tree() {
  remove_all_indirect();
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t> VariableRecordNode::buffer_references() const {
  std::vector<std::int32_t> result;
  for (std::size_t index = 0; index < key_count_; ++index) {
    if (indirect(index))
      result.push_back(buffer_->get_i32(data_offset(index)));
  }
  return result;
}

bool VariableRecordNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  task.checkpoint();
  if (!leaf_links_and_keys_consistent(task))
    return false;
  const auto entries_end = entry_base_offset + key_count_ * entry_size;
  auto previous_offset = buffer_->size();
  for (std::size_t index = 0; index < key_count_; ++index) {
    task.checkpoint();
    const auto offset = data_offset(index);
    if (offset < entries_end || offset >= previous_offset)
      return false;
    const auto length = previous_offset - offset;
    if (indirect(index)) {
      if (length != 4 || buffer_->get_i32(offset) < 0)
        return false;
    }
    previous_offset = offset;
  }
  task.checkpoint();
  return true;
}

} // namespace llmghidra::db
