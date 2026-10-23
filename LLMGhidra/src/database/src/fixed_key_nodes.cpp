/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/fixed_key_nodes.hpp"

#include "llmghidra/db/chained_buffer.hpp"
#include "llmghidra/db/node_manager.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {
namespace {

std::int32_t checked_fixed_key_chained_length(std::size_t length) {
  if (length == 0 || length > static_cast<std::size_t>(
                                  std::numeric_limits<std::int32_t>::max())) {
    throw std::length_error(
        "record length cannot be represented by ChainedBuffer");
  }
  return static_cast<std::int32_t>(length);
}

} // namespace

FixedKeyNode::FixedKeyNode(NodeManager &manager,
                           std::shared_ptr<DataBuffer> buffer)
    : manager_(manager), buffer_(std::move(buffer)),
      key_size_(manager.schema().key_type().storage_length()) {
  if (!manager.schema().use_fixed_key_nodes() || key_size_ == 0) {
    throw std::invalid_argument("schema does not use fixed-key nodes");
  }
  const auto stored_count = buffer_->get_i32(key_count_offset);
  if (stored_count < 0)
    throw std::runtime_error("negative B-Tree key count");
  key_count_ = static_cast<std::size_t>(stored_count);
}

FixedKeyNode::FixedKeyNode(NodeManager &manager, std::uint8_t node_type)
    : manager_(manager), buffer_(manager.buffer_manager().create_buffer()),
      key_size_(manager.schema().key_type().storage_length()) {
  if (!manager.schema().use_fixed_key_nodes() || key_size_ == 0) {
    throw std::invalid_argument("schema does not use fixed-key nodes");
  }
  NodeManager::set_node_type(*buffer_,
                             static_cast<NodeManager::NodeType>(node_type));
  set_key_count(0);
}

InteriorNode *FixedKeyNode::parent() const noexcept { return parent_; }

void FixedKeyNode::set_key_count(std::size_t count) {
  if (!buffer_)
    throw std::logic_error("invalidated fixed-key B-Tree node");
  if (count >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::overflow_error("B-Tree key count exceeds int32");
  }
  buffer_->put_i32(key_count_offset, static_cast<std::int32_t>(count));
  key_count_ = count;
}

void FixedKeyNode::require_key_type(const Field &key) const {
  if (!key.same_type(manager_.schema().key_type()) || key.is_null() ||
      key.storage_length() != key_size_) {
    throw std::invalid_argument("fixed B-Tree key type or size differs");
  }
}

std::unique_ptr<Field> FixedKeyNode::key_field(std::size_t index) const {
  if (!buffer_)
    throw std::logic_error("invalidated fixed-key B-Tree node");
  if (index >= key_count_)
    throw std::out_of_range("fixed key index");
  auto result = manager_.schema().key_type().empty();
  result->read(*buffer_, key_offset(index));
  return result;
}

std::shared_ptr<FixedKeyNode> FixedKeyNode::root() {
  if (parent_)
    return parent_->root();
  return shared_from_this();
}

FixedKeyInteriorNode::FixedKeyInteriorNode(NodeManager &manager,
                                           std::shared_ptr<DataBuffer> existing)
    : FixedKeyNode(manager, std::move(existing)) {
  maximum_key_count_ = (buffer_->size() - entry_base_offset) / entry_size();
  if (key_count_ > maximum_key_count_) {
    throw std::runtime_error("fixed-key interior count exceeds capacity");
  }
}

FixedKeyInteriorNode::FixedKeyInteriorNode(NodeManager &manager,
                                           const Field &left_key,
                                           std::int32_t left_id,
                                           const Field &right_key,
                                           std::int32_t right_id)
    : FixedKeyNode(manager, static_cast<std::uint8_t>(
                                NodeManager::NodeType::fixed_key_interior)) {
  require_key_type(left_key);
  require_key_type(right_key);
  maximum_key_count_ = (buffer_->size() - entry_base_offset) / entry_size();
  if (maximum_key_count_ < 2 || left_key.compare(right_key) >= 0 ||
      left_id < 0 || right_id < 0) {
    throw std::invalid_argument("invalid initial fixed-key interior entries");
  }
  put_entry(0, left_key, left_id);
  put_entry(1, right_key, right_id);
  set_key_count(2);
}

FixedKeyInteriorNode::FixedKeyInteriorNode(NodeManager &manager)
    : FixedKeyNode(manager, static_cast<std::uint8_t>(
                                NodeManager::NodeType::fixed_key_interior)) {
  maximum_key_count_ = (buffer_->size() - entry_base_offset) / entry_size();
  if (maximum_key_count_ < 2) {
    throw std::runtime_error("buffer is too small for fixed-key interior");
  }
}

std::size_t FixedKeyInteriorNode::key_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("interior key index");
  return entry_base_offset + index * entry_size();
}

std::int32_t FixedKeyInteriorNode::child_id(std::size_t index) const {
  return buffer_->get_i32(key_offset(index) + key_size_);
}

std::ptrdiff_t FixedKeyInteriorNode::key_index(const Field &key) const {
  require_key_type(key);
  std::size_t minimum = 0;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    const auto comparison = key.compare_stored(*buffer_, key_offset(index));
    if (comparison == 0)
      return static_cast<std::ptrdiff_t>(index);
    if (comparison > 0)
      minimum = index + 1;
    else
      maximum = index;
  }
  return -static_cast<std::ptrdiff_t>(minimum) - 1;
}

std::size_t FixedKeyInteriorNode::child_index(const Field &key) const {
  require_key_type(key);
  if (key_count_ == 0)
    throw std::logic_error("empty fixed-key interior");
  std::size_t minimum = 1;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    if (key.compare_stored(*buffer_, key_offset(index)) >= 0) {
      minimum = index + 1;
    } else {
      maximum = index;
    }
  }
  return minimum - 1;
}

void FixedKeyInteriorNode::put_key(std::size_t index, const Field &key) {
  if (index >= key_count_)
    throw std::out_of_range("interior key index");
  require_key_type(key);
  key.write(*buffer_, key_offset(index));
}

void FixedKeyInteriorNode::put_entry(std::size_t index, const Field &key,
                                     std::int32_t id) {
  require_key_type(key);
  const auto offset = entry_base_offset + index * entry_size();
  key.write(*buffer_, offset);
  buffer_->put_i32(offset + key_size_, id);
}

void FixedKeyInteriorNode::insert_entry(std::size_t index, const Field &key,
                                        std::int32_t id) {
  if (index > key_count_ || key_count_ >= maximum_key_count_) {
    throw std::logic_error("invalid fixed-key interior insertion");
  }
  const auto offset = entry_base_offset + index * entry_size();
  buffer_->move(offset, offset + entry_size(),
                (key_count_ - index) * entry_size());
  put_entry(index, key, id);
  set_key_count(key_count_ + 1);
}

void FixedKeyInteriorNode::delete_entry(std::size_t index) {
  if (key_count_ < 3 || index >= key_count_) {
    throw std::logic_error("invalid fixed-key interior deletion");
  }
  if (index + 1 < key_count_) {
    const auto source = entry_base_offset + (index + 1) * entry_size();
    buffer_->move(source, source - entry_size(),
                  (key_count_ - index - 1) * entry_size());
  }
  set_key_count(key_count_ - 1);
}

void FixedKeyInteriorNode::child_key_changed(const Field &old_key,
                                             const Field &new_key) {
  const auto found = key_index(old_key);
  if (found < 0)
    throw std::logic_error("old fixed child key not found");
  const auto index = static_cast<std::size_t>(found);
  put_key(index, new_key);
  if (index == 0 && parent_)
    parent_->child_key_changed(old_key, new_key);
}

std::shared_ptr<FixedKeyRecordNode>
FixedKeyInteriorNode::leaf_for(const Field &key) {
  auto child = manager_.get_fixed_key_node(child_id(child_index(key)));
  child->parent_ = this;
  return child->leaf_for(key);
}

std::shared_ptr<FixedKeyNode>
FixedKeyInteriorNode::insert_child(std::int32_t id, const Field &key) {
  require_key_type(key);
  if (key_count_ == maximum_key_count_)
    return split_and_insert(key, id);
  const auto found = key_index(key);
  if (found >= 0 || id < 0) {
    throw std::logic_error("duplicate fixed key or invalid child id");
  }
  const auto index = static_cast<std::size_t>(-found - 1);
  insert_entry(index, key, id);
  if (index == 0 && parent_) {
    auto old_key = key_field(1);
    parent_->child_key_changed(*old_key, key);
  }
  return root();
}

void FixedKeyInteriorNode::move_keys_right(FixedKeyInteriorNode &left,
                                           FixedKeyInteriorNode &right,
                                           std::size_t count) {
  if (count == 0 || count > left.key_count_ ||
      left.entry_size() != right.entry_size()) {
    throw std::logic_error("invalid fixed-key rightward move");
  }
  const auto size = left.entry_size();
  const auto source = entry_base_offset + (left.key_count_ - count) * size;
  const auto length = count * size;
  right.buffer_->move(entry_base_offset, entry_base_offset + length,
                      right.key_count_ * size);
  right.buffer_->copy(entry_base_offset, *left.buffer_, source, length);
  left.set_key_count(left.key_count_ - count);
  right.set_key_count(right.key_count_ + count);
}

void FixedKeyInteriorNode::move_keys_left(FixedKeyInteriorNode &left,
                                          FixedKeyInteriorNode &right,
                                          std::size_t count) {
  if (count == 0 || count > right.key_count_ ||
      left.entry_size() != right.entry_size()) {
    throw std::logic_error("invalid fixed-key leftward move");
  }
  const auto size = left.entry_size();
  const auto destination = entry_base_offset + left.key_count_ * size;
  const auto length = count * size;
  left.buffer_->copy(destination, *right.buffer_, entry_base_offset, length);
  left.set_key_count(left.key_count_ + count);
  if (count < right.key_count_) {
    const auto remaining = right.key_count_ - count;
    right.buffer_->move(entry_base_offset + length, entry_base_offset,
                        remaining * size);
    right.set_key_count(remaining);
  }
}

std::shared_ptr<FixedKeyNode>
FixedKeyInteriorNode::split_and_insert(const Field &key, std::int32_t id) {
  auto right = manager_.create_empty_fixed_key_interior();
  move_keys_right(*this, *right, key_count_ / 2);
  auto right_key = right->key_field(0);
  if (key.compare(*right_key) < 0)
    (void)insert_child(id, key);
  else
    (void)right->insert_child(id, key);

  if (parent_)
    return parent_->insert_child(right->buffer_id(), *right_key);
  auto left_key = key_field(0);
  return manager_.create_fixed_key_interior(*left_key, buffer_id(), *right_key,
                                            right->buffer_id());
}

std::shared_ptr<FixedKeyNode>
FixedKeyInteriorNode::delete_child(const Field &key) {
  const auto found = key_index(key);
  if (found < 0)
    throw std::logic_error("fixed child key not found");
  const auto index = static_cast<std::size_t>(found);
  if (key_count_ == 2) {
    if (parent_)
      throw std::logic_error("non-root interior has two children");
    auto new_root = manager_.get_fixed_key_node(child_id(1 - index));
    new_root->parent_ = nullptr;
    manager_.delete_node(shared_from_this());
    return new_root;
  }
  delete_entry(index);
  if (index == 0 && parent_) {
    auto new_key = key_field(0);
    parent_->child_key_changed(key, *new_key);
  }
  return parent_ ? parent_->balance_child(*this) : shared_from_this();
}

std::shared_ptr<FixedKeyNode>
FixedKeyInteriorNode::balance_child(FixedKeyInteriorNode &node) {
  if (node.key_count_ > maximum_key_count_ / 2)
    return root();
  auto node_key = node.key_field(0);
  const auto index = child_index(*node_key);
  if (index == key_count_ - 1) {
    auto left = std::dynamic_pointer_cast<FixedKeyInteriorNode>(
        manager_.get_fixed_key_node(child_id(index - 1)));
    if (!left)
      throw std::logic_error("fixed interior sibling mismatch");
    return balance_pair(*left, node);
  }
  auto right = std::dynamic_pointer_cast<FixedKeyInteriorNode>(
      manager_.get_fixed_key_node(child_id(index + 1)));
  if (!right)
    throw std::logic_error("fixed interior sibling mismatch");
  return balance_pair(node, *right);
}

std::shared_ptr<FixedKeyNode>
FixedKeyInteriorNode::balance_pair(FixedKeyInteriorNode &left,
                                   FixedKeyInteriorNode &right) {
  auto right_key = right.key_field(0);
  const auto total = left.key_count_ + right.key_count_;
  if (total <= maximum_key_count_) {
    move_keys_left(left, right, right.key_count_);
    manager_.delete_node(right.shared_from_this());
    return delete_child(*right_key);
  }
  const auto new_left_count = total / 2;
  if (new_left_count < left.key_count_) {
    move_keys_right(left, right, left.key_count_ - new_left_count);
  } else if (new_left_count > left.key_count_) {
    move_keys_left(left, right, new_left_count - left.key_count_);
  }
  auto new_right_key = right.key_field(0);
  child_key_changed(*right_key, *new_right_key);
  return root();
}

void FixedKeyInteriorNode::delete_tree() {
  const auto ids = buffer_references();
  for (const auto id : ids)
    manager_.get_fixed_key_node(id)->delete_tree();
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t> FixedKeyInteriorNode::buffer_references() const {
  std::vector<std::int32_t> result;
  result.reserve(key_count_);
  for (std::size_t index = 0; index < key_count_; ++index) {
    result.push_back(child_id(index));
  }
  return result;
}

bool FixedKeyInteriorNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  task.checkpoint();
  if (key_count_ < 2 || key_count_ > maximum_key_count_)
    return false;
  std::unique_ptr<Field> previous_maximum;
  for (std::size_t index = 0; index < key_count_; ++index) {
    task.checkpoint();
    auto key = key_field(index);
    if (previous_maximum && key->compare(*previous_maximum) <= 0)
      return false;
    auto child = manager_.get_fixed_key_node(child_id(index));
    if (child->key_count() == 0)
      return false;
    auto child_minimum = child->key_field(0);
    if (!key->equals(*child_minimum))
      return false;
    child->parent_ = this;
    if (!child->consistent(task))
      return false;
    previous_maximum = child->key_field(child->key_count() - 1);
    task.checkpoint();
  }
  task.checkpoint();
  return true;
}

bool FixedKeyInteriorNode::is_leftmost_key(const Field &key) const {
  if (child_index(key) != 0)
    return false;
  return parent_ ? parent_->is_leftmost_key(key) : true;
}

bool FixedKeyInteriorNode::is_rightmost_key(const Field &key) const {
  if (child_index(key) != key_count_ - 1)
    return false;
  if (!parent_)
    return true;
  auto first = key_field(0);
  return parent_->is_rightmost_key(*first);
}

FixedKeyRecordNode::FixedKeyRecordNode(NodeManager &manager,
                                       std::shared_ptr<DataBuffer> existing)
    : FixedKeyNode(manager, std::move(existing)) {}

FixedKeyRecordNode::FixedKeyRecordNode(NodeManager &manager,
                                       std::uint8_t node_type,
                                       std::int32_t previous_leaf_id,
                                       std::int32_t next_leaf_id)
    : FixedKeyNode(manager, node_type) {
  buffer_->put_i32(previous_leaf_id_offset, previous_leaf_id);
  buffer_->put_i32(next_leaf_id_offset, next_leaf_id);
}

std::ptrdiff_t FixedKeyRecordNode::key_index(const Field &key) const {
  require_key_type(key);
  std::size_t minimum = 0;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    const auto comparison = key.compare_stored(*buffer_, key_offset(index));
    if (comparison == 0)
      return static_cast<std::ptrdiff_t>(index);
    if (comparison > 0)
      minimum = index + 1;
    else
      maximum = index;
  }
  return -static_cast<std::ptrdiff_t>(minimum) - 1;
}

std::shared_ptr<FixedKeyRecordNode>
FixedKeyRecordNode::leaf_for(const Field &key) {
  require_key_type(key);
  return std::static_pointer_cast<FixedKeyRecordNode>(shared_from_this());
}

std::unique_ptr<Record> FixedKeyRecordNode::record(const Field &key) const {
  const auto found = key_index(key);
  return found < 0 ? nullptr : record_at(static_cast<std::size_t>(found));
}

std::shared_ptr<FixedKeyRecordNode> FixedKeyRecordNode::next_leaf() const {
  const auto id = buffer_->get_i32(next_leaf_id_offset);
  if (id < 0)
    return nullptr;
  auto result = std::dynamic_pointer_cast<FixedKeyRecordNode>(
      manager_.get_fixed_key_node(id));
  if (!result)
    throw std::logic_error("next fixed-key leaf type mismatch");
  return result;
}

std::shared_ptr<FixedKeyRecordNode> FixedKeyRecordNode::previous_leaf() const {
  const auto id = buffer_->get_i32(previous_leaf_id_offset);
  if (id < 0)
    return nullptr;
  auto result = std::dynamic_pointer_cast<FixedKeyRecordNode>(
      manager_.get_fixed_key_node(id));
  if (!result)
    throw std::logic_error("previous fixed-key leaf type mismatch");
  return result;
}

std::unique_ptr<Record>
FixedKeyRecordNode::record_before(const Field &key) const {
  auto index = key_index(key);
  index = index < 0 ? -index - 2 : index - 1;
  if (index < 0) {
    auto leaf = previous_leaf();
    return leaf ? leaf->record_at(leaf->key_count_ - 1) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::unique_ptr<Record>
FixedKeyRecordNode::record_after(const Field &key) const {
  auto index = key_index(key);
  index = index < 0 ? -index - 1 : index + 1;
  if (static_cast<std::size_t>(index) == key_count_) {
    auto leaf = next_leaf();
    return leaf ? leaf->record_at(0) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::unique_ptr<Record>
FixedKeyRecordNode::record_at_or_before(const Field &key) const {
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
FixedKeyRecordNode::record_at_or_after(const Field &key) const {
  auto index = key_index(key);
  if (index < 0)
    index = -index - 1;
  if (static_cast<std::size_t>(index) == key_count_) {
    auto leaf = next_leaf();
    return leaf ? leaf->record_at(0) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::shared_ptr<FixedKeyNode> FixedKeyRecordNode::split_leaf() {
  const auto old_next = buffer_->get_i32(next_leaf_id_offset);
  auto right = create_leaf(buffer_id(), old_next);
  buffer_->put_i32(next_leaf_id_offset, right->buffer_id());
  if (old_next >= 0) {
    auto old_sibling = std::dynamic_pointer_cast<FixedKeyRecordNode>(
        manager_.get_fixed_key_node(old_next));
    if (!old_sibling)
      throw std::logic_error("fixed leaf sibling mismatch");
    old_sibling->buffer_->put_i32(previous_leaf_id_offset, right->buffer_id());
  }
  split_data(*right);
  auto right_key = right->key_field(0);
  if (parent_)
    return parent_->insert_child(right->buffer_id(), *right_key);
  auto left_key = key_field(0);
  return manager_.create_fixed_key_interior(*left_key, buffer_id(), *right_key,
                                            right->buffer_id());
}

std::shared_ptr<FixedKeyNode> FixedKeyRecordNode::append_leaf(
    const std::shared_ptr<FixedKeyRecordNode> &leaf) {
  if (!leaf || leaf.get() == this || leaf->key_count_ == 0) {
    throw std::invalid_argument("invalid appended fixed-key leaf");
  }
  leaf->buffer_->put_i32(previous_leaf_id_offset, buffer_id());
  const auto old_next = buffer_->get_i32(next_leaf_id_offset);
  leaf->buffer_->put_i32(next_leaf_id_offset, old_next);
  buffer_->put_i32(next_leaf_id_offset, leaf->buffer_id());
  if (old_next >= 0) {
    auto right = std::dynamic_pointer_cast<FixedKeyRecordNode>(
        manager_.get_fixed_key_node(old_next));
    if (!right)
      throw std::logic_error("fixed leaf sibling mismatch");
    right->buffer_->put_i32(previous_leaf_id_offset, leaf->buffer_id());
  }
  auto leaf_key = leaf->key_field(0);
  if (parent_)
    return parent_->insert_child(leaf->buffer_id(), *leaf_key);
  auto this_key = key_field(0);
  return manager_.create_fixed_key_interior(*this_key, buffer_id(), *leaf_key,
                                            leaf->buffer_id());
}

std::shared_ptr<FixedKeyNode> FixedKeyRecordNode::remove_leaf() {
  if (key_count_ == 0)
    throw std::logic_error("cannot remove empty fixed leaf");
  auto key = key_field(0);
  const auto previous_id = buffer_->get_i32(previous_leaf_id_offset);
  const auto next_id = buffer_->get_i32(next_leaf_id_offset);
  if (previous_id >= 0) {
    auto previous = std::dynamic_pointer_cast<FixedKeyRecordNode>(
        manager_.get_fixed_key_node(previous_id));
    if (!previous)
      throw std::logic_error("fixed leaf sibling mismatch");
    previous->buffer_->put_i32(next_leaf_id_offset, next_id);
  }
  if (next_id >= 0) {
    auto next = std::dynamic_pointer_cast<FixedKeyRecordNode>(
        manager_.get_fixed_key_node(next_id));
    if (!next)
      throw std::logic_error("fixed leaf sibling mismatch");
    next->buffer_->put_i32(previous_leaf_id_offset, previous_id);
  }
  auto old_parent = parent_;
  manager_.delete_node(shared_from_this());
  return old_parent ? old_parent->delete_child(*key) : nullptr;
}

std::shared_ptr<FixedKeyNode>
FixedKeyRecordNode::put_record(Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("record schema differs from fixed-key leaf");
  }
  const auto &key = record_value.key();
  require_key_type(key);
  auto index = key_index(key);
  if (index >= 0) {
    return update_record(static_cast<std::size_t>(index), record_value);
  }
  const auto insertion = static_cast<std::size_t>(-index - 1);
  if (insert_record(insertion, record_value)) {
    if (insertion == 0 && parent_) {
      auto old_key = key_field(1);
      parent_->child_key_changed(*old_key, key);
    }
    return root();
  }
  if (insertion == key_count_) {
    auto leaf = create_leaf(-1, -1);
    if (!leaf->insert_record(0, record_value)) {
      throw std::logic_error("empty fixed-key leaf rejected record");
    }
    return append_leaf(leaf);
  }
  auto new_root = split_leaf();
  return new_root->leaf_for(key)->put_record(record_value);
}

std::shared_ptr<FixedKeyNode>
FixedKeyRecordNode::delete_record(const Field &key) {
  const auto found = key_index(key);
  if (found < 0)
    return root();
  const auto index = static_cast<std::size_t>(found);
  if (key_count_ == 1)
    return remove_leaf();
  remove_record(index);
  if (index == 0 && parent_) {
    auto new_key = key_field(0);
    parent_->child_key_changed(key, *new_key);
  }
  return root();
}

bool FixedKeyRecordNode::leaf_links_and_keys_consistent(
    const TaskContext &task) {
  task.checkpoint();
  if (key_count_ == 0)
    return false;
  auto previous_key = key_field(0);
  for (std::size_t index = 1; index < key_count_; ++index) {
    task.checkpoint();
    auto key = key_field(index);
    if (key->compare(*previous_key) <= 0)
      return false;
    previous_key = std::move(key);
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
    auto first = key_field(0);
    if (parent_->is_leftmost_key(*first) != (previous == nullptr))
      return false;
    if (parent_->is_rightmost_key(*first) != (next == nullptr))
      return false;
  }
  task.checkpoint();
  return true;
}

FixedKeyFixedRecordNode::FixedKeyFixedRecordNode(
    NodeManager &manager, std::shared_ptr<DataBuffer> existing,
    std::size_t record_length)
    : FixedKeyRecordNode(manager, std::move(existing)),
      record_length_(record_length) {
  const auto capacity = (buffer_->size() - entry_base_offset) / entry_size();
  if (key_count_ > capacity) {
    throw std::runtime_error("fixed-key record count exceeds capacity");
  }
}

FixedKeyFixedRecordNode::FixedKeyFixedRecordNode(NodeManager &manager,
                                                 std::size_t record_length,
                                                 std::int32_t previous_leaf_id,
                                                 std::int32_t next_leaf_id)
    : FixedKeyRecordNode(manager,
                         static_cast<std::uint8_t>(
                             NodeManager::NodeType::fixed_key_fixed_record),
                         previous_leaf_id, next_leaf_id),
      record_length_(record_length) {
  if ((buffer_->size() - entry_base_offset) / entry_size() == 0) {
    throw std::runtime_error("record is too large for fixed-key leaf");
  }
}

std::size_t FixedKeyFixedRecordNode::key_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("fixed record key index");
  return entry_base_offset + index * entry_size();
}

std::ptrdiff_t FixedKeyFixedRecordNode::record_offset(std::size_t index) const {
  return static_cast<std::ptrdiff_t>(key_offset(index));
}

std::unique_ptr<Record>
FixedKeyFixedRecordNode::record_at(std::size_t index) const {
  auto key = key_field(index);
  auto result = manager_.schema().create_record(std::move(key));
  result->read(*buffer_, key_offset(index) + key_size_);
  return result;
}

void FixedKeyFixedRecordNode::shift_records(std::size_t index, bool right) {
  if (index == key_count_)
    return;
  const auto start = entry_base_offset + index * entry_size();
  buffer_->move(start, right ? start + entry_size() : start - entry_size(),
                (key_count_ - index) * entry_size());
}

bool FixedKeyFixedRecordNode::insert_record(std::size_t index,
                                            Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema()) ||
      record_value.storage_length() != record_length_) {
    throw std::invalid_argument("record schema differs from fixed-key leaf");
  }
  require_key_type(record_value.key());
  const auto capacity = (buffer_->size() - entry_base_offset) / entry_size();
  if (key_count_ == capacity)
    return false;
  if (index > key_count_)
    throw std::out_of_range("record insertion index");
  shift_records(index, true);
  const auto offset = entry_base_offset + index * entry_size();
  record_value.key().write(*buffer_, offset);
  record_value.write(*buffer_, offset + key_size_);
  set_key_count(key_count_ + 1);
  return true;
}

void FixedKeyFixedRecordNode::remove_record(std::size_t index) {
  if (index >= key_count_)
    throw std::out_of_range("record removal index");
  shift_records(index + 1, false);
  set_key_count(key_count_ - 1);
}

std::shared_ptr<FixedKeyNode>
FixedKeyFixedRecordNode::update_record(std::size_t index,
                                       Record &record_value) {
  auto old_key = key_field(index);
  if (!record_value.key().equals(*old_key) ||
      !record_value.has_same_schema(manager_.schema()) ||
      record_value.storage_length() != record_length_) {
    throw std::invalid_argument("updated fixed-key record differs");
  }
  record_value.write(*buffer_, key_offset(index) + key_size_);
  return root();
}

void FixedKeyFixedRecordNode::split_data(FixedKeyRecordNode &right_leaf) {
  auto *right = dynamic_cast<FixedKeyFixedRecordNode *>(&right_leaf);
  if (!right)
    throw std::logic_error("fixed-key leaf split type mismatch");
  const auto split = key_count_ / 2;
  const auto count = key_count_ - split;
  const auto source = entry_base_offset + split * entry_size();
  right->buffer_->copy(entry_base_offset, *buffer_, source,
                       count * entry_size());
  set_key_count(split);
  right->set_key_count(count);
}

std::shared_ptr<FixedKeyRecordNode>
FixedKeyFixedRecordNode::create_leaf(std::int32_t previous_leaf_id,
                                     std::int32_t next_leaf_id) {
  return manager_.create_fixed_key_fixed_record_node(previous_leaf_id,
                                                     next_leaf_id);
}

void FixedKeyFixedRecordNode::delete_tree() {
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t> FixedKeyFixedRecordNode::buffer_references() const {
  return {};
}

bool FixedKeyFixedRecordNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  task.checkpoint();
  const auto capacity = (buffer_->size() - entry_base_offset) / entry_size();
  return key_count_ <= capacity && leaf_links_and_keys_consistent(task);
}

FixedKeyVariableRecordNode::FixedKeyVariableRecordNode(
    NodeManager &manager, std::shared_ptr<DataBuffer> existing)
    : FixedKeyRecordNode(manager, std::move(existing)) {
  if (key_count_ > (buffer_->size() - entry_base_offset) / entry_size()) {
    throw std::runtime_error(
        "fixed-key variable record count exceeds capacity");
  }
}

FixedKeyVariableRecordNode::FixedKeyVariableRecordNode(
    NodeManager &manager, std::int32_t previous_leaf_id,
    std::int32_t next_leaf_id)
    : FixedKeyRecordNode(manager,
                         static_cast<std::uint8_t>(
                             NodeManager::NodeType::fixed_key_variable_record),
                         previous_leaf_id, next_leaf_id) {
  if (buffer_->size() < entry_base_offset + entry_size() + 1) {
    throw std::runtime_error("buffer is too small for fixed-key variable leaf");
  }
}

std::size_t FixedKeyVariableRecordNode::key_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("fixed variable key index");
  return entry_base_offset + index * entry_size();
}

std::size_t FixedKeyVariableRecordNode::data_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("fixed variable data index");
  const auto value =
      buffer_->get_i32(record_offset_base() + index * entry_size());
  if (value < 0)
    throw std::runtime_error("negative fixed variable offset");
  return static_cast<std::size_t>(value);
}

void FixedKeyVariableRecordNode::put_data_offset(std::size_t index,
                                                 std::size_t offset) {
  if (index > key_count_ ||
      offset >
          static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::out_of_range("fixed variable record offset");
  }
  buffer_->put_i32(record_offset_base() + index * entry_size(),
                   static_cast<std::int32_t>(offset));
}

bool FixedKeyVariableRecordNode::indirect(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("fixed indirect index");
  return buffer_->get_u8(indirect_flag_base() + index * entry_size()) != 0;
}

void FixedKeyVariableRecordNode::set_indirect(std::size_t index, bool state) {
  if (index >= key_count_)
    throw std::out_of_range("fixed indirect index");
  buffer_->put_u8(indirect_flag_base() + index * entry_size(),
                  state ? std::uint8_t{1} : std::uint8_t{0});
}

std::size_t FixedKeyVariableRecordNode::free_space() const {
  const auto data_begin =
      key_count_ == 0 ? buffer_->size() : data_offset(key_count_ - 1);
  const auto entries_end = entry_base_offset + key_count_ * entry_size();
  if (data_begin < entries_end) {
    throw std::runtime_error("fixed variable entries overlap data");
  }
  return data_begin - entries_end;
}

std::size_t FixedKeyVariableRecordNode::stored_length(std::size_t index) const {
  return stored_length(index, data_offset(index));
}

std::size_t
FixedKeyVariableRecordNode::stored_length(std::size_t index,
                                          std::size_t offset) const {
  if (index >= key_count_)
    throw std::out_of_range("fixed record length index");
  const auto end = index == 0 ? buffer_->size() : data_offset(index - 1);
  if (offset > end)
    throw std::runtime_error("invalid fixed variable offsets");
  return end - offset;
}

std::size_t FixedKeyVariableRecordNode::move_records(std::size_t index,
                                                     std::ptrdiff_t shift) {
  if (index > key_count_)
    throw std::out_of_range("fixed record movement index");
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
    throw std::runtime_error("invalid fixed variable block");
  buffer_->move(start, shifted(start), end - start);
  for (auto current = index; current < key_count_; ++current) {
    put_data_offset(current, shifted(data_offset(current)));
  }
  return shifted(end);
}

std::ptrdiff_t
FixedKeyVariableRecordNode::record_offset(std::size_t index) const {
  const auto offset = data_offset(index);
  if (!indirect(index))
    return static_cast<std::ptrdiff_t>(offset);
  return -static_cast<std::ptrdiff_t>(buffer_->get_i32(offset));
}

std::unique_ptr<Record>
FixedKeyVariableRecordNode::record_at(std::size_t index) const {
  auto key = key_field(index);
  auto result = manager_.schema().create_record(std::move(key));
  const auto offset = data_offset(index);
  if (indirect(index)) {
    ChainedBuffer chained(manager_.buffer_manager(), buffer_->get_i32(offset));
    result->read(chained, 0);
  } else {
    result->read(*buffer_, offset);
  }
  return result;
}

std::size_t FixedKeyVariableRecordNode::maximum_inline_record_length() const {
  const auto quarter = (buffer_->size() - entry_base_offset) >> 2;
  return quarter > entry_size() ? quarter - entry_size() : 0;
}

bool FixedKeyVariableRecordNode::insert_record(std::size_t index,
                                               Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument(
        "record schema differs from fixed variable leaf");
  }
  require_key_type(record_value.key());
  if (index > key_count_)
    throw std::out_of_range("record insertion index");
  const auto logical_length = record_value.storage_length();
  const auto use_indirect = logical_length > maximum_inline_record_length();
  const auto physical_length = use_indirect ? std::size_t{4} : logical_length;
  if (physical_length + entry_size() > free_space())
    return false;

  const auto offset =
      move_records(index, -static_cast<std::ptrdiff_t>(physical_length));
  const auto entry_offset = entry_base_offset + index * entry_size();
  buffer_->move(entry_offset, entry_offset + entry_size(),
                (key_count_ - index) * entry_size());
  record_value.key().write(*buffer_, entry_offset);
  buffer_->put_i32(entry_offset + key_size_, static_cast<std::int32_t>(offset));
  set_key_count(key_count_ + 1);
  if (use_indirect) {
    ChainedBuffer chained(checked_fixed_key_chained_length(logical_length),
                          manager_.buffer_manager());
    buffer_->put_i32(offset, chained.id());
    record_value.write(chained, 0);
  } else {
    record_value.write(*buffer_, offset);
  }
  set_indirect(index, use_indirect);
  return true;
}

std::shared_ptr<FixedKeyNode>
FixedKeyVariableRecordNode::update_record(std::size_t index,
                                          Record &record_value) {
  auto old_key = key_field(index);
  if (!record_value.key().equals(*old_key) ||
      !record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("updated fixed variable record differs");
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
      chained.set_size(checked_fixed_key_chained_length(logical_length), false);
      record_value.write(chained, 0);
    } else {
      if (offset + old_length < 4) {
        throw std::runtime_error("invalid fixed inline record offset");
      }
      ChainedBuffer chained(checked_fixed_key_chained_length(logical_length),
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

  auto key = record_value.key().clone();
  auto new_root = delete_record(*key);
  if (!new_root) {
    auto leaf = manager_.create_fixed_key_variable_record_node();
    if (!leaf->insert_record(0, record_value)) {
      throw std::logic_error("empty fixed variable leaf rejected record");
    }
    return leaf;
  }
  return new_root->leaf_for(*key)->put_record(record_value);
}

void FixedKeyVariableRecordNode::remove_indirect(std::int32_t buffer_id) {
  ChainedBuffer chained(manager_.buffer_manager(), buffer_id);
  chained.remove();
}

void FixedKeyVariableRecordNode::remove_record(std::size_t index) {
  if (index >= key_count_)
    throw std::out_of_range("record removal index");
  if (indirect(index)) {
    remove_indirect(buffer_->get_i32(data_offset(index)));
    set_indirect(index, false);
  }
  const auto length = stored_length(index);
  (void)move_records(index + 1, static_cast<std::ptrdiff_t>(length));
  const auto following = entry_base_offset + (index + 1) * entry_size();
  buffer_->move(following, following - entry_size(),
                (key_count_ - index - 1) * entry_size());
  set_key_count(key_count_ - 1);
}

std::size_t FixedKeyVariableRecordNode::split_index() const {
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

void FixedKeyVariableRecordNode::split_data(FixedKeyRecordNode &right_leaf) {
  auto *right = dynamic_cast<FixedKeyVariableRecordNode *>(&right_leaf);
  if (!right)
    throw std::logic_error("fixed variable split type mismatch");
  const auto split = split_index();
  const auto count = key_count_ - split;
  const auto start = data_offset(key_count_ - 1);
  const auto end = data_offset(split - 1);
  if (start > end)
    throw std::runtime_error("invalid fixed variable split");
  const auto length = end - start;
  const auto right_offset = buffer_->size() - length;
  right->buffer_->copy(right_offset, *buffer_, start, length);
  right->buffer_->copy(entry_base_offset, *buffer_,
                       entry_base_offset + split * entry_size(),
                       count * entry_size());
  const auto correction = buffer_->size() - end;
  right->set_key_count(count);
  for (std::size_t index = 0; index < count; ++index) {
    right->put_data_offset(index, right->data_offset(index) + correction);
  }
  set_key_count(split);
}

std::shared_ptr<FixedKeyRecordNode>
FixedKeyVariableRecordNode::create_leaf(std::int32_t previous_leaf_id,
                                        std::int32_t next_leaf_id) {
  return manager_.create_fixed_key_variable_record_node(previous_leaf_id,
                                                        next_leaf_id);
}

void FixedKeyVariableRecordNode::remove_all_indirect() {
  for (std::size_t index = 0; index < key_count_; ++index) {
    if (indirect(index)) {
      const auto offset = data_offset(index);
      remove_indirect(buffer_->get_i32(offset));
      buffer_->put_i32(offset, -1);
      set_indirect(index, false);
    }
  }
}

std::shared_ptr<FixedKeyNode> FixedKeyVariableRecordNode::remove_leaf() {
  remove_all_indirect();
  return FixedKeyRecordNode::remove_leaf();
}

void FixedKeyVariableRecordNode::delete_tree() {
  remove_all_indirect();
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t>
FixedKeyVariableRecordNode::buffer_references() const {
  std::vector<std::int32_t> result;
  for (std::size_t index = 0; index < key_count_; ++index) {
    if (indirect(index))
      result.push_back(buffer_->get_i32(data_offset(index)));
  }
  return result;
}

bool FixedKeyVariableRecordNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  task.checkpoint();
  if (!leaf_links_and_keys_consistent(task))
    return false;
  const auto entries_end = entry_base_offset + key_count_ * entry_size();
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
