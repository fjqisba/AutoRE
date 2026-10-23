/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/variable_key_nodes.hpp"

#include "llmghidra/db/chained_buffer.hpp"
#include "llmghidra/db/node_manager.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {

class VariableKeyBufferLease final {
public:
  explicit VariableKeyBufferLease(BufferManager &manager)
      : manager_(manager), buffer_(manager.create_buffer()) {}

  ~VariableKeyBufferLease() {
    if (!buffer_)
      return;
    try {
      buffer_->set_empty(true);
      buffer_->set_dirty(true);
      manager_.release_buffer(buffer_);
    } catch (...) {
    }
  }

  [[nodiscard]] const std::shared_ptr<DataBuffer> &buffer() const noexcept {
    return buffer_;
  }

  void commit() noexcept { buffer_.reset(); }

private:
  BufferManager &manager_;
  std::shared_ptr<DataBuffer> buffer_;
};

namespace {

std::int32_t checked_variable_key_chained_length(std::size_t length) {
  if (length == 0 || length > static_cast<std::size_t>(
                                  std::numeric_limits<std::int32_t>::max())) {
    throw std::length_error(
        "record length cannot be represented by ChainedBuffer");
  }
  return static_cast<std::int32_t>(length);
}

std::size_t shifted_offset(std::size_t value, std::ptrdiff_t shift) {
  if (shift < 0) {
    const auto magnitude = static_cast<std::size_t>(-shift);
    if (magnitude > value)
      throw std::out_of_range("negative packed-data movement");
    return value - magnitude;
  }
  const auto magnitude = static_cast<std::size_t>(shift);
  if (magnitude > std::numeric_limits<std::size_t>::max() - value) {
    throw std::overflow_error("packed-data movement overflow");
  }
  return value + magnitude;
}

std::vector<std::uint8_t> serialize_record(Record &record) {
  const auto length = record.storage_length();
  DataBuffer serialized(length);
  const auto end = record.write(serialized, 0);
  if (end != length) {
    throw std::logic_error(
        "record serialized length differs from storage length");
  }
  return serialized.bytes();
}

class PendingChainedBuffer final {
public:
  PendingChainedBuffer(BufferManager &manager,
                       std::span<const std::uint8_t> bytes)
      : chained_(std::make_unique<ChainedBuffer>(
            checked_variable_key_chained_length(bytes.size()), manager)) {
    try {
      chained_->put(0, bytes);
    } catch (...) {
      try {
        chained_->remove();
      } catch (...) {
      }
      throw;
    }
  }

  ~PendingChainedBuffer() {
    if (!chained_)
      return;
    try {
      chained_->remove();
    } catch (...) {
    }
  }

  [[nodiscard]] std::int32_t id() const noexcept { return chained_->id(); }
  void commit() noexcept { chained_.reset(); }

private:
  std::unique_ptr<ChainedBuffer> chained_;
};

} // namespace

VariableKeyNode::VariableKeyNode(NodeManager &manager,
                                 std::shared_ptr<DataBuffer> buffer)
    : manager_(manager), buffer_(std::move(buffer)) {
  if (!manager.schema().use_variable_key_nodes()) {
    throw std::invalid_argument("schema does not use variable-key nodes");
  }
  key_type_ = make_field(buffer_->get_u8(key_type_offset));
  if (!key_type_->same_type(manager.schema().key_type())) {
    throw std::runtime_error("stored variable-key type differs from schema");
  }
  const auto stored_count = buffer_->get_i32(key_count_offset);
  if (stored_count < 0)
    throw std::runtime_error("negative B-Tree key count");
  key_count_ = static_cast<std::size_t>(stored_count);
  maximum_key_length_ = calculate_maximum_key_length(buffer_->size());
  if (maximum_key_length_ == 0) {
    throw std::runtime_error("buffer is too small for variable-key nodes");
  }
}

VariableKeyNode::VariableKeyNode(NodeManager &manager, std::uint8_t node_type)
    : manager_(manager),
      new_buffer_lease_(
          std::make_unique<VariableKeyBufferLease>(manager.buffer_manager())),
      buffer_(new_buffer_lease_->buffer()),
      key_type_(manager.schema().key_type().empty()) {
  if (!manager.schema().use_variable_key_nodes()) {
    throw std::invalid_argument("schema does not use variable-key nodes");
  }
  NodeManager::set_node_type(*buffer_,
                             static_cast<NodeManager::NodeType>(node_type));
  buffer_->put_u8(key_type_offset, manager.schema().encoded_key_type());
  set_key_count(0);
  maximum_key_length_ = calculate_maximum_key_length(buffer_->size());
  if (maximum_key_length_ == 0) {
    throw std::runtime_error("buffer is too small for variable-key nodes");
  }
}

VariableKeyNode::~VariableKeyNode() = default;

void VariableKeyNode::commit_new_buffer() noexcept {
  if (!new_buffer_lease_)
    return;
  new_buffer_lease_->commit();
  new_buffer_lease_.reset();
}

InteriorNode *VariableKeyNode::parent() const noexcept { return parent_; }

void VariableKeyNode::set_key_count(std::size_t count) {
  if (!buffer_)
    throw std::logic_error("invalidated variable-key B-Tree node");
  if (count >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::overflow_error("B-Tree key count exceeds int32");
  }
  buffer_->put_i32(key_count_offset, static_cast<std::int32_t>(count));
  key_count_ = count;
}

void VariableKeyNode::require_key_type(const Field &key) const {
  if (!key.same_type(*key_type_) || key.is_null()) {
    throw std::invalid_argument("variable B-Tree key type differs or is null");
  }
  if (key.storage_length() > maximum_key_length_) {
    throw std::length_error(
        "variable B-Tree key exceeds maximum stored length");
  }
}

std::unique_ptr<Field> VariableKeyNode::key_field(std::size_t index) const {
  if (!buffer_) {
    throw std::logic_error("invalidated variable-key B-Tree node");
  }
  if (index >= key_count_)
    throw std::out_of_range("variable key index");
  auto result = key_type_->empty();
  result->read(*buffer_, key_offset(index));
  return result;
}

std::ptrdiff_t VariableKeyNode::key_index(const Field &key) const {
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

std::shared_ptr<VariableKeyNode> VariableKeyNode::root() {
  if (parent_)
    return parent_->root();
  return shared_from_this();
}

std::size_t VariableKeyNode::calculate_maximum_key_length(
    std::size_t buffer_size) noexcept {
  if (buffer_size <= header_size)
    return 0;
  const auto per_key = (buffer_size - header_size) /
                       VariableKeyInteriorNode::minimum_key_capacity;
  if (per_key <= VariableKeyInteriorNode::entry_size)
    return 0;
  return per_key - VariableKeyInteriorNode::entry_size;
}

VariableKeyInteriorNode::VariableKeyInteriorNode(
    NodeManager &manager, std::shared_ptr<DataBuffer> existing)
    : VariableKeyNode(manager, std::move(existing)) {
  if (entry_base_offset + key_count_ * entry_size > buffer_->size()) {
    throw std::runtime_error(
        "variable-key interior entry table exceeds buffer");
  }
  for (std::size_t index = 0; index < key_count_; ++index) {
    const auto offset = key_offset(index);
    if (offset < entry_base_offset + key_count_ * entry_size ||
        offset >= buffer_->size() || child_id(index) < 0) {
      throw std::runtime_error("invalid variable-key interior entry");
    }
  }
}

VariableKeyInteriorNode::VariableKeyInteriorNode(NodeManager &manager,
                                                 const Field &left_key,
                                                 std::int32_t left_id,
                                                 const Field &right_key,
                                                 std::int32_t right_id)
    : VariableKeyNode(manager,
                      static_cast<std::uint8_t>(
                          NodeManager::NodeType::variable_key_interior)) {
  require_key_type(left_key);
  require_key_type(right_key);
  if (left_id < 0 || right_id < 0 || left_key.compare(right_key) >= 0) {
    throw std::invalid_argument(
        "invalid initial variable-key interior entries");
  }
  std::vector<Entry> initial;
  initial.push_back(Entry{left_key.clone(), left_id});
  initial.push_back(Entry{right_key.clone(), right_id});
  rebuild(initial);
}

VariableKeyInteriorNode::VariableKeyInteriorNode(NodeManager &manager)
    : VariableKeyNode(manager,
                      static_cast<std::uint8_t>(
                          NodeManager::NodeType::variable_key_interior)) {}

std::size_t VariableKeyInteriorNode::key_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("interior key index");
  const auto value = buffer_->get_i32(entry_base_offset + index * entry_size);
  if (value < 0)
    throw std::runtime_error("negative variable-key offset");
  return static_cast<std::size_t>(value);
}

std::size_t VariableKeyInteriorNode::child_index(const Field &key) const {
  require_key_type(key);
  if (key_count_ == 0)
    throw std::logic_error("empty variable-key interior");
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

std::int32_t VariableKeyInteriorNode::child_id(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("interior child index");
  return buffer_->get_i32(entry_base_offset + index * entry_size +
                          key_offset_size);
}

std::shared_ptr<VariableKeyRecordNode>
VariableKeyInteriorNode::leaf_for(const Field &key) {
  auto child = manager_.get_variable_key_node(child_id(child_index(key)));
  child->parent_ = this;
  return child->leaf_for(key);
}

std::size_t VariableKeyInteriorNode::free_space() const {
  const auto data_begin =
      key_count_ == 0 ? buffer_->size() : key_offset(key_count_ - 1);
  const auto entries_end = entry_base_offset + key_count_ * entry_size;
  if (data_begin < entries_end) {
    throw std::runtime_error("variable-key interior entries overlap keys");
  }
  return data_begin - entries_end;
}

std::size_t VariableKeyInteriorNode::key_length(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("interior key length index");
  return key_type_->read_length(*buffer_, key_offset(index));
}

void VariableKeyInteriorNode::put_key_offset(std::size_t index,
                                             std::size_t offset) {
  if (entry_base_offset + index * entry_size + key_offset_size >
          buffer_->size() ||
      offset >
          static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::out_of_range("variable interior key offset");
  }
  buffer_->put_i32(entry_base_offset + index * entry_size,
                   static_cast<std::int32_t>(offset));
}

std::size_t VariableKeyInteriorNode::move_keys(std::size_t index,
                                               std::ptrdiff_t shift) {
  if (index > key_count_)
    throw std::out_of_range("key movement index");
  if (index == key_count_) {
    const auto end = index == 0 ? buffer_->size() : key_offset(key_count_ - 1);
    return shifted_offset(end, shift);
  }
  const auto start = key_offset(key_count_ - 1);
  const auto end = index == 0 ? buffer_->size() : key_offset(index - 1);
  if (start > end)
    throw std::runtime_error("invalid variable-key block");
  buffer_->move(start, shifted_offset(start, shift), end - start);
  for (auto current = index; current < key_count_; ++current) {
    put_key_offset(current, shifted_offset(key_offset(current), shift));
  }
  return shifted_offset(end, shift);
}

void VariableKeyInteriorNode::insert_entry(std::size_t index, const Field &key,
                                           std::int32_t id) {
  require_key_type(key);
  if (index > key_count_ || id < 0 ||
      key.storage_length() + entry_size > free_space()) {
    throw std::logic_error("invalid variable-key interior insertion");
  }
  const auto offset =
      move_keys(index, -static_cast<std::ptrdiff_t>(key.storage_length()));
  const auto entry_offset = entry_base_offset + index * entry_size;
  buffer_->move(entry_offset, entry_offset + entry_size,
                (key_count_ - index) * entry_size);
  buffer_->put_i32(entry_offset, static_cast<std::int32_t>(offset));
  buffer_->put_i32(entry_offset + key_offset_size, id);
  key.write(*buffer_, offset);
  set_key_count(key_count_ + 1);
}

void VariableKeyInteriorNode::update_key(std::size_t index, const Field &key) {
  require_key_type(key);
  if (index >= key_count_)
    throw std::out_of_range("interior update index");
  const auto old_length = key_length(index);
  const auto new_length = key.storage_length();
  if (new_length > old_length + free_space()) {
    throw std::length_error("updated variable interior key does not fit");
  }
  const auto offset =
      move_keys(index + 1, static_cast<std::ptrdiff_t>(old_length) -
                               static_cast<std::ptrdiff_t>(new_length));
  key.write(*buffer_, offset);
  put_key_offset(index, offset);
}

void VariableKeyInteriorNode::delete_entry(std::size_t index) {
  if (key_count_ < 3 || index >= key_count_) {
    throw std::logic_error("invalid variable-key interior deletion");
  }
  const auto movement = index + 1;
  if (movement < key_count_) {
    (void)move_keys(movement, static_cast<std::ptrdiff_t>(key_length(index)));
    const auto source = entry_base_offset + movement * entry_size;
    buffer_->move(source, source - entry_size,
                  (key_count_ - movement) * entry_size);
  }
  set_key_count(key_count_ - 1);
}

std::vector<VariableKeyInteriorNode::Entry>
VariableKeyInteriorNode::entries() const {
  std::vector<Entry> result;
  result.reserve(key_count_);
  for (std::size_t index = 0; index < key_count_; ++index) {
    result.push_back(Entry{key_field(index), child_id(index)});
  }
  return result;
}

std::size_t
VariableKeyInteriorNode::storage_size(const std::vector<Entry> &values) {
  std::size_t result = header_size + values.size() * entry_size;
  for (const auto &entry : values) {
    if (!entry.key)
      throw std::invalid_argument("null variable interior key");
    if (entry.key->storage_length() >
        std::numeric_limits<std::size_t>::max() - result) {
      throw std::overflow_error("variable interior storage size overflow");
    }
    result += entry.key->storage_length();
  }
  return result;
}

void VariableKeyInteriorNode::rebuild(const std::vector<Entry> &values) {
  if (storage_size(values) > buffer_->size()) {
    throw std::length_error("variable interior entries do not fit buffer");
  }
  for (std::size_t index = 0; index < values.size(); ++index) {
    require_key_type(*values[index].key);
    if (values[index].child_id < 0) {
      throw std::invalid_argument("negative variable interior child id");
    }
    if (index != 0 && values[index - 1].key->compare(*values[index].key) >= 0) {
      throw std::invalid_argument("variable interior keys are not increasing");
    }
  }

  std::vector<std::shared_ptr<VariableKeyNode>> children;
  children.reserve(values.size());
  for (const auto &entry : values) {
    children.push_back(manager_.get_variable_key_node(entry.child_id));
  }

  auto cursor = buffer_->size();
  for (std::size_t index = 0; index < values.size(); ++index) {
    cursor -= values[index].key->storage_length();
    values[index].key->write(*buffer_, cursor);
    put_key_offset(index, cursor);
    buffer_->put_i32(entry_base_offset + index * entry_size + key_offset_size,
                     values[index].child_id);
  }
  set_key_count(values.size());
  for (const auto &child : children) {
    child->parent_ = this;
  }
}

std::size_t VariableKeyInteriorNode::offset_index(std::size_t offset) const {
  std::size_t minimum = 0;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    if (key_offset(index) < offset)
      maximum = index;
    else
      minimum = index + 1;
  }
  if (minimum != 0 && key_offset(minimum - 1) == offset)
    return minimum - 1;
  return minimum;
}

std::shared_ptr<VariableKeyNode> VariableKeyInteriorNode::split_for_insert(
    const std::shared_ptr<VariableKeyNode> &node) {
  if (key_count_ < 3) {
    throw std::logic_error(
        "cannot split variable interior with fewer than three keys");
  }
  auto key = node->key_field(0);
  const auto halfway = (key_offset(key_count_ - 1) + buffer_->size()) / 2;
  const auto split = offset_index(halfway);
  if (split == 0 || split >= key_count_) {
    throw std::logic_error("invalid Java-compatible variable interior split");
  }
  auto values = entries();
  std::vector<Entry> left_values;
  std::vector<Entry> right_values;
  left_values.reserve(split);
  right_values.reserve(values.size() - split);
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index < split)
      left_values.push_back(std::move(values[index]));
    else
      right_values.push_back(std::move(values[index]));
  }

  auto right = manager_.create_empty_variable_key_interior();
  rebuild(left_values);
  right->rebuild(right_values);
  auto right_key_before_insert = right->key_field(0);
  if (key->compare(*right_key_before_insert) < 0) {
    (void)insert_child(node);
  } else {
    (void)right->insert_child(node);
  }

  if (parent_) {
    return parent_->insert_child(right);
  }
  auto new_left_key = key_field(0);
  auto right_key = right->key_field(0);
  return manager_.create_variable_key_interior(*new_left_key, buffer_id(),
                                               *right_key, right->buffer_id());
}

std::shared_ptr<VariableKeyNode> VariableKeyInteriorNode::split_for_key_change(
    std::size_t old_index, const Field &old_key, const Field &new_key,
    const std::shared_ptr<VariableKeyNode> &child) {
  if (key_count_ < 3 || old_index >= key_count_) {
    throw std::logic_error("invalid variable interior key-change split");
  }
  const auto halfway = (key_offset(key_count_ - 1) + buffer_->size()) / 2;
  const auto split = offset_index(halfway);
  if (split == 0 || split >= key_count_) {
    throw std::logic_error("invalid Java-compatible variable interior split");
  }
  auto values = entries();
  std::vector<Entry> left_values;
  std::vector<Entry> right_values;
  left_values.reserve(split);
  right_values.reserve(values.size() - split);
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index < split)
      left_values.push_back(std::move(values[index]));
    else
      right_values.push_back(std::move(values[index]));
  }

  auto right = manager_.create_empty_variable_key_interior();
  rebuild(left_values);
  right->rebuild(right_values);
  if (old_index < split) {
    auto updated = entries();
    updated[old_index].key = new_key.clone();
    rebuild(updated);
    if (old_index == 0 && parent_) {
      (void)parent_->child_key_changed(old_key, new_key, shared_from_this());
    }
  } else {
    auto updated = right->entries();
    updated[old_index - split].key = new_key.clone();
    right->rebuild(updated);
    child->parent_ = right.get();
  }

  if (parent_)
    return parent_->insert_child(right);
  auto left_key = key_field(0);
  auto right_key = right->key_field(0);
  return manager_.create_variable_key_interior(*left_key, buffer_id(),
                                               *right_key, right->buffer_id());
}

std::shared_ptr<VariableKeyNode> VariableKeyInteriorNode::insert_child(
    const std::shared_ptr<VariableKeyNode> &node) {
  if (!node || node.get() == this || node->key_count() == 0) {
    throw std::invalid_argument("invalid variable-key child insertion");
  }
  auto key = node->key_field(0);
  require_key_type(*key);
  const auto found = key_index(*key);
  if (found >= 0)
    throw std::logic_error("duplicate variable interior key");
  const auto insertion = static_cast<std::size_t>(-found - 1);
  auto values = entries();
  auto old_left = values.front().key->clone();
  values.insert(values.begin() + static_cast<std::ptrdiff_t>(insertion),
                Entry{key->clone(), node->buffer_id()});

  if (storage_size(values) > buffer_->size()) {
    return split_for_insert(node);
  }
  rebuild(values);
  node->parent_ = this;
  if (insertion == 0 && parent_ && old_left) {
    return parent_->child_key_changed(*old_left, *key, shared_from_this());
  }
  return root();
}

std::shared_ptr<VariableKeyNode> VariableKeyInteriorNode::child_key_changed(
    const Field &old_key, const Field &new_key,
    const std::shared_ptr<VariableKeyNode> &child) {
  require_key_type(old_key);
  require_key_type(new_key);
  const auto found = key_index(old_key);
  if (found < 0)
    throw std::logic_error("old variable child key not found");
  const auto index = static_cast<std::size_t>(found);
  if (!child || child_id(index) != child->buffer_id()) {
    throw std::logic_error("variable child key update has wrong child");
  }
  auto values = entries();
  values[index].key = new_key.clone();
  if ((index > 0 && values[index - 1].key->compare(new_key) >= 0) ||
      (index + 1 < values.size() &&
       new_key.compare(*values[index + 1].key) >= 0)) {
    throw std::logic_error("updated variable child key breaks ordering");
  }
  if (storage_size(values) > buffer_->size()) {
    return split_for_key_change(index, old_key, new_key, child);
  }
  rebuild(values);
  if (index == 0 && parent_) {
    return parent_->child_key_changed(old_key, new_key, shared_from_this());
  }
  return root();
}

std::shared_ptr<VariableKeyNode>
VariableKeyInteriorNode::delete_child(const Field &key) {
  const auto found = key_index(key);
  if (found < 0)
    throw std::logic_error("variable child key not found");
  const auto index = static_cast<std::size_t>(found);
  if (key_count_ == 2) {
    if (parent_)
      throw std::logic_error("non-root interior has two children");
    auto new_root = manager_.get_variable_key_node(child_id(1 - index));
    new_root->parent_ = nullptr;
    manager_.delete_node(shared_from_this());
    return new_root;
  }

  delete_entry(index);
  if (index == 0 && parent_) {
    auto new_key = key_field(0);
    (void)parent_->child_key_changed(key, *new_key, shared_from_this());
  }
  return parent_ ? parent_->balance_child(*this) : shared_from_this();
}

std::shared_ptr<VariableKeyNode>
VariableKeyInteriorNode::balance_child(VariableKeyInteriorNode &node) {
  const auto unit = maximum_key_length_ + entry_size;
  const auto threshold = (minimum_key_capacity / 2) * unit;
  if (node.free_space() < threshold)
    return root();
  auto node_key = node.key_field(0);
  const auto index = child_index(*node_key);
  if (index == key_count_ - 1) {
    auto left = std::dynamic_pointer_cast<VariableKeyInteriorNode>(
        manager_.get_variable_key_node(child_id(index - 1)));
    if (!left)
      throw std::logic_error("variable interior sibling mismatch");
    return balance_pair(*left, node);
  }
  auto right = std::dynamic_pointer_cast<VariableKeyInteriorNode>(
      manager_.get_variable_key_node(child_id(index + 1)));
  if (!right)
    throw std::logic_error("variable interior sibling mismatch");
  return balance_pair(node, *right);
}

std::shared_ptr<VariableKeyNode>
VariableKeyInteriorNode::balance_pair(VariableKeyInteriorNode &left,
                                      VariableKeyInteriorNode &right) {
  auto right_key = right.key_field(0);
  auto combined = left.entries();
  auto right_values = right.entries();
  for (auto &entry : right_values)
    combined.push_back(std::move(entry));

  if (storage_size(combined) <= left.buffer_->size()) {
    left.rebuild(combined);
    manager_.delete_node(right.shared_from_this());
    return delete_child(*right_key);
  }

  const auto buffer_size = left.buffer_->size();
  const auto left_key_space =
      buffer_size - left.key_offset(left.key_count_ - 1);
  const auto right_key_space =
      buffer_size - right.key_offset(right.key_count_ - 1);
  const auto half_key_space = (left_key_space + right_key_space) / 2;
  std::size_t split = left.key_count_;
  if (half_key_space < left_key_space) {
    const auto index = left.offset_index(buffer_size - half_key_space);
    const auto count =
        index + 1 < left.key_count_ ? left.key_count_ - index - 1 : 0;
    if (count == 0)
      return root();
    split -= count;
  } else {
    const auto index = right.offset_index(buffer_size - half_key_space);
    const auto count =
        index + 1 < right.key_count_ ? right.key_count_ - index - 1 : 0;
    if (count == 0)
      return root();
    split += count;
  }
  std::vector<Entry> left_values;
  std::vector<Entry> redistributed_right;
  for (std::size_t index = 0; index < combined.size(); ++index) {
    if (index < split)
      left_values.push_back(std::move(combined[index]));
    else
      redistributed_right.push_back(std::move(combined[index]));
  }
  left.rebuild(left_values);
  right.rebuild(redistributed_right);
  auto new_right_key = right.key_field(0);
  if (!right_key->equals(*new_right_key)) {
    return child_key_changed(*right_key, *new_right_key,
                             right.shared_from_this());
  }
  return root();
}

bool VariableKeyInteriorNode::is_leftmost_key(const Field &key) const {
  if (child_index(key) != 0)
    return false;
  return parent_ ? parent_->is_leftmost_key(key) : true;
}

bool VariableKeyInteriorNode::is_rightmost_key(const Field &key) const {
  if (child_index(key) != key_count_ - 1)
    return false;
  if (!parent_)
    return true;
  auto first = key_field(0);
  return parent_->is_rightmost_key(*first);
}

void VariableKeyInteriorNode::delete_tree() {
  const auto ids = buffer_references();
  for (const auto id : ids)
    manager_.get_variable_key_node(id)->delete_tree();
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t> VariableKeyInteriorNode::buffer_references() const {
  std::vector<std::int32_t> result;
  result.reserve(key_count_);
  for (std::size_t index = 0; index < key_count_; ++index) {
    result.push_back(child_id(index));
  }
  return result;
}

bool VariableKeyInteriorNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  try {
    task.checkpoint();
    if (key_count_ < 2 || storage_size(entries()) > buffer_->size())
      return false;
    std::unique_ptr<Field> previous_maximum;
    for (std::size_t index = 0; index < key_count_; ++index) {
      task.checkpoint();
      auto key = key_field(index);
      if (previous_maximum && key->compare(*previous_maximum) <= 0)
        return false;
      auto child = manager_.get_variable_key_node(child_id(index));
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
  } catch (const OperationCancelled &) {
    throw;
  } catch (...) {
    return false;
  }
}

VariableKeyRecordNode::VariableKeyRecordNode(
    NodeManager &manager, std::shared_ptr<DataBuffer> existing)
    : VariableKeyNode(manager, std::move(existing)) {
  if (entry_base_offset + key_count_ * entry_size > buffer_->size()) {
    throw std::runtime_error("variable-key record entry table exceeds buffer");
  }
  for (std::size_t index = 0; index < key_count_; ++index) {
    const auto offset = key_offset(index);
    if (offset < entry_base_offset + key_count_ * entry_size ||
        offset >= buffer_->size()) {
      throw std::runtime_error("invalid variable-key record offset");
    }
  }
}

VariableKeyRecordNode::VariableKeyRecordNode(NodeManager &manager,
                                             std::int32_t previous_leaf_id,
                                             std::int32_t next_leaf_id)
    : VariableKeyNode(manager,
                      static_cast<std::uint8_t>(
                          NodeManager::NodeType::variable_key_record)) {
  if (buffer_->size() < entry_base_offset + entry_size + 1) {
    throw std::runtime_error("buffer is too small for variable-key leaf");
  }
  buffer_->put_i32(previous_leaf_id_offset, previous_leaf_id);
  buffer_->put_i32(next_leaf_id_offset, next_leaf_id);
}

std::size_t VariableKeyRecordNode::key_offset(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("variable record key index");
  const auto value = buffer_->get_i32(entry_base_offset + index * entry_size);
  if (value < 0)
    throw std::runtime_error("negative variable record offset");
  return static_cast<std::size_t>(value);
}

std::size_t VariableKeyRecordNode::record_data_offset(std::size_t index) const {
  const auto offset = key_offset(index);
  const auto key_length = key_type_->read_length(*buffer_, offset);
  if (key_length > buffer_->size() - offset) {
    throw std::runtime_error("variable record key exceeds buffer");
  }
  return offset + key_length;
}

void VariableKeyRecordNode::put_key_offset(std::size_t index,
                                           std::size_t offset) {
  if (entry_base_offset + index * entry_size + stored_offset_size >
          buffer_->size() ||
      offset >
          static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::out_of_range("variable record key offset");
  }
  buffer_->put_i32(entry_base_offset + index * entry_size,
                   static_cast<std::int32_t>(offset));
}

bool VariableKeyRecordNode::indirect(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("variable indirect index");
  return buffer_->get_u8(entry_base_offset + index * entry_size +
                         stored_offset_size) != 0;
}

void VariableKeyRecordNode::set_indirect(std::size_t index, bool state) {
  if (index >= key_count_)
    throw std::out_of_range("variable indirect index");
  buffer_->put_u8(entry_base_offset + index * entry_size + stored_offset_size,
                  state ? std::uint8_t{1} : std::uint8_t{0});
}

std::size_t VariableKeyRecordNode::free_space() const {
  const auto data_begin =
      key_count_ == 0 ? buffer_->size() : key_offset(key_count_ - 1);
  const auto entries_end = entry_base_offset + key_count_ * entry_size;
  if (data_begin < entries_end) {
    throw std::runtime_error("variable record entries overlap data");
  }
  return data_begin - entries_end;
}

std::size_t VariableKeyRecordNode::full_record_length(std::size_t index) const {
  if (index >= key_count_)
    throw std::out_of_range("full record length index");
  const auto offset = key_offset(index);
  const auto end = index == 0 ? buffer_->size() : key_offset(index - 1);
  if (offset > end)
    throw std::runtime_error("invalid variable record offsets");
  return end - offset;
}

std::size_t VariableKeyRecordNode::move_records(std::size_t index,
                                                std::ptrdiff_t shift) {
  if (index > key_count_)
    throw std::out_of_range("record movement index");
  if (index == key_count_) {
    const auto end = index == 0 ? buffer_->size() : key_offset(key_count_ - 1);
    return shifted_offset(end, shift);
  }
  const auto start = key_offset(key_count_ - 1);
  const auto end = index == 0 ? buffer_->size() : key_offset(index - 1);
  if (start > end)
    throw std::runtime_error("invalid variable record block");
  buffer_->move(start, shifted_offset(start, shift), end - start);
  for (auto current = index; current < key_count_; ++current) {
    put_key_offset(current, shifted_offset(key_offset(current), shift));
  }
  return shifted_offset(end, shift);
}

std::ptrdiff_t VariableKeyRecordNode::record_offset(std::size_t index) const {
  const auto offset = record_data_offset(index);
  if (!indirect(index))
    return static_cast<std::ptrdiff_t>(offset);
  return -static_cast<std::ptrdiff_t>(buffer_->get_i32(offset));
}

std::shared_ptr<VariableKeyRecordNode>
VariableKeyRecordNode::leaf_for(const Field &key) {
  require_key_type(key);
  return std::static_pointer_cast<VariableKeyRecordNode>(shared_from_this());
}

std::unique_ptr<Record>
VariableKeyRecordNode::record_at(std::size_t index) const {
  auto key = key_field(index);
  auto result = manager_.schema().create_record(std::move(key));
  const auto offset = record_data_offset(index);
  if (indirect(index)) {
    ChainedBuffer chained(manager_.buffer_manager(), buffer_->get_i32(offset));
    result->read(chained, 0);
  } else {
    result->read(*buffer_, offset);
  }
  return result;
}

std::unique_ptr<Record> VariableKeyRecordNode::record(const Field &key) const {
  const auto found = key_index(key);
  return found < 0 ? nullptr : record_at(static_cast<std::size_t>(found));
}

std::shared_ptr<VariableKeyRecordNode>
VariableKeyRecordNode::next_leaf() const {
  const auto id = buffer_->get_i32(next_leaf_id_offset);
  if (id < 0)
    return nullptr;
  auto result = std::dynamic_pointer_cast<VariableKeyRecordNode>(
      manager_.get_variable_key_node(id));
  if (!result)
    throw std::logic_error("next variable-key leaf type mismatch");
  return result;
}

std::shared_ptr<VariableKeyRecordNode>
VariableKeyRecordNode::previous_leaf() const {
  const auto id = buffer_->get_i32(previous_leaf_id_offset);
  if (id < 0)
    return nullptr;
  auto result = std::dynamic_pointer_cast<VariableKeyRecordNode>(
      manager_.get_variable_key_node(id));
  if (!result)
    throw std::logic_error("previous variable-key leaf type mismatch");
  return result;
}

std::unique_ptr<Record>
VariableKeyRecordNode::record_before(const Field &key) const {
  if (key_count_ == 0)
    return nullptr;
  auto index = key_index(key);
  index = index < 0 ? -index - 2 : index - 1;
  if (index < 0) {
    auto leaf = previous_leaf();
    return leaf ? leaf->record_at(leaf->key_count_ - 1) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::unique_ptr<Record>
VariableKeyRecordNode::record_after(const Field &key) const {
  if (key_count_ == 0)
    return nullptr;
  auto index = key_index(key);
  index = index < 0 ? -index - 1 : index + 1;
  if (static_cast<std::size_t>(index) == key_count_) {
    auto leaf = next_leaf();
    return leaf ? leaf->record_at(0) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::unique_ptr<Record>
VariableKeyRecordNode::record_at_or_before(const Field &key) const {
  if (key_count_ == 0)
    return nullptr;
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
VariableKeyRecordNode::record_at_or_after(const Field &key) const {
  if (key_count_ == 0)
    return nullptr;
  auto index = key_index(key);
  if (index < 0)
    index = -index - 1;
  if (static_cast<std::size_t>(index) == key_count_) {
    auto leaf = next_leaf();
    return leaf ? leaf->record_at(0) : nullptr;
  }
  return record_at(static_cast<std::size_t>(index));
}

std::size_t VariableKeyRecordNode::maximum_inline_record_length(
    std::size_t key_length) const {
  if (buffer_->size() <= entry_base_offset)
    return 0;
  const auto quarter = (buffer_->size() - entry_base_offset) >> 2;
  if (quarter <= entry_size || quarter - entry_size <= key_length)
    return 0;
  return quarter - entry_size - key_length;
}

bool VariableKeyRecordNode::insert_record(std::size_t index,
                                          Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("record schema differs from variable-key leaf");
  }
  const auto &key = record_value.key();
  require_key_type(key);
  if (index > key_count_)
    throw std::out_of_range("record insertion index");
  const auto key_length = key.storage_length();
  const auto logical_length = record_value.storage_length();
  const auto use_indirect =
      logical_length > maximum_inline_record_length(key_length);
  const auto physical_length = use_indirect ? std::size_t{4} : logical_length;
  const auto full_length = key_length + physical_length;
  if (full_length + entry_size > free_space())
    return false;

  auto serialized = serialize_record(record_value);
  std::unique_ptr<PendingChainedBuffer> pending_chain;
  if (use_indirect) {
    pending_chain = std::make_unique<PendingChainedBuffer>(
        manager_.buffer_manager(), serialized);
  }
  auto original_bytes = buffer_->bytes();

  try {
    const auto offset =
        move_records(index, -static_cast<std::ptrdiff_t>(full_length));
    const auto entry_offset = entry_base_offset + index * entry_size;
    buffer_->move(entry_offset, entry_offset + entry_size,
                  (key_count_ - index) * entry_size);
    buffer_->put_i32(entry_offset, static_cast<std::int32_t>(offset));
    key.write(*buffer_, offset);
    set_key_count(key_count_ + 1);
    const auto data_offset = offset + key_length;
    if (use_indirect) {
      buffer_->put_i32(data_offset, pending_chain->id());
    } else {
      buffer_->put(data_offset, serialized);
    }
    set_indirect(index, use_indirect);
  } catch (...) {
    buffer_->set_data(std::move(original_bytes));
    buffer_->set_dirty(true);
    throw;
  }
  if (pending_chain)
    pending_chain->commit();
  return true;
}

std::shared_ptr<VariableKeyNode>
VariableKeyRecordNode::update_record(std::size_t index, Record &record_value) {
  auto old_key = key_field(index);
  if (!record_value.key().equals(*old_key) ||
      !record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("updated variable-key record differs");
  }
  const auto key_length = old_key->storage_length();
  const auto old_full_length = full_record_length(index);
  if (old_full_length < key_length) {
    throw std::runtime_error("variable record is shorter than its key");
  }
  const auto old_physical_length = old_full_length - key_length;
  const auto logical_length = record_value.storage_length();
  const auto was_indirect = indirect(index);
  const auto use_indirect =
      logical_length > maximum_inline_record_length(key_length);
  const auto new_physical_length =
      use_indirect ? std::size_t{4} : logical_length;
  const auto old_data_offset = record_data_offset(index);

  if (new_physical_length <= old_physical_length + free_space()) {
    std::int32_t old_chain_id = -1;
    if (was_indirect)
      old_chain_id = buffer_->get_i32(old_data_offset);

    auto serialized = serialize_record(record_value);
    std::unique_ptr<PendingChainedBuffer> pending_chain;
    if (use_indirect) {
      pending_chain = std::make_unique<PendingChainedBuffer>(
          manager_.buffer_manager(), serialized);
    }
    auto original_bytes = buffer_->bytes();

    try {
      const auto shift = static_cast<std::ptrdiff_t>(old_physical_length) -
                         static_cast<std::ptrdiff_t>(new_physical_length);
      auto new_key_offset = key_offset(index);
      if (shift != 0) {
        new_key_offset = move_records(index + 1, shift);
        put_key_offset(index, new_key_offset);
      }
      old_key->write(*buffer_, new_key_offset);
      const auto new_data_offset = new_key_offset + key_length;
      if (use_indirect) {
        buffer_->put_i32(new_data_offset, pending_chain->id());
      } else {
        buffer_->put(new_data_offset, serialized);
      }
      set_indirect(index, use_indirect);
    } catch (...) {
      buffer_->set_data(std::move(original_bytes));
      buffer_->set_dirty(true);
      throw;
    }
    if (pending_chain)
      pending_chain->commit();
    if (old_chain_id >= 0)
      remove_indirect(old_chain_id);
    return root();
  }

  auto key = record_value.key().clone();
  auto new_root = delete_record(*key);
  if (!new_root) {
    auto leaf = manager_.create_variable_key_record_node();
    if (!leaf->insert_record(0, record_value)) {
      throw std::logic_error("empty variable-key leaf rejected record");
    }
    return leaf;
  }
  return new_root->leaf_for(*key)->put_record(record_value);
}

std::shared_ptr<VariableKeyNode>
VariableKeyRecordNode::put_record(Record &record_value) {
  if (!record_value.has_same_schema(manager_.schema())) {
    throw std::invalid_argument("record schema differs from variable-key leaf");
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
      return parent_->child_key_changed(*old_key, key, shared_from_this());
    }
    return root();
  }
  if (insertion == key_count_) {
    auto leaf = create_leaf(-1, -1);
    if (!leaf->insert_record(0, record_value)) {
      throw std::logic_error("empty variable-key leaf rejected record");
    }
    return append_leaf(leaf);
  }
  auto new_root = split_leaf();
  return new_root->leaf_for(key)->put_record(record_value);
}

void VariableKeyRecordNode::remove_indirect(std::int32_t buffer_id) {
  ChainedBuffer chained(manager_.buffer_manager(), buffer_id);
  chained.remove();
}

void VariableKeyRecordNode::remove_record(std::size_t index) {
  if (index >= key_count_)
    throw std::out_of_range("record removal index");
  if (indirect(index)) {
    remove_indirect(buffer_->get_i32(record_data_offset(index)));
    set_indirect(index, false);
  }
  const auto length = full_record_length(index);
  (void)move_records(index + 1, static_cast<std::ptrdiff_t>(length));
  const auto following = entry_base_offset + (index + 1) * entry_size;
  buffer_->move(following, following - entry_size,
                (key_count_ - index - 1) * entry_size);
  set_key_count(key_count_ - 1);
}

std::shared_ptr<VariableKeyNode>
VariableKeyRecordNode::delete_record(const Field &key) {
  const auto found = key_index(key);
  if (found < 0)
    return root();
  const auto index = static_cast<std::size_t>(found);
  if (key_count_ == 1)
    return remove_leaf();
  remove_record(index);
  if (index == 0 && parent_) {
    auto new_key = key_field(0);
    return parent_->child_key_changed(key, *new_key, shared_from_this());
  }
  return root();
}

std::size_t VariableKeyRecordNode::split_index() const {
  if (key_count_ < 2)
    throw std::logic_error("cannot split one-record leaf");
  const auto halfway = (key_offset(key_count_ - 1) + buffer_->size()) / 2;
  std::size_t minimum = 0;
  std::size_t maximum = key_count_;
  while (minimum < maximum) {
    const auto index = minimum + (maximum - minimum) / 2;
    if (key_offset(index) > halfway)
      minimum = index + 1;
    else
      maximum = index;
  }
  return std::clamp(minimum, std::size_t{1}, key_count_ - 1);
}

void VariableKeyRecordNode::split_data(VariableKeyRecordNode &right) {
  const auto split = split_index();
  const auto count = key_count_ - split;
  const auto start = key_offset(key_count_ - 1);
  const auto end = key_offset(split - 1);
  if (start > end)
    throw std::runtime_error("invalid variable record split");
  const auto length = end - start;
  const auto right_offset = buffer_->size() - length;
  right.buffer_->copy(right_offset, *buffer_, start, length);
  right.buffer_->copy(entry_base_offset, *buffer_,
                      entry_base_offset + split * entry_size,
                      count * entry_size);
  const auto correction = buffer_->size() - end;
  right.set_key_count(count);
  for (std::size_t index = 0; index < count; ++index) {
    right.put_key_offset(index, right.key_offset(index) + correction);
  }
  set_key_count(split);
}

std::shared_ptr<VariableKeyRecordNode>
VariableKeyRecordNode::create_leaf(std::int32_t previous_leaf_id,
                                   std::int32_t next_leaf_id) {
  return manager_.create_variable_key_record_node(previous_leaf_id,
                                                  next_leaf_id);
}

std::shared_ptr<VariableKeyNode> VariableKeyRecordNode::split_leaf() {
  const auto old_next = buffer_->get_i32(next_leaf_id_offset);
  auto right = create_leaf(buffer_id(), old_next);
  buffer_->put_i32(next_leaf_id_offset, right->buffer_id());
  if (old_next >= 0) {
    auto old_sibling = std::dynamic_pointer_cast<VariableKeyRecordNode>(
        manager_.get_variable_key_node(old_next));
    if (!old_sibling)
      throw std::logic_error("variable leaf sibling mismatch");
    old_sibling->buffer_->put_i32(previous_leaf_id_offset, right->buffer_id());
  }
  split_data(*right);
  if (parent_)
    return parent_->insert_child(right);
  auto left_key = key_field(0);
  auto right_key = right->key_field(0);
  return manager_.create_variable_key_interior(*left_key, buffer_id(),
                                               *right_key, right->buffer_id());
}

std::shared_ptr<VariableKeyNode> VariableKeyRecordNode::append_leaf(
    const std::shared_ptr<VariableKeyRecordNode> &leaf) {
  if (!leaf || leaf.get() == this || leaf->key_count_ == 0) {
    throw std::invalid_argument("invalid appended variable-key leaf");
  }
  leaf->buffer_->put_i32(previous_leaf_id_offset, buffer_id());
  const auto old_next = buffer_->get_i32(next_leaf_id_offset);
  leaf->buffer_->put_i32(next_leaf_id_offset, old_next);
  buffer_->put_i32(next_leaf_id_offset, leaf->buffer_id());
  if (old_next >= 0) {
    auto right = std::dynamic_pointer_cast<VariableKeyRecordNode>(
        manager_.get_variable_key_node(old_next));
    if (!right)
      throw std::logic_error("variable leaf sibling mismatch");
    right->buffer_->put_i32(previous_leaf_id_offset, leaf->buffer_id());
  }
  if (parent_)
    return parent_->insert_child(leaf);
  auto this_key = key_field(0);
  auto leaf_key = leaf->key_field(0);
  return manager_.create_variable_key_interior(*this_key, buffer_id(),
                                               *leaf_key, leaf->buffer_id());
}

void VariableKeyRecordNode::remove_all_indirect() {
  for (std::size_t index = 0; index < key_count_; ++index) {
    if (indirect(index)) {
      const auto offset = record_data_offset(index);
      remove_indirect(buffer_->get_i32(offset));
      buffer_->put_i32(offset, -1);
      set_indirect(index, false);
    }
  }
}

std::shared_ptr<VariableKeyNode> VariableKeyRecordNode::remove_leaf() {
  if (key_count_ == 0)
    throw std::logic_error("cannot remove empty variable leaf");
  remove_all_indirect();
  auto key = key_field(0);
  const auto previous_id = buffer_->get_i32(previous_leaf_id_offset);
  const auto next_id = buffer_->get_i32(next_leaf_id_offset);
  if (previous_id >= 0) {
    auto previous = std::dynamic_pointer_cast<VariableKeyRecordNode>(
        manager_.get_variable_key_node(previous_id));
    if (!previous)
      throw std::logic_error("variable leaf sibling mismatch");
    previous->buffer_->put_i32(next_leaf_id_offset, next_id);
  }
  if (next_id >= 0) {
    auto next = std::dynamic_pointer_cast<VariableKeyRecordNode>(
        manager_.get_variable_key_node(next_id));
    if (!next)
      throw std::logic_error("variable leaf sibling mismatch");
    next->buffer_->put_i32(previous_leaf_id_offset, previous_id);
  }
  auto old_parent = parent_;
  manager_.delete_node(shared_from_this());
  return old_parent ? old_parent->delete_child(*key) : nullptr;
}

void VariableKeyRecordNode::delete_tree() {
  remove_all_indirect();
  manager_.delete_node(shared_from_this());
}

std::vector<std::int32_t> VariableKeyRecordNode::buffer_references() const {
  std::vector<std::int32_t> result;
  for (std::size_t index = 0; index < key_count_; ++index) {
    if (indirect(index)) {
      result.push_back(buffer_->get_i32(record_data_offset(index)));
    }
  }
  return result;
}

bool VariableKeyRecordNode::consistent(const TaskContext &task) {
  auto consistency_scope = manager_.enter_consistency_node(buffer_id());
  try {
    task.checkpoint();
    if (key_count_ == 0)
      return false;
    const auto entries_end = entry_base_offset + key_count_ * entry_size;
    auto previous_offset = buffer_->size();
    std::unique_ptr<Field> previous_key;
    for (std::size_t index = 0; index < key_count_; ++index) {
      task.checkpoint();
      const auto offset = key_offset(index);
      if (offset < entries_end || offset >= previous_offset)
        return false;
      auto key = key_field(index);
      if (previous_key && key->compare(*previous_key) <= 0)
        return false;
      const auto key_length = key_type_->read_length(*buffer_, offset);
      const auto full_length = previous_offset - offset;
      if (key_length > full_length)
        return false;
      const auto physical_length = full_length - key_length;
      if (indirect(index)) {
        if (physical_length != 4 || buffer_->get_i32(offset + key_length) < 0) {
          return false;
        }
      } else {
        (void)record_at(index);
      }
      previous_key = std::move(key);
      previous_offset = offset;
    }

    task.checkpoint();
    auto previous = previous_leaf();
    auto next = next_leaf();
    if (previous &&
        previous->buffer_->get_i32(next_leaf_id_offset) != buffer_id()) {
      return false;
    }
    if (next &&
        next->buffer_->get_i32(previous_leaf_id_offset) != buffer_id()) {
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
  } catch (const OperationCancelled &) {
    throw;
  } catch (...) {
    return false;
  }
}

} // namespace llmghidra::db
