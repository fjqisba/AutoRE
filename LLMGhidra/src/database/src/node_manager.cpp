/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/node_manager.hpp"

#include "llmghidra/db/fixed_key_nodes.hpp"
#include "llmghidra/db/long_key_nodes.hpp"
#include "llmghidra/db/variable_key_nodes.hpp"

#include <stdexcept>
#include <utility>

namespace llmghidra::db {

NodeManager::ConsistencyNodeScope::ConsistencyNodeScope(NodeManager &manager,
                                                        std::int32_t buffer_id)
    : manager_(&manager), buffer_id_(buffer_id) {}

NodeManager::ConsistencyNodeScope::ConsistencyNodeScope(
    ConsistencyNodeScope &&other) noexcept
    : manager_(std::exchange(other.manager_, nullptr)),
      buffer_id_(other.buffer_id_) {}

NodeManager::ConsistencyNodeScope::~ConsistencyNodeScope() {
  if (manager_)
    manager_->leave_consistency_node(buffer_id_);
}

NodeManager::NodeManager(BufferManager &buffer_manager,
                         std::shared_ptr<const Schema> schema,
                         std::string table_name)
    : buffer_manager_(buffer_manager), schema_(std::move(schema)),
      table_name_(std::move(table_name)) {
  if (!schema_)
    throw std::invalid_argument("NodeManager requires a schema");
}

NodeManager::~NodeManager() {
  try {
    (void)release_nodes();
  } catch (...) {
  }
}

NodeManager::ConsistencyNodeScope
NodeManager::enter_consistency_node(std::int32_t buffer_id) {
  if (consistency_active_.contains(buffer_id)) {
    throw StorageIntegrityError(StorageIntegrityCode::node_cycle, buffer_id,
                                table_name_);
  }
  if (consistency_visited_.contains(buffer_id)) {
    throw StorageIntegrityError(StorageIntegrityCode::duplicate_node_ownership,
                                buffer_id, table_name_);
  }
  consistency_visited_.insert(buffer_id);
  consistency_active_.insert(buffer_id);
  ++consistency_depth_;
  return ConsistencyNodeScope(*this, buffer_id);
}

void NodeManager::leave_consistency_node(std::int32_t buffer_id) noexcept {
  consistency_active_.erase(buffer_id);
  if (consistency_depth_ != 0)
    --consistency_depth_;
  if (consistency_depth_ == 0) {
    consistency_active_.clear();
    consistency_visited_.clear();
  }
}

NodeManager::NodeType NodeManager::node_type(const DataBuffer &buffer) {
  return static_cast<NodeType>(buffer.get_u8(node_type_offset));
}

void NodeManager::set_node_type(DataBuffer &buffer, NodeType type) {
  buffer.put_u8(node_type_offset, static_cast<std::uint8_t>(type));
}

bool NodeManager::is_variable_key_node(BufferManager &manager,
                                       std::int32_t buffer_id) {
  auto buffer = manager.get_buffer(buffer_id);
  const auto type = node_type(*buffer);
  manager.release_buffer(buffer);
  return type == NodeType::variable_key_record ||
         type == NodeType::variable_key_interior;
}

template <typename Node>
std::shared_ptr<Node> NodeManager::cache_new_node(std::shared_ptr<Node> node,
                                                  bool existing_leaf) {
  const auto id = node->buffer_id();
  if (id < 0 || nodes_.contains(id)) {
    throw std::logic_error("duplicate or invalid NodeManager buffer id");
  }
  nodes_.emplace(id, node);
  if (existing_leaf) {
    leaf_record_balance_ += static_cast<std::int64_t>(node->key_count());
  }
  return node;
}

std::shared_ptr<LongKeyNode>
NodeManager::get_long_key_node(std::int32_t buffer_id) {
  const auto cached = nodes_.find(buffer_id);
  if (cached != nodes_.end()) {
    auto node = std::dynamic_pointer_cast<LongKeyNode>(cached->second);
    if (!node) {
      throw std::logic_error("cached node is not a long-key node");
    }
    return node;
  }

  auto buffer = buffer_manager_.get_buffer(buffer_id);
  try {
    switch (node_type(*buffer)) {
    case NodeType::long_key_fixed_record: {
      if (schema_->variable_length()) {
        throw std::runtime_error(
            "fixed record node cannot use variable-length schema");
      }
      auto node = std::shared_ptr<FixedRecordNode>(
          new FixedRecordNode(*this, buffer, schema_->fixed_length()));
      return cache_new_node(std::move(node), true);
    }
    case NodeType::long_key_interior: {
      auto node = std::shared_ptr<LongKeyInteriorNode>(
          new LongKeyInteriorNode(*this, buffer));
      return cache_new_node(std::move(node), false);
    }
    case NodeType::long_key_variable_record: {
      if (!schema_->variable_length()) {
        throw std::runtime_error(
            "variable record node requires variable-length schema");
      }
      auto node = std::shared_ptr<VariableRecordNode>(
          new VariableRecordNode(*this, buffer));
      return cache_new_node(std::move(node), true);
    }
    default:
      throw std::runtime_error("unexpected node type for long-key tree");
    }
  } catch (...) {
    try {
      buffer_manager_.release_buffer(buffer);
    } catch (...) {
    }
    throw;
  }
}

std::shared_ptr<FixedKeyNode>
NodeManager::get_fixed_key_node(std::int32_t buffer_id) {
  const auto cached = nodes_.find(buffer_id);
  if (cached != nodes_.end()) {
    auto node = std::dynamic_pointer_cast<FixedKeyNode>(cached->second);
    if (!node)
      throw std::logic_error("cached node is not a fixed-key node");
    return node;
  }

  auto buffer = buffer_manager_.get_buffer(buffer_id);
  try {
    switch (node_type(*buffer)) {
    case NodeType::fixed_key_fixed_record: {
      if (!schema_->use_fixed_key_nodes() || schema_->variable_length()) {
        throw std::runtime_error("fixed-key fixed record schema mismatch");
      }
      auto node = std::shared_ptr<FixedKeyFixedRecordNode>(
          new FixedKeyFixedRecordNode(*this, buffer, schema_->fixed_length()));
      return cache_new_node(std::move(node), true);
    }
    case NodeType::fixed_key_interior: {
      if (!schema_->use_fixed_key_nodes()) {
        throw std::runtime_error("fixed-key interior schema mismatch");
      }
      auto node = std::shared_ptr<FixedKeyInteriorNode>(
          new FixedKeyInteriorNode(*this, buffer));
      return cache_new_node(std::move(node), false);
    }
    case NodeType::fixed_key_variable_record: {
      if (!schema_->use_fixed_key_nodes() || !schema_->variable_length()) {
        throw std::runtime_error("fixed-key variable record schema mismatch");
      }
      auto node = std::shared_ptr<FixedKeyVariableRecordNode>(
          new FixedKeyVariableRecordNode(*this, buffer));
      return cache_new_node(std::move(node), true);
    }
    default:
      throw std::runtime_error("unexpected node type for fixed-key tree");
    }
  } catch (...) {
    try {
      buffer_manager_.release_buffer(buffer);
    } catch (...) {
    }
    throw;
  }
}

std::shared_ptr<VariableKeyNode>
NodeManager::get_variable_key_node(std::int32_t buffer_id) {
  const auto cached = nodes_.find(buffer_id);
  if (cached != nodes_.end()) {
    auto node = std::dynamic_pointer_cast<VariableKeyNode>(cached->second);
    if (!node) {
      throw std::logic_error("cached node is not a variable-key node");
    }
    return node;
  }

  auto buffer = buffer_manager_.get_buffer(buffer_id);
  try {
    if (!schema_->use_variable_key_nodes()) {
      throw std::runtime_error("schema does not use variable-key nodes");
    }
    switch (node_type(*buffer)) {
    case NodeType::variable_key_record: {
      auto node = std::shared_ptr<VariableKeyRecordNode>(
          new VariableKeyRecordNode(*this, buffer));
      return cache_new_node(std::move(node), true);
    }
    case NodeType::variable_key_interior: {
      auto node = std::shared_ptr<VariableKeyInteriorNode>(
          new VariableKeyInteriorNode(*this, buffer));
      return cache_new_node(std::move(node), false);
    }
    default:
      throw std::runtime_error("unexpected node type for variable-key tree");
    }
  } catch (...) {
    try {
      buffer_manager_.release_buffer(buffer);
    } catch (...) {
    }
    throw;
  }
}

std::shared_ptr<FixedRecordNode>
NodeManager::create_fixed_record_node(std::int32_t previous_leaf_id,
                                      std::int32_t next_leaf_id) {
  if (!schema_->use_long_key_nodes() || schema_->variable_length()) {
    throw std::logic_error(
        "long-key fixed record node requires a fixed-length long-key schema");
  }
  auto node = std::shared_ptr<FixedRecordNode>(new FixedRecordNode(
      *this, schema_->fixed_length(), previous_leaf_id, next_leaf_id));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<VariableRecordNode>
NodeManager::create_variable_record_node(std::int32_t previous_leaf_id,
                                         std::int32_t next_leaf_id) {
  if (!schema_->use_long_key_nodes() || !schema_->variable_length()) {
    throw std::logic_error("long-key variable record node requires a "
                           "variable-length long-key schema");
  }
  auto node = std::shared_ptr<VariableRecordNode>(
      new VariableRecordNode(*this, previous_leaf_id, next_leaf_id));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<LongKeyRecordNode>
NodeManager::create_long_key_record_node(std::int32_t previous_leaf_id,
                                         std::int32_t next_leaf_id) {
  if (schema_->variable_length()) {
    return create_variable_record_node(previous_leaf_id, next_leaf_id);
  }
  return create_fixed_record_node(previous_leaf_id, next_leaf_id);
}

std::shared_ptr<LongKeyInteriorNode> NodeManager::create_long_key_interior(
    std::int64_t left_key, std::int32_t left_id, std::int64_t right_key,
    std::int32_t right_id) {
  if (!schema_->use_long_key_nodes()) {
    throw std::logic_error("schema does not use long-key interiors");
  }
  auto node = std::shared_ptr<LongKeyInteriorNode>(
      new LongKeyInteriorNode(*this, left_key, left_id, right_key, right_id));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<LongKeyInteriorNode>
NodeManager::create_empty_long_key_interior() {
  if (!schema_->use_long_key_nodes()) {
    throw std::logic_error("schema does not use long-key interiors");
  }
  auto node =
      std::shared_ptr<LongKeyInteriorNode>(new LongKeyInteriorNode(*this));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<FixedKeyFixedRecordNode>
NodeManager::create_fixed_key_fixed_record_node(std::int32_t previous_leaf_id,
                                                std::int32_t next_leaf_id) {
  if (!schema_->use_fixed_key_nodes() || schema_->variable_length()) {
    throw std::logic_error("schema does not use fixed-key fixed records");
  }
  auto node =
      std::shared_ptr<FixedKeyFixedRecordNode>(new FixedKeyFixedRecordNode(
          *this, schema_->fixed_length(), previous_leaf_id, next_leaf_id));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<FixedKeyVariableRecordNode>
NodeManager::create_fixed_key_variable_record_node(
    std::int32_t previous_leaf_id, std::int32_t next_leaf_id) {
  if (!schema_->use_fixed_key_nodes() || !schema_->variable_length()) {
    throw std::logic_error("schema does not use fixed-key variable records");
  }
  auto node = std::shared_ptr<FixedKeyVariableRecordNode>(
      new FixedKeyVariableRecordNode(*this, previous_leaf_id, next_leaf_id));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<FixedKeyRecordNode>
NodeManager::create_fixed_key_record_node(std::int32_t previous_leaf_id,
                                          std::int32_t next_leaf_id) {
  if (schema_->variable_length()) {
    return create_fixed_key_variable_record_node(previous_leaf_id,
                                                 next_leaf_id);
  }
  return create_fixed_key_fixed_record_node(previous_leaf_id, next_leaf_id);
}

std::shared_ptr<FixedKeyInteriorNode> NodeManager::create_fixed_key_interior(
    const Field &left_key, std::int32_t left_id, const Field &right_key,
    std::int32_t right_id) {
  if (!schema_->use_fixed_key_nodes()) {
    throw std::logic_error("schema does not use fixed-key interiors");
  }
  auto node = std::shared_ptr<FixedKeyInteriorNode>(
      new FixedKeyInteriorNode(*this, left_key, left_id, right_key, right_id));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<FixedKeyInteriorNode>
NodeManager::create_empty_fixed_key_interior() {
  if (!schema_->use_fixed_key_nodes()) {
    throw std::logic_error("schema does not use fixed-key interiors");
  }
  auto node =
      std::shared_ptr<FixedKeyInteriorNode>(new FixedKeyInteriorNode(*this));
  return cache_new_node(std::move(node), false);
}

std::shared_ptr<VariableKeyRecordNode>
NodeManager::create_variable_key_record_node(std::int32_t previous_leaf_id,
                                             std::int32_t next_leaf_id) {
  if (!schema_->use_variable_key_nodes()) {
    throw std::logic_error("schema does not use variable-key records");
  }
  auto node = std::shared_ptr<VariableKeyRecordNode>(
      new VariableKeyRecordNode(*this, previous_leaf_id, next_leaf_id));
  auto cached = cache_new_node(std::move(node), false);
  cached->commit_new_buffer();
  return cached;
}

std::shared_ptr<VariableKeyInteriorNode>
NodeManager::create_variable_key_interior(const Field &left_key,
                                          std::int32_t left_id,
                                          const Field &right_key,
                                          std::int32_t right_id) {
  if (!schema_->use_variable_key_nodes()) {
    throw std::logic_error("schema does not use variable-key interiors");
  }
  auto node =
      std::shared_ptr<VariableKeyInteriorNode>(new VariableKeyInteriorNode(
          *this, left_key, left_id, right_key, right_id));
  auto cached = cache_new_node(std::move(node), false);
  cached->commit_new_buffer();
  return cached;
}

std::shared_ptr<VariableKeyInteriorNode>
NodeManager::create_empty_variable_key_interior() {
  if (!schema_->use_variable_key_nodes()) {
    throw std::logic_error("schema does not use variable-key interiors");
  }
  auto node = std::shared_ptr<VariableKeyInteriorNode>(
      new VariableKeyInteriorNode(*this));
  auto cached = cache_new_node(std::move(node), false);
  cached->commit_new_buffer();
  return cached;
}

void NodeManager::delete_node(const std::shared_ptr<BTreeNode> &node) {
  if (!node)
    throw std::invalid_argument("cannot delete null BTree node");
  const auto id = node->buffer_id();
  const auto found = nodes_.find(id);
  if (found == nodes_.end() || found->second.get() != node.get()) {
    throw std::logic_error("BTree node is not owned by NodeManager");
  }
  const auto buffer = node->buffer_handle();
  buffer_manager_.release_buffer(buffer);
  nodes_.erase(found);
  buffer_manager_.delete_buffer(id);
  if (auto long_node = std::dynamic_pointer_cast<LongKeyNode>(node)) {
    long_node->invalidate();
  }
  if (auto fixed_node = std::dynamic_pointer_cast<FixedKeyNode>(node)) {
    fixed_node->invalidate();
  }
  if (auto variable_node = std::dynamic_pointer_cast<VariableKeyNode>(node)) {
    variable_node->invalidate();
  }
}

void NodeManager::release_read_only_node(std::int32_t buffer_id) {
  const auto found = nodes_.find(buffer_id);
  if (found == nodes_.end()) {
    throw std::out_of_range("NodeManager node is not cached");
  }
  const auto buffer = found->second->buffer_handle();
  if (buffer->dirty()) {
    throw std::logic_error("cannot release dirty node as read-only");
  }
  if (dynamic_cast<RecordNode *>(found->second.get())) {
    leaf_record_balance_ -=
        static_cast<std::int64_t>(found->second->key_count());
  }
  buffer_manager_.release_buffer(buffer);
  if (auto long_node = std::dynamic_pointer_cast<LongKeyNode>(found->second)) {
    long_node->invalidate();
  }
  if (auto fixed_node =
          std::dynamic_pointer_cast<FixedKeyNode>(found->second)) {
    fixed_node->invalidate();
  }
  if (auto variable_node =
          std::dynamic_pointer_cast<VariableKeyNode>(found->second)) {
    variable_node->invalidate();
  }
  nodes_.erase(found);
}

std::int64_t NodeManager::release_nodes() {
  for (auto &[id, node] : nodes_) {
    (void)id;
    if (dynamic_cast<RecordNode *>(node.get())) {
      leaf_record_balance_ -= static_cast<std::int64_t>(node->key_count());
    }
    buffer_manager_.release_buffer(node->buffer_handle());
    if (auto long_node = std::dynamic_pointer_cast<LongKeyNode>(node)) {
      long_node->invalidate();
    }
    if (auto fixed_node = std::dynamic_pointer_cast<FixedKeyNode>(node)) {
      fixed_node->invalidate();
    }
    if (auto variable_node = std::dynamic_pointer_cast<VariableKeyNode>(node)) {
      variable_node->invalidate();
    }
  }
  nodes_.clear();
  const auto result = -leaf_record_balance_;
  leaf_record_balance_ = 0;
  return result;
}

} // namespace llmghidra::db
