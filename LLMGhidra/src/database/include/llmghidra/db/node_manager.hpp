/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/btree_node.hpp"
#include "llmghidra/db/buffer_manager.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/storage_integrity.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace llmghidra::db {

class FixedRecordNode;
class FixedKeyFixedRecordNode;
class FixedKeyInteriorNode;
class FixedKeyNode;
class FixedKeyRecordNode;
class FixedKeyVariableRecordNode;
class LongKeyInteriorNode;
class LongKeyNode;
class LongKeyRecordNode;
class VariableKeyInteriorNode;
class VariableKeyNode;
class VariableKeyRecordNode;
class VariableRecordNode;

class NodeManager final {
public:
  class ConsistencyNodeScope final {
  public:
    ConsistencyNodeScope(const ConsistencyNodeScope &) = delete;
    ConsistencyNodeScope &operator=(const ConsistencyNodeScope &) = delete;
    ConsistencyNodeScope(ConsistencyNodeScope &&other) noexcept;
    ConsistencyNodeScope &operator=(ConsistencyNodeScope &&) = delete;
    ~ConsistencyNodeScope();

  private:
    friend class NodeManager;
    ConsistencyNodeScope(NodeManager &manager, std::int32_t buffer_id);
    NodeManager *manager_ = nullptr;
    std::int32_t buffer_id_ = -1;
  };

  static constexpr std::size_t node_type_offset = 0;
  static constexpr std::size_t node_header_size = 1;

  enum class NodeType : std::uint8_t {
    long_key_interior = 0,
    long_key_variable_record = 1,
    long_key_fixed_record = 2,
    variable_key_interior = 3,
    variable_key_record = 4,
    fixed_key_interior = 5,
    fixed_key_variable_record = 6,
    fixed_key_fixed_record = 7,
    chained_buffer_index = 8,
    chained_buffer_data = 9,
  };

  NodeManager(BufferManager &buffer_manager,
              std::shared_ptr<const Schema> schema, std::string table_name);
  ~NodeManager();
  NodeManager(const NodeManager &) = delete;
  NodeManager &operator=(const NodeManager &) = delete;

  [[nodiscard]] BufferManager &buffer_manager() const noexcept {
    return buffer_manager_;
  }
  [[nodiscard]] const Schema &schema() const noexcept { return *schema_; }
  [[nodiscard]] const std::shared_ptr<const Schema> &
  schema_handle() const noexcept {
    return schema_;
  }
  [[nodiscard]] const std::string &table_name() const noexcept {
    return table_name_;
  }

  [[nodiscard]] std::shared_ptr<LongKeyNode>
  get_long_key_node(std::int32_t buffer_id);
  [[nodiscard]] std::shared_ptr<FixedKeyNode>
  get_fixed_key_node(std::int32_t buffer_id);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  get_variable_key_node(std::int32_t buffer_id);
  [[nodiscard]] std::shared_ptr<FixedRecordNode>
  create_fixed_record_node(std::int32_t previous_leaf_id = -1,
                           std::int32_t next_leaf_id = -1);
  [[nodiscard]] std::shared_ptr<VariableRecordNode>
  create_variable_record_node(std::int32_t previous_leaf_id = -1,
                              std::int32_t next_leaf_id = -1);
  [[nodiscard]] std::shared_ptr<LongKeyRecordNode>
  create_long_key_record_node(std::int32_t previous_leaf_id = -1,
                              std::int32_t next_leaf_id = -1);
  [[nodiscard]] std::shared_ptr<LongKeyInteriorNode>
  create_long_key_interior(std::int64_t left_key, std::int32_t left_id,
                           std::int64_t right_key, std::int32_t right_id);
  [[nodiscard]] std::shared_ptr<LongKeyInteriorNode>
  create_empty_long_key_interior();
  [[nodiscard]] std::shared_ptr<FixedKeyFixedRecordNode>
  create_fixed_key_fixed_record_node(std::int32_t previous_leaf_id = -1,
                                     std::int32_t next_leaf_id = -1);
  [[nodiscard]] std::shared_ptr<FixedKeyVariableRecordNode>
  create_fixed_key_variable_record_node(std::int32_t previous_leaf_id = -1,
                                        std::int32_t next_leaf_id = -1);
  [[nodiscard]] std::shared_ptr<FixedKeyRecordNode>
  create_fixed_key_record_node(std::int32_t previous_leaf_id = -1,
                               std::int32_t next_leaf_id = -1);
  [[nodiscard]] std::shared_ptr<FixedKeyInteriorNode>
  create_fixed_key_interior(const Field &left_key, std::int32_t left_id,
                            const Field &right_key, std::int32_t right_id);
  [[nodiscard]] std::shared_ptr<FixedKeyInteriorNode>
  create_empty_fixed_key_interior();
  [[nodiscard]] std::shared_ptr<VariableKeyRecordNode>
  create_variable_key_record_node(std::int32_t previous_leaf_id = -1,
                                  std::int32_t next_leaf_id = -1);
  [[nodiscard]] std::shared_ptr<VariableKeyInteriorNode>
  create_variable_key_interior(const Field &left_key, std::int32_t left_id,
                               const Field &right_key, std::int32_t right_id);
  [[nodiscard]] std::shared_ptr<VariableKeyInteriorNode>
  create_empty_variable_key_interior();

  void delete_node(const std::shared_ptr<BTreeNode> &node);
  void release_read_only_node(std::int32_t buffer_id);
  [[nodiscard]] std::int64_t release_nodes();
  [[nodiscard]] std::size_t cached_node_count() const noexcept {
    return nodes_.size();
  }
  [[nodiscard]] ConsistencyNodeScope
  enter_consistency_node(std::int32_t buffer_id);

  [[nodiscard]] static NodeType node_type(const DataBuffer &buffer);
  static void set_node_type(DataBuffer &buffer, NodeType type);
  [[nodiscard]] static bool is_variable_key_node(BufferManager &manager,
                                                 std::int32_t buffer_id);

private:
  template <typename Node>
  std::shared_ptr<Node> cache_new_node(std::shared_ptr<Node> node,
                                       bool existing_leaf);
  void leave_consistency_node(std::int32_t buffer_id) noexcept;

  BufferManager &buffer_manager_;
  std::shared_ptr<const Schema> schema_;
  std::string table_name_;
  std::int64_t leaf_record_balance_ = 0;
  std::unordered_map<std::int32_t, std::shared_ptr<BTreeNode>> nodes_;
  std::unordered_set<std::int32_t> consistency_visited_;
  std::unordered_set<std::int32_t> consistency_active_;
  std::size_t consistency_depth_ = 0;
};

} // namespace llmghidra::db
