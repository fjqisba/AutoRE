/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/btree_node.hpp"
#include "llmghidra/db/record.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace llmghidra::db {

class NodeManager;
class VariableKeyBufferLease;
class VariableKeyInteriorNode;
class VariableKeyRecordNode;

class VariableKeyNode : public BTreeNode,
                        public std::enable_shared_from_this<VariableKeyNode> {
public:
  static constexpr std::size_t key_type_offset = 1;
  static constexpr std::size_t key_count_offset = 2;
  static constexpr std::size_t header_size = 6;

  ~VariableKeyNode() override;

  [[nodiscard]] InteriorNode *parent() const noexcept override;
  [[nodiscard]] VariableKeyInteriorNode *variable_key_parent() const noexcept {
    return parent_;
  }
  [[nodiscard]] std::int32_t buffer_id() const noexcept override {
    return buffer_ ? buffer_->id() : -1;
  }
  [[nodiscard]] const std::shared_ptr<DataBuffer> &
  buffer_handle() const noexcept override {
    return buffer_;
  }
  [[nodiscard]] std::size_t key_count() const noexcept override {
    return key_count_;
  }
  void set_key_count(std::size_t count) override;
  [[nodiscard]] std::unique_ptr<Field>
  key_field(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t key_index(const Field &key) const override;
  [[nodiscard]] virtual std::size_t key_offset(std::size_t index) const = 0;
  [[nodiscard]] virtual std::shared_ptr<VariableKeyRecordNode>
  leaf_for(const Field &key) = 0;
  [[nodiscard]] std::shared_ptr<VariableKeyNode> root();
  [[nodiscard]] std::size_t maximum_key_length() const noexcept {
    return maximum_key_length_;
  }

protected:
  VariableKeyNode(NodeManager &manager, std::shared_ptr<DataBuffer> buffer);
  VariableKeyNode(NodeManager &manager, std::uint8_t node_type);
  void invalidate() noexcept { buffer_.reset(); }
  void require_key_type(const Field &key) const;
  [[nodiscard]] static std::size_t
  calculate_maximum_key_length(std::size_t buffer_size) noexcept;
  void commit_new_buffer() noexcept;

  NodeManager &manager_;
  std::unique_ptr<VariableKeyBufferLease> new_buffer_lease_;
  std::shared_ptr<DataBuffer> buffer_;
  VariableKeyInteriorNode *parent_ = nullptr;
  std::unique_ptr<Field> key_type_;
  std::size_t key_count_ = 0;
  std::size_t maximum_key_length_ = 0;

  friend class NodeManager;
  friend class VariableKeyInteriorNode;
};

class VariableKeyInteriorNode final : public VariableKeyNode,
                                      public InteriorNode {
public:
  static constexpr std::size_t entry_base_offset = VariableKeyNode::header_size;
  static constexpr std::size_t key_offset_size = 4;
  static constexpr std::size_t id_size = 4;
  static constexpr std::size_t entry_size = key_offset_size + id_size;
  static constexpr std::size_t minimum_key_capacity = 8;

  [[nodiscard]] std::size_t key_offset(std::size_t index) const override;
  [[nodiscard]] std::size_t child_index(const Field &key) const;
  [[nodiscard]] std::int32_t child_id(std::size_t index) const;
  [[nodiscard]] std::shared_ptr<VariableKeyRecordNode>
  leaf_for(const Field &key) override;
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  insert_child(const std::shared_ptr<VariableKeyNode> &node);
  [[nodiscard]] std::shared_ptr<VariableKeyNode> delete_child(const Field &key);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  child_key_changed(const Field &old_key, const Field &new_key,
                    const std::shared_ptr<VariableKeyNode> &child);
  [[nodiscard]] bool is_leftmost_key(const Field &key) const;
  [[nodiscard]] bool is_rightmost_key(const Field &key) const;

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  struct Entry {
    std::unique_ptr<Field> key;
    std::int32_t child_id = -1;
  };

  VariableKeyInteriorNode(NodeManager &manager,
                          std::shared_ptr<DataBuffer> existing);
  VariableKeyInteriorNode(NodeManager &manager, const Field &left_key,
                          std::int32_t left_id, const Field &right_key,
                          std::int32_t right_id);
  explicit VariableKeyInteriorNode(NodeManager &manager);

  [[nodiscard]] std::size_t free_space() const;
  [[nodiscard]] std::size_t key_length(std::size_t index) const;
  void put_key_offset(std::size_t index, std::size_t offset);
  [[nodiscard]] std::size_t move_keys(std::size_t index, std::ptrdiff_t shift);
  void insert_entry(std::size_t index, const Field &key, std::int32_t child_id);
  void update_key(std::size_t index, const Field &key);
  void delete_entry(std::size_t index);
  [[nodiscard]] std::vector<Entry> entries() const;
  void rebuild(const std::vector<Entry> &entries);
  [[nodiscard]] std::size_t offset_index(std::size_t offset) const;
  [[nodiscard]] static std::size_t
  storage_size(const std::vector<Entry> &entries);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  split_for_insert(const std::shared_ptr<VariableKeyNode> &node);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  split_for_key_change(std::size_t old_index, const Field &old_key,
                       const Field &new_key,
                       const std::shared_ptr<VariableKeyNode> &child);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  balance_child(VariableKeyInteriorNode &node);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  balance_pair(VariableKeyInteriorNode &left, VariableKeyInteriorNode &right);

  friend class NodeManager;
  friend class VariableKeyRecordNode;
};

class VariableKeyRecordNode final : public VariableKeyNode, public RecordNode {
public:
  static constexpr std::size_t previous_leaf_id_offset =
      VariableKeyNode::header_size;
  static constexpr std::size_t next_leaf_id_offset =
      previous_leaf_id_offset + 4;
  static constexpr std::size_t entry_base_offset = next_leaf_id_offset + 4;
  static constexpr std::size_t stored_offset_size = 4;
  static constexpr std::size_t indirect_flag_size = 1;
  static constexpr std::size_t entry_size =
      stored_offset_size + indirect_flag_size;

  [[nodiscard]] std::size_t key_offset(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t record_offset(std::size_t index) const override;
  [[nodiscard]] std::shared_ptr<VariableKeyRecordNode>
  leaf_for(const Field &key) override;
  [[nodiscard]] std::unique_ptr<Record> record_at(std::size_t index) const;
  [[nodiscard]] std::unique_ptr<Record> record(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record> record_before(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record> record_after(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record>
  record_at_or_before(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record>
  record_at_or_after(const Field &key) const;

  [[nodiscard]] std::shared_ptr<VariableKeyNode> put_record(Record &record);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  delete_record(const Field &key);
  [[nodiscard]] std::shared_ptr<VariableKeyRecordNode> next_leaf() const;
  [[nodiscard]] std::shared_ptr<VariableKeyRecordNode> previous_leaf() const;
  [[nodiscard]] std::shared_ptr<VariableKeyNode> split_leaf();
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  append_leaf(const std::shared_ptr<VariableKeyRecordNode> &leaf);
  [[nodiscard]] std::shared_ptr<VariableKeyNode> remove_leaf();

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  VariableKeyRecordNode(NodeManager &manager,
                        std::shared_ptr<DataBuffer> existing);
  VariableKeyRecordNode(NodeManager &manager, std::int32_t previous_leaf_id,
                        std::int32_t next_leaf_id);

  [[nodiscard]] std::size_t record_data_offset(std::size_t index) const;
  void put_key_offset(std::size_t index, std::size_t offset);
  [[nodiscard]] bool indirect(std::size_t index) const;
  void set_indirect(std::size_t index, bool state);
  [[nodiscard]] std::size_t free_space() const;
  [[nodiscard]] std::size_t full_record_length(std::size_t index) const;
  [[nodiscard]] std::size_t move_records(std::size_t index,
                                         std::ptrdiff_t shift);
  [[nodiscard]] std::size_t split_index() const;
  void split_data(VariableKeyRecordNode &right);
  [[nodiscard]] std::shared_ptr<VariableKeyRecordNode>
  create_leaf(std::int32_t previous_leaf_id, std::int32_t next_leaf_id);
  [[nodiscard]] std::shared_ptr<VariableKeyNode>
  update_record(std::size_t index, Record &record);
  [[nodiscard]] bool insert_record(std::size_t index, Record &record);
  void remove_record(std::size_t index);
  void remove_indirect(std::int32_t buffer_id);
  void remove_all_indirect();
  [[nodiscard]] std::size_t
  maximum_inline_record_length(std::size_t key_length) const;

  friend class NodeManager;
};

} // namespace llmghidra::db
