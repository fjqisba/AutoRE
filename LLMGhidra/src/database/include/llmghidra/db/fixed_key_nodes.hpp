/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/btree_node.hpp"
#include "llmghidra/db/record.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace llmghidra::db {

class FixedKeyInteriorNode;
class FixedKeyRecordNode;
class FixedKeyFixedRecordNode;
class FixedKeyVariableRecordNode;
class NodeManager;

class FixedKeyNode : public BTreeNode,
                     public std::enable_shared_from_this<FixedKeyNode> {
public:
  static constexpr std::size_t key_count_offset = 1;
  static constexpr std::size_t header_size = 5;

  [[nodiscard]] InteriorNode *parent() const noexcept override;
  [[nodiscard]] FixedKeyInteriorNode *fixed_key_parent() const noexcept {
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
  [[nodiscard]] virtual std::size_t key_offset(std::size_t index) const = 0;
  [[nodiscard]] virtual std::shared_ptr<FixedKeyRecordNode>
  leaf_for(const Field &key) = 0;
  [[nodiscard]] std::shared_ptr<FixedKeyNode> root();

protected:
  FixedKeyNode(NodeManager &manager, std::shared_ptr<DataBuffer> buffer);
  FixedKeyNode(NodeManager &manager, std::uint8_t node_type);
  void invalidate() noexcept { buffer_.reset(); }
  void require_key_type(const Field &key) const;

  NodeManager &manager_;
  std::shared_ptr<DataBuffer> buffer_;
  FixedKeyInteriorNode *parent_ = nullptr;
  std::size_t key_count_ = 0;
  std::size_t key_size_ = 0;

  friend class NodeManager;
  friend class FixedKeyInteriorNode;
};

class FixedKeyInteriorNode final : public FixedKeyNode, public InteriorNode {
public:
  static constexpr std::size_t entry_base_offset = FixedKeyNode::header_size;
  static constexpr std::size_t id_size = 4;

  [[nodiscard]] std::size_t key_offset(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t key_index(const Field &key) const override;
  [[nodiscard]] std::size_t child_index(const Field &key) const;
  [[nodiscard]] std::int32_t child_id(std::size_t index) const;
  [[nodiscard]] std::shared_ptr<FixedKeyRecordNode>
  leaf_for(const Field &key) override;
  [[nodiscard]] std::shared_ptr<FixedKeyNode> insert_child(std::int32_t id,
                                                           const Field &key);
  [[nodiscard]] std::shared_ptr<FixedKeyNode> delete_child(const Field &key);
  void child_key_changed(const Field &old_key, const Field &new_key);
  [[nodiscard]] bool is_leftmost_key(const Field &key) const;
  [[nodiscard]] bool is_rightmost_key(const Field &key) const;

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  FixedKeyInteriorNode(NodeManager &manager,
                       std::shared_ptr<DataBuffer> existing);
  FixedKeyInteriorNode(NodeManager &manager, const Field &left_key,
                       std::int32_t left_id, const Field &right_key,
                       std::int32_t right_id);
  explicit FixedKeyInteriorNode(NodeManager &manager);

  [[nodiscard]] std::size_t entry_size() const noexcept {
    return key_size_ + id_size;
  }
  void put_key(std::size_t index, const Field &key);
  void put_entry(std::size_t index, const Field &key, std::int32_t id);
  void insert_entry(std::size_t index, const Field &key, std::int32_t id);
  void delete_entry(std::size_t index);
  [[nodiscard]] std::shared_ptr<FixedKeyNode> split_and_insert(const Field &key,
                                                               std::int32_t id);
  [[nodiscard]] std::shared_ptr<FixedKeyNode>
  balance_child(FixedKeyInteriorNode &node);
  [[nodiscard]] std::shared_ptr<FixedKeyNode>
  balance_pair(FixedKeyInteriorNode &left, FixedKeyInteriorNode &right);
  static void move_keys_right(FixedKeyInteriorNode &left,
                              FixedKeyInteriorNode &right, std::size_t count);
  static void move_keys_left(FixedKeyInteriorNode &left,
                             FixedKeyInteriorNode &right, std::size_t count);

  std::size_t maximum_key_count_ = 0;

  friend class NodeManager;
  friend class FixedKeyRecordNode;
};

class FixedKeyRecordNode : public FixedKeyNode, public RecordNode {
public:
  static constexpr std::size_t previous_leaf_id_offset =
      FixedKeyNode::header_size;
  static constexpr std::size_t next_leaf_id_offset =
      previous_leaf_id_offset + 4;
  static constexpr std::size_t entry_base_offset = next_leaf_id_offset + 4;

  [[nodiscard]] virtual std::size_t
  key_offset(std::size_t index) const override = 0;
  [[nodiscard]] std::ptrdiff_t key_index(const Field &key) const override;
  [[nodiscard]] std::shared_ptr<FixedKeyRecordNode>
  leaf_for(const Field &key) override;

  [[nodiscard]] virtual std::unique_ptr<Record>
  record_at(std::size_t index) const = 0;
  [[nodiscard]] std::unique_ptr<Record> record(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record> record_before(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record> record_after(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record>
  record_at_or_before(const Field &key) const;
  [[nodiscard]] std::unique_ptr<Record>
  record_at_or_after(const Field &key) const;

  [[nodiscard]] std::shared_ptr<FixedKeyNode> put_record(Record &record);
  [[nodiscard]] std::shared_ptr<FixedKeyNode> delete_record(const Field &key);
  [[nodiscard]] std::shared_ptr<FixedKeyRecordNode> next_leaf() const;
  [[nodiscard]] std::shared_ptr<FixedKeyRecordNode> previous_leaf() const;
  [[nodiscard]] std::shared_ptr<FixedKeyNode> split_leaf();
  [[nodiscard]] std::shared_ptr<FixedKeyNode>
  append_leaf(const std::shared_ptr<FixedKeyRecordNode> &leaf);
  [[nodiscard]] virtual std::shared_ptr<FixedKeyNode> remove_leaf();
  [[nodiscard]] bool leaf_links_and_keys_consistent(const TaskContext &task);

protected:
  FixedKeyRecordNode(NodeManager &manager,
                     std::shared_ptr<DataBuffer> existing);
  FixedKeyRecordNode(NodeManager &manager, std::uint8_t node_type,
                     std::int32_t previous_leaf_id, std::int32_t next_leaf_id);

  [[nodiscard]] virtual std::shared_ptr<FixedKeyRecordNode>
  create_leaf(std::int32_t previous_leaf_id, std::int32_t next_leaf_id) = 0;
  virtual void split_data(FixedKeyRecordNode &right) = 0;
  [[nodiscard]] virtual std::shared_ptr<FixedKeyNode>
  update_record(std::size_t index, Record &record) = 0;
  [[nodiscard]] virtual bool insert_record(std::size_t index,
                                           Record &record) = 0;
  virtual void remove_record(std::size_t index) = 0;

  friend class NodeManager;
};

class FixedKeyFixedRecordNode final : public FixedKeyRecordNode {
public:
  [[nodiscard]] std::size_t key_offset(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t record_offset(std::size_t index) const override;
  [[nodiscard]] std::unique_ptr<Record>
  record_at(std::size_t index) const override;
  [[nodiscard]] std::shared_ptr<FixedKeyNode>
  update_record(std::size_t index, Record &record) override;
  [[nodiscard]] bool insert_record(std::size_t index, Record &record) override;
  void remove_record(std::size_t index) override;

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  FixedKeyFixedRecordNode(NodeManager &manager,
                          std::shared_ptr<DataBuffer> existing,
                          std::size_t record_length);
  FixedKeyFixedRecordNode(NodeManager &manager, std::size_t record_length,
                          std::int32_t previous_leaf_id,
                          std::int32_t next_leaf_id);
  [[nodiscard]] std::size_t entry_size() const noexcept {
    return key_size_ + record_length_;
  }
  void shift_records(std::size_t index, bool right);
  void split_data(FixedKeyRecordNode &right) override;
  [[nodiscard]] std::shared_ptr<FixedKeyRecordNode>
  create_leaf(std::int32_t previous_leaf_id,
              std::int32_t next_leaf_id) override;

  std::size_t record_length_ = 0;

  friend class NodeManager;
};

class FixedKeyVariableRecordNode final : public FixedKeyRecordNode {
public:
  static constexpr std::size_t record_offset_size = 4;
  static constexpr std::size_t indirect_flag_size = 1;

  [[nodiscard]] std::size_t key_offset(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t record_offset(std::size_t index) const override;
  [[nodiscard]] std::unique_ptr<Record>
  record_at(std::size_t index) const override;
  [[nodiscard]] std::shared_ptr<FixedKeyNode>
  update_record(std::size_t index, Record &record) override;
  [[nodiscard]] bool insert_record(std::size_t index, Record &record) override;
  void remove_record(std::size_t index) override;
  [[nodiscard]] std::shared_ptr<FixedKeyNode> remove_leaf() override;

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  FixedKeyVariableRecordNode(NodeManager &manager,
                             std::shared_ptr<DataBuffer> existing);
  FixedKeyVariableRecordNode(NodeManager &manager,
                             std::int32_t previous_leaf_id,
                             std::int32_t next_leaf_id);

  [[nodiscard]] std::size_t entry_size() const noexcept {
    return key_size_ + record_offset_size + indirect_flag_size;
  }
  [[nodiscard]] std::size_t record_offset_base() const noexcept {
    return entry_base_offset + key_size_;
  }
  [[nodiscard]] std::size_t indirect_flag_base() const noexcept {
    return record_offset_base() + record_offset_size;
  }
  [[nodiscard]] std::size_t data_offset(std::size_t index) const;
  void put_data_offset(std::size_t index, std::size_t offset);
  [[nodiscard]] bool indirect(std::size_t index) const;
  void set_indirect(std::size_t index, bool state);
  [[nodiscard]] std::size_t free_space() const;
  [[nodiscard]] std::size_t stored_length(std::size_t index) const;
  [[nodiscard]] std::size_t stored_length(std::size_t index,
                                          std::size_t offset) const;
  [[nodiscard]] std::size_t move_records(std::size_t index,
                                         std::ptrdiff_t shift);
  [[nodiscard]] std::size_t split_index() const;
  void split_data(FixedKeyRecordNode &right) override;
  [[nodiscard]] std::shared_ptr<FixedKeyRecordNode>
  create_leaf(std::int32_t previous_leaf_id,
              std::int32_t next_leaf_id) override;
  void remove_indirect(std::int32_t buffer_id);
  void remove_all_indirect();
  [[nodiscard]] std::size_t maximum_inline_record_length() const;

  friend class NodeManager;
};

} // namespace llmghidra::db
