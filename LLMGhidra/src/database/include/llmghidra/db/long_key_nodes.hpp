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
class FixedRecordNode;
class VariableRecordNode;
class LongKeyInteriorNode;
class LongKeyRecordNode;

class LongKeyNode : public BTreeNode,
                    public std::enable_shared_from_this<LongKeyNode> {
public:
  static constexpr std::size_t key_count_offset = 1;
  static constexpr std::size_t header_size = 5;

  [[nodiscard]] InteriorNode *parent() const noexcept override;
  [[nodiscard]] LongKeyInteriorNode *long_key_parent() const noexcept {
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
  [[nodiscard]] virtual std::int64_t key_at(std::size_t index) const = 0;
  [[nodiscard]] virtual std::shared_ptr<LongKeyRecordNode>
  leaf_for(std::int64_t key) = 0;
  [[nodiscard]] std::shared_ptr<LongKeyNode> root();

protected:
  LongKeyNode(NodeManager &manager, std::shared_ptr<DataBuffer> buffer);
  LongKeyNode(NodeManager &manager, std::uint8_t node_type);
  void invalidate() noexcept { buffer_.reset(); }

  NodeManager &manager_;
  std::shared_ptr<DataBuffer> buffer_;
  LongKeyInteriorNode *parent_ = nullptr;
  std::size_t key_count_ = 0;

  friend class NodeManager;
  friend class LongKeyInteriorNode;
};

class LongKeyInteriorNode final : public LongKeyNode, public InteriorNode {
public:
  static constexpr std::size_t entry_base_offset = LongKeyNode::header_size;
  static constexpr std::size_t key_size = 8;
  static constexpr std::size_t id_size = 4;
  static constexpr std::size_t entry_size = key_size + id_size;

  [[nodiscard]] std::int64_t key_at(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t key_index(const Field &key) const override;
  [[nodiscard]] std::ptrdiff_t key_index(std::int64_t key) const;
  [[nodiscard]] std::size_t child_index(std::int64_t key) const;
  [[nodiscard]] std::int32_t child_id(std::size_t index) const;
  [[nodiscard]] std::shared_ptr<LongKeyRecordNode>
  leaf_for(std::int64_t key) override;
  [[nodiscard]] std::shared_ptr<LongKeyNode> insert_child(std::int32_t id,
                                                          std::int64_t key);
  [[nodiscard]] std::shared_ptr<LongKeyNode> delete_child(std::int64_t key);
  void child_key_changed(std::int64_t old_key, std::int64_t new_key);
  [[nodiscard]] bool is_leftmost_key(std::int64_t key) const;
  [[nodiscard]] bool is_rightmost_key(std::int64_t key) const;

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  LongKeyInteriorNode(NodeManager &manager,
                      std::shared_ptr<DataBuffer> existing);
  LongKeyInteriorNode(NodeManager &manager, std::int64_t left_key,
                      std::int32_t left_id, std::int64_t right_key,
                      std::int32_t right_id);
  explicit LongKeyInteriorNode(NodeManager &manager);

  void put_key(std::size_t index, std::int64_t key);
  void put_entry(std::size_t index, std::int64_t key, std::int32_t id);
  void insert_entry(std::size_t index, std::int64_t key, std::int32_t id);
  void delete_entry(std::size_t index);
  [[nodiscard]] std::shared_ptr<LongKeyNode> split_and_insert(std::int64_t key,
                                                              std::int32_t id);
  [[nodiscard]] std::shared_ptr<LongKeyNode>
  balance_child(LongKeyInteriorNode &node);
  [[nodiscard]] std::shared_ptr<LongKeyNode>
  balance_pair(LongKeyInteriorNode &left, LongKeyInteriorNode &right);
  static void move_keys_right(LongKeyInteriorNode &left,
                              LongKeyInteriorNode &right, std::size_t count);
  static void move_keys_left(LongKeyInteriorNode &left,
                             LongKeyInteriorNode &right, std::size_t count);

  std::size_t maximum_key_count_ = 0;

  friend class NodeManager;
  friend class LongKeyRecordNode;
};

class LongKeyRecordNode : public LongKeyNode, public RecordNode {
public:
  static constexpr std::size_t previous_leaf_id_offset =
      LongKeyNode::header_size;
  static constexpr std::size_t next_leaf_id_offset =
      previous_leaf_id_offset + 4;
  static constexpr std::size_t entry_base_offset = next_leaf_id_offset + 4;

  [[nodiscard]] std::ptrdiff_t key_index(const Field &key) const override;
  [[nodiscard]] std::ptrdiff_t key_index(std::int64_t key) const;
  [[nodiscard]] std::shared_ptr<LongKeyRecordNode>
  leaf_for(std::int64_t key) override;

  [[nodiscard]] virtual std::unique_ptr<Record>
  record_at(std::size_t index) const = 0;
  [[nodiscard]] std::unique_ptr<Record> record(std::int64_t key) const;
  [[nodiscard]] std::unique_ptr<Record> record_before(std::int64_t key) const;
  [[nodiscard]] std::unique_ptr<Record> record_after(std::int64_t key) const;
  [[nodiscard]] std::unique_ptr<Record>
  record_at_or_before(std::int64_t key) const;
  [[nodiscard]] std::unique_ptr<Record>
  record_at_or_after(std::int64_t key) const;

  [[nodiscard]] std::shared_ptr<LongKeyNode> put_record(Record &record);
  [[nodiscard]] std::shared_ptr<LongKeyNode> delete_record(std::int64_t key);
  [[nodiscard]] std::shared_ptr<LongKeyRecordNode> next_leaf() const;
  [[nodiscard]] std::shared_ptr<LongKeyRecordNode> previous_leaf() const;
  [[nodiscard]] std::shared_ptr<LongKeyNode> split_leaf();
  [[nodiscard]] std::shared_ptr<LongKeyNode>
  append_leaf(const std::shared_ptr<LongKeyRecordNode> &leaf);
  [[nodiscard]] virtual std::shared_ptr<LongKeyNode> remove_leaf();
  [[nodiscard]] bool leaf_links_and_keys_consistent(const TaskContext &task);

protected:
  LongKeyRecordNode(NodeManager &manager, std::shared_ptr<DataBuffer> existing);
  LongKeyRecordNode(NodeManager &manager, std::uint8_t node_type,
                    std::int32_t previous_leaf_id, std::int32_t next_leaf_id);

  [[nodiscard]] virtual std::shared_ptr<LongKeyRecordNode>
  create_leaf(std::int32_t previous_leaf_id, std::int32_t next_leaf_id) = 0;
  virtual void split_data(LongKeyRecordNode &right) = 0;
  [[nodiscard]] virtual std::shared_ptr<LongKeyNode>
  update_record(std::size_t index, Record &record) = 0;
  [[nodiscard]] virtual bool insert_record(std::size_t index,
                                           Record &record) = 0;
  virtual void remove_record(std::size_t index) = 0;

  friend class NodeManager;
};

class FixedRecordNode final : public LongKeyRecordNode {
public:
  static constexpr std::size_t key_size = 8;

  [[nodiscard]] std::int64_t key_at(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t record_offset(std::size_t index) const override;
  [[nodiscard]] std::size_t key_offset(std::size_t index) const override;

  [[nodiscard]] std::unique_ptr<Record>
  record_at(std::size_t index) const override;
  [[nodiscard]] std::shared_ptr<LongKeyNode>
  update_record(std::size_t index, Record &record) override;
  [[nodiscard]] bool insert_record(std::size_t index, Record &record) override;
  void remove_record(std::size_t index) override;

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  FixedRecordNode(NodeManager &manager, std::shared_ptr<DataBuffer> existing,
                  std::size_t record_length);
  FixedRecordNode(NodeManager &manager, std::size_t record_length,
                  std::int32_t previous_leaf_id, std::int32_t next_leaf_id);
  void shift_records(std::size_t index, bool right);
  void split_data(LongKeyRecordNode &right) override;
  [[nodiscard]] std::shared_ptr<LongKeyRecordNode>
  create_leaf(std::int32_t previous_leaf_id,
              std::int32_t next_leaf_id) override;

  std::size_t record_length_ = 0;
  std::size_t entry_size_ = 0;

  friend class NodeManager;
};

class VariableRecordNode final : public LongKeyRecordNode {
public:
  static constexpr std::size_t key_size = 8;
  static constexpr std::size_t record_offset_size = 4;
  static constexpr std::size_t indirect_flag_size = 1;
  static constexpr std::size_t entry_size =
      key_size + record_offset_size + indirect_flag_size;
  static constexpr std::size_t record_offset_base =
      entry_base_offset + key_size;
  static constexpr std::size_t indirect_flag_base =
      record_offset_base + record_offset_size;

  [[nodiscard]] std::int64_t key_at(std::size_t index) const override;
  [[nodiscard]] std::ptrdiff_t record_offset(std::size_t index) const override;
  [[nodiscard]] std::size_t key_offset(std::size_t index) const override;
  [[nodiscard]] std::unique_ptr<Record>
  record_at(std::size_t index) const override;
  [[nodiscard]] std::shared_ptr<LongKeyNode>
  update_record(std::size_t index, Record &record) override;
  [[nodiscard]] bool insert_record(std::size_t index, Record &record) override;
  void remove_record(std::size_t index) override;
  [[nodiscard]] std::shared_ptr<LongKeyNode> remove_leaf() override;

  void delete_tree() override;
  [[nodiscard]] std::vector<std::int32_t> buffer_references() const override;
  [[nodiscard]] bool consistent(const TaskContext &task = {}) override;

private:
  VariableRecordNode(NodeManager &manager,
                     std::shared_ptr<DataBuffer> existing);
  VariableRecordNode(NodeManager &manager, std::int32_t previous_leaf_id,
                     std::int32_t next_leaf_id);

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
  void split_data(LongKeyRecordNode &right) override;
  [[nodiscard]] std::shared_ptr<LongKeyRecordNode>
  create_leaf(std::int32_t previous_leaf_id,
              std::int32_t next_leaf_id) override;
  void remove_indirect(std::int32_t buffer_id);
  void remove_all_indirect();
  [[nodiscard]] std::size_t maximum_inline_record_length() const;

  friend class NodeManager;
};

} // namespace llmghidra::db
