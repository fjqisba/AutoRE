/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/table.hpp"

#include "llmghidra/db/chained_buffer.hpp"
#include "llmghidra/db/fixed_key_nodes.hpp"
#include "llmghidra/db/index_table.hpp"
#include "llmghidra/db/long_key_nodes.hpp"
#include "llmghidra/db/variable_key_nodes.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace llmghidra::db {

class Table::NodeSession final {
public:
  explicit NodeSession(NodeManager &nodes) : nodes_(nodes) {}
  NodeSession(const NodeSession &) = delete;
  NodeSession &operator=(const NodeSession &) = delete;
  ~NodeSession() {
    if (!active_)
      return;
    try {
      (void)nodes_.release_nodes();
    } catch (...) {
    }
  }
  std::int64_t finish() {
    if (!active_)
      return 0;
    active_ = false;
    return nodes_.release_nodes();
  }

private:
  NodeManager &nodes_;
  bool active_ = true;
};

Table::Table(BufferManager &buffers, std::shared_ptr<TableRecord> metadata,
             std::function<void()> mutation_guard,
             std::shared_ptr<std::recursive_mutex> database_monitor)
    : buffers_(buffers), metadata_(std::move(metadata)),
      schema_(metadata_ ? metadata_->table_schema_handle() : nullptr),
      nodes_(buffers_, schema_, metadata_ ? metadata_->name() : std::string{}),
      mutex_(database_monitor ? std::move(database_monitor)
                              : std::make_shared<std::recursive_mutex>()),
      mutation_guard_(std::move(mutation_guard)) {
  if (!metadata_ || !schema_) {
    throw std::invalid_argument("Table requires metadata and schema");
  }
  // Match db.Table construction: loading persisted metadata is not a table
  // mutation.  Only a later master-table undo/redo notification advances the
  // modification generation via metadata_changed().
  root_buffer_id_ = metadata_->root_buffer_id();
  record_count_ = metadata_->record_count();
  maximum_key_ = metadata_->maximum_key();
}

void Table::check_mutation() const {
  check_valid();
  if (mutation_guard_)
    mutation_guard_();
}

void Table::check_valid() const {
  std::scoped_lock lock(*mutex_);
  if (!valid_ || !metadata_ || !metadata_->valid()) {
    throw std::logic_error("Table is invalid");
  }
}

bool Table::valid() const noexcept {
  std::scoped_lock lock(*mutex_);
  return valid_ && metadata_ && metadata_->valid();
}

std::string Table::name() const {
  std::scoped_lock lock(*mutex_);
  check_valid();
  return metadata_->name();
}

std::int64_t Table::table_number() const {
  std::scoped_lock lock(*mutex_);
  check_valid();
  return metadata_->table_number();
}

std::int32_t Table::root_buffer_id() const {
  std::scoped_lock lock(*mutex_);
  check_valid();
  return root_buffer_id_;
}

std::int32_t Table::record_count() const {
  std::scoped_lock lock(*mutex_);
  check_valid();
  return record_count_;
}

std::int64_t Table::maximum_key() const {
  std::scoped_lock lock(*mutex_);
  check_valid();
  return maximum_key_;
}

std::int64_t Table::next_long_key() const {
  std::scoped_lock lock(*mutex_);
  check_valid();
  require_long_key_schema();
  if (maximum_key_ == TableRecord::initial_maximum_key)
    return 0;
  if (maximum_key_ == std::numeric_limits<std::int64_t>::max()) {
    throw std::overflow_error("Table long-key space exhausted");
  }
  return maximum_key_ + 1;
}

std::uint64_t Table::modification_count() const noexcept {
  std::scoped_lock lock(*mutex_);
  return modification_count_;
}

void Table::require_long_key_schema() const {
  check_valid();
  if (!schema_->use_long_key_nodes()) {
    throw std::invalid_argument("operation requires a long-key table");
  }
}

void Table::require_field_key(const Field &key) const {
  check_valid();
  if (schema_->use_long_key_nodes()) {
    if (!key.same_type(schema_->key_type()) || key.is_null()) {
      throw std::invalid_argument("long Table key type differs or is null");
    }
    return;
  }
  if (!key.same_type(schema_->key_type()) || key.is_null()) {
    throw std::invalid_argument("Table key type differs or is null");
  }
}

std::shared_ptr<LongKeyNode> Table::open_long_root() {
  require_long_key_schema();
  if (root_buffer_id_ < 0)
    return nullptr;
  return nodes_.get_long_key_node(root_buffer_id_);
}

std::shared_ptr<FixedKeyNode> Table::open_fixed_root() {
  if (!schema_->use_fixed_key_nodes()) {
    throw std::invalid_argument("operation requires a fixed-key table");
  }
  if (root_buffer_id_ < 0)
    return nullptr;
  return nodes_.get_fixed_key_node(root_buffer_id_);
}

std::shared_ptr<VariableKeyNode> Table::open_variable_root() {
  if (!schema_->use_variable_key_nodes()) {
    throw std::invalid_argument("operation requires a variable-key table");
  }
  if (root_buffer_id_ < 0)
    return nullptr;
  return nodes_.get_variable_key_node(root_buffer_id_);
}

std::shared_ptr<BTreeNode> Table::open_root() {
  if (schema_->use_long_key_nodes())
    return open_long_root();
  if (schema_->use_fixed_key_nodes())
    return open_fixed_root();
  return open_variable_root();
}

void Table::update_root(const std::shared_ptr<BTreeNode> &root) {
  const auto id = root ? root->buffer_id() : -1;
  if (id == root_buffer_id_)
    return;
  root_buffer_id_ = id;
  metadata_->set_root_buffer_id(id);
}

void Table::apply_record_delta(std::int64_t delta) {
  if (delta == 0)
    return;
  const auto value = static_cast<std::int64_t>(record_count_) + delta;
  if (value < 0 || value > std::numeric_limits<std::int32_t>::max()) {
    throw std::overflow_error("Table record count is out of range");
  }
  record_count_ = static_cast<std::int32_t>(value);
  metadata_->set_record_count(record_count_);
}

bool Table::has_record(std::int64_t key) { return record(key) != nullptr; }

bool Table::has_record(const Field &key) { return record(key) != nullptr; }

std::unique_ptr<Record> Table::record(std::int64_t key) {
  std::scoped_lock lock(*mutex_);
  require_long_key_schema();
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result = open_long_root()->leaf_for(key)->record(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record(const Field &key) {
  std::scoped_lock lock(*mutex_);
  require_field_key(key);
  if (schema_->use_long_key_nodes())
    return record(key.as_integer());
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  std::unique_ptr<Record> result;
  if (schema_->use_fixed_key_nodes()) {
    result = open_fixed_root()->leaf_for(key)->record(key);
  } else {
    result = open_variable_root()->leaf_for(key)->record(key);
  }
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_before(std::int64_t key) {
  std::scoped_lock lock(*mutex_);
  require_long_key_schema();
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result = open_long_root()->leaf_for(key)->record_before(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_before(const Field &key) {
  std::scoped_lock lock(*mutex_);
  require_field_key(key);
  if (schema_->use_long_key_nodes())
    return record_before(key.as_integer());
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result = schema_->use_fixed_key_nodes()
                    ? open_fixed_root()->leaf_for(key)->record_before(key)
                    : open_variable_root()->leaf_for(key)->record_before(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_after(std::int64_t key) {
  std::scoped_lock lock(*mutex_);
  require_long_key_schema();
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result = open_long_root()->leaf_for(key)->record_after(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_after(const Field &key) {
  std::scoped_lock lock(*mutex_);
  require_field_key(key);
  if (schema_->use_long_key_nodes())
    return record_after(key.as_integer());
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result = schema_->use_fixed_key_nodes()
                    ? open_fixed_root()->leaf_for(key)->record_after(key)
                    : open_variable_root()->leaf_for(key)->record_after(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_at_or_before(std::int64_t key) {
  std::scoped_lock lock(*mutex_);
  require_long_key_schema();
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result = open_long_root()->leaf_for(key)->record_at_or_before(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_at_or_before(const Field &key) {
  std::scoped_lock lock(*mutex_);
  require_field_key(key);
  if (schema_->use_long_key_nodes()) {
    return record_at_or_before(key.as_integer());
  }
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result =
      schema_->use_fixed_key_nodes()
          ? open_fixed_root()->leaf_for(key)->record_at_or_before(key)
          : open_variable_root()->leaf_for(key)->record_at_or_before(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_at_or_after(std::int64_t key) {
  std::scoped_lock lock(*mutex_);
  require_long_key_schema();
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result = open_long_root()->leaf_for(key)->record_at_or_after(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::record_at_or_after(const Field &key) {
  std::scoped_lock lock(*mutex_);
  require_field_key(key);
  if (schema_->use_long_key_nodes()) {
    return record_at_or_after(key.as_integer());
  }
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  auto result =
      schema_->use_fixed_key_nodes()
          ? open_fixed_root()->leaf_for(key)->record_at_or_after(key)
          : open_variable_root()->leaf_for(key)->record_at_or_after(key);
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::first_record() {
  std::scoped_lock lock(*mutex_);
  check_valid();
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  std::unique_ptr<Record> result;
  if (schema_->use_long_key_nodes()) {
    std::shared_ptr<LongKeyNode> node = open_long_root();
    while (auto interior =
               std::dynamic_pointer_cast<LongKeyInteriorNode>(node)) {
      node = nodes_.get_long_key_node(interior->child_id(0));
    }
    auto leaf = std::dynamic_pointer_cast<LongKeyRecordNode>(node);
    if (!leaf)
      throw std::runtime_error("long-key tree has no record leaf");
    if (leaf->key_count() != 0)
      result = leaf->record_at(0);
  } else if (schema_->use_fixed_key_nodes()) {
    std::shared_ptr<FixedKeyNode> node = open_fixed_root();
    while (auto interior =
               std::dynamic_pointer_cast<FixedKeyInteriorNode>(node)) {
      node = nodes_.get_fixed_key_node(interior->child_id(0));
    }
    auto leaf = std::dynamic_pointer_cast<FixedKeyRecordNode>(node);
    if (!leaf)
      throw std::runtime_error("fixed-key tree has no record leaf");
    if (leaf->key_count() != 0)
      result = leaf->record_at(0);
  } else {
    std::shared_ptr<VariableKeyNode> node = open_variable_root();
    while (auto interior =
               std::dynamic_pointer_cast<VariableKeyInteriorNode>(node)) {
      node = nodes_.get_variable_key_node(interior->child_id(0));
    }
    auto leaf = std::dynamic_pointer_cast<VariableKeyRecordNode>(node);
    if (!leaf) {
      throw std::runtime_error("variable-key tree has no record leaf");
    }
    if (leaf->key_count() != 0)
      result = leaf->record_at(0);
  }
  (void)session.finish();
  return result;
}

std::unique_ptr<Record> Table::last_record() {
  std::scoped_lock lock(*mutex_);
  check_valid();
  if (root_buffer_id_ < 0)
    return nullptr;
  NodeSession session(nodes_);
  std::unique_ptr<Record> result;
  if (schema_->use_long_key_nodes()) {
    std::shared_ptr<LongKeyNode> node = open_long_root();
    while (auto interior =
               std::dynamic_pointer_cast<LongKeyInteriorNode>(node)) {
      node = nodes_.get_long_key_node(
          interior->child_id(interior->key_count() - 1));
    }
    auto leaf = std::dynamic_pointer_cast<LongKeyRecordNode>(node);
    if (!leaf)
      throw std::runtime_error("long-key tree has no record leaf");
    if (leaf->key_count() != 0) {
      result = leaf->record_at(leaf->key_count() - 1);
    }
  } else if (schema_->use_fixed_key_nodes()) {
    std::shared_ptr<FixedKeyNode> node = open_fixed_root();
    while (auto interior =
               std::dynamic_pointer_cast<FixedKeyInteriorNode>(node)) {
      node = nodes_.get_fixed_key_node(
          interior->child_id(interior->key_count() - 1));
    }
    auto leaf = std::dynamic_pointer_cast<FixedKeyRecordNode>(node);
    if (!leaf)
      throw std::runtime_error("fixed-key tree has no record leaf");
    if (leaf->key_count() != 0) {
      result = leaf->record_at(leaf->key_count() - 1);
    }
  } else {
    std::shared_ptr<VariableKeyNode> node = open_variable_root();
    while (auto interior =
               std::dynamic_pointer_cast<VariableKeyInteriorNode>(node)) {
      node = nodes_.get_variable_key_node(
          interior->child_id(interior->key_count() - 1));
    }
    auto leaf = std::dynamic_pointer_cast<VariableKeyRecordNode>(node);
    if (!leaf) {
      throw std::runtime_error("variable-key tree has no record leaf");
    }
    if (leaf->key_count() != 0) {
      result = leaf->record_at(leaf->key_count() - 1);
    }
  }
  (void)session.finish();
  return result;
}

void Table::put_record(Record &record_value) {
  std::scoped_lock lock(*mutex_);
  check_mutation();
  if (!record_value.has_same_schema(*schema_)) {
    throw std::invalid_argument("record schema differs from Table");
  }
  auto old_record = record(record_value.key());
  NodeSession session(nodes_);
  std::shared_ptr<BTreeNode> provisional_root;
  if (!old_record && root_buffer_id_ < 0) {
    // Ghidra allocates the first primary leaf before invoking the secondary
    // index insertion callbacks.  Preserve that observable buffer allocation
    // order while keeping the index update rollback below transactional.
    if (schema_->use_long_key_nodes()) {
      provisional_root = nodes_.create_long_key_record_node();
    } else if (schema_->use_fixed_key_nodes()) {
      provisional_root = nodes_.create_fixed_key_record_node();
    } else {
      provisional_root = nodes_.create_variable_key_record_node();
    }
  }
  auto indexes = live_indexes();
  std::size_t synchronized_indexes = 0;
  try {
    for (; synchronized_indexes < indexes.size(); ++synchronized_indexes) {
      if (old_record) {
        indexes[synchronized_indexes]->update_entry(*old_record, record_value);
      } else {
        indexes[synchronized_indexes]->add_entry(record_value);
      }
    }
  } catch (...) {
    while (synchronized_indexes != 0) {
      auto &index = indexes[--synchronized_indexes];
      if (old_record)
        index->update_entry(record_value, *old_record);
      else
        index->delete_entry(record_value);
    }
    if (provisional_root)
      provisional_root->delete_tree();
    apply_record_delta(session.finish());
    throw;
  }
  try {
    std::shared_ptr<BTreeNode> root;
    if (schema_->use_long_key_nodes()) {
      auto long_root =
          provisional_root
              ? std::dynamic_pointer_cast<LongKeyNode>(provisional_root)
              : open_long_root();
      if (!long_root)
        long_root = nodes_.create_long_key_record_node();
      const auto key = record_value.key().as_integer();
      root = long_root->leaf_for(key)->put_record(record_value);
      if (maximum_key_ < key) {
        maximum_key_ = key;
        metadata_->set_maximum_key(key);
      }
    } else if (schema_->use_fixed_key_nodes()) {
      auto fixed_root =
          provisional_root
              ? std::dynamic_pointer_cast<FixedKeyNode>(provisional_root)
              : open_fixed_root();
      if (!fixed_root)
        fixed_root = nodes_.create_fixed_key_record_node();
      root = fixed_root->leaf_for(record_value.key())->put_record(record_value);
    } else {
      auto variable_root =
          provisional_root
              ? std::dynamic_pointer_cast<VariableKeyNode>(provisional_root)
              : open_variable_root();
      if (!variable_root) {
        variable_root = nodes_.create_variable_key_record_node();
      }
      root =
          variable_root->leaf_for(record_value.key())->put_record(record_value);
    }
    update_root(root);
    ++modification_count_;
  } catch (...) {
    if (provisional_root && root_buffer_id_ < 0)
      provisional_root->delete_tree();
    apply_record_delta(session.finish());
    while (synchronized_indexes != 0) {
      auto &index = indexes[--synchronized_indexes];
      if (old_record)
        index->update_entry(record_value, *old_record);
      else
        index->delete_entry(record_value);
    }
    throw;
  }
  apply_record_delta(session.finish());
}

bool Table::delete_record(std::int64_t key) {
  std::scoped_lock lock(*mutex_);
  check_mutation();
  require_long_key_schema();
  if (root_buffer_id_ < 0)
    return false;
  auto old_record = record(key);
  auto indexes = live_indexes();
  std::size_t synchronized_indexes = 0;
  if (old_record) {
    try {
      for (; synchronized_indexes < indexes.size(); ++synchronized_indexes) {
        indexes[synchronized_indexes]->delete_entry(*old_record);
      }
    } catch (...) {
      while (synchronized_indexes != 0) {
        indexes[--synchronized_indexes]->add_entry(*old_record);
      }
      throw;
    }
  }
  NodeSession session(nodes_);
  try {
    auto root = open_long_root();
    root = root->leaf_for(key)->delete_record(key);
    update_root(root);
    ++modification_count_;
  } catch (...) {
    apply_record_delta(session.finish());
    while (synchronized_indexes != 0) {
      indexes[--synchronized_indexes]->add_entry(*old_record);
    }
    throw;
  }
  const auto delta = session.finish();
  apply_record_delta(delta);
  if (delta >= 0 && old_record) {
    while (synchronized_indexes != 0) {
      indexes[--synchronized_indexes]->add_entry(*old_record);
    }
  }
  return delta < 0;
}

bool Table::delete_record(const Field &key) {
  std::scoped_lock lock(*mutex_);
  check_mutation();
  require_field_key(key);
  if (schema_->use_long_key_nodes())
    return delete_record(key.as_integer());
  if (root_buffer_id_ < 0)
    return false;
  auto old_record = record(key);
  auto indexes = live_indexes();
  std::size_t synchronized_indexes = 0;
  if (old_record) {
    try {
      for (; synchronized_indexes < indexes.size(); ++synchronized_indexes) {
        indexes[synchronized_indexes]->delete_entry(*old_record);
      }
    } catch (...) {
      while (synchronized_indexes != 0) {
        indexes[--synchronized_indexes]->add_entry(*old_record);
      }
      throw;
    }
  }
  NodeSession session(nodes_);
  try {
    std::shared_ptr<BTreeNode> root;
    if (schema_->use_fixed_key_nodes()) {
      auto fixed_root = open_fixed_root();
      root = fixed_root->leaf_for(key)->delete_record(key);
    } else {
      auto variable_root = open_variable_root();
      root = variable_root->leaf_for(key)->delete_record(key);
    }
    update_root(root);
    ++modification_count_;
  } catch (...) {
    apply_record_delta(session.finish());
    while (synchronized_indexes != 0) {
      indexes[--synchronized_indexes]->add_entry(*old_record);
    }
    throw;
  }
  const auto delta = session.finish();
  apply_record_delta(delta);
  if (delta >= 0 && old_record) {
    while (synchronized_indexes != 0) {
      indexes[--synchronized_indexes]->add_entry(*old_record);
    }
  }
  return delta < 0;
}

bool Table::delete_records(std::int64_t start_key, std::int64_t end_key) {
  std::scoped_lock lock(*mutex_);
  check_mutation();
  require_long_key_schema();
  if (start_key > end_key) {
    throw std::invalid_argument("Table deletion range is reversed");
  }
  if (root_buffer_id_ < 0)
    return false;

  // The fixed Java baseline reports a non-empty tail search as changed when
  // the entire range sorts after the last record, even though no record is
  // removed.  This observable legacy return value is relied upon by callers
  // and is distinct from the genuinely empty-table result above.
  const auto tail = last_record();
  const bool legacy_nonempty_tail =
      tail && tail->key().as_integer() < start_key;

  NodeSession session(nodes_);
  bool deleted = false;
  auto indexes = live_indexes();
  ++modification_count_;
  try {
    auto cursor = start_key;
    while (root_buffer_id_ >= 0) {
      auto record_value =
          open_long_root()->leaf_for(cursor)->record_at_or_after(cursor);
      if (!record_value)
        break;
      const auto key = record_value->key().as_integer();
      if (key > end_key)
        break;

      std::size_t synchronized_indexes = 0;
      try {
        for (; synchronized_indexes < indexes.size(); ++synchronized_indexes) {
          indexes[synchronized_indexes]->delete_entry(*record_value);
        }
        auto root = open_long_root();
        root = root->leaf_for(key)->delete_record(key);
        update_root(root);
      } catch (...) {
        while (synchronized_indexes != 0) {
          indexes[--synchronized_indexes]->add_entry(*record_value);
        }
        throw;
      }
      deleted = true;
      if (key == std::numeric_limits<std::int64_t>::max())
        break;
      cursor = key + 1;
    }
  } catch (...) {
    apply_record_delta(session.finish());
    throw;
  }
  const auto delta = session.finish();
  apply_record_delta(delta);
  return deleted || delta < 0 || legacy_nonempty_tail;
}

bool Table::delete_records(const Field &start_key, const Field &end_key) {
  std::scoped_lock lock(*mutex_);
  check_mutation();
  if (schema_->use_long_key_nodes()) {
    throw std::invalid_argument(
        "operation requires a non-long Field-key table");
  }
  require_field_key(start_key);
  require_field_key(end_key);
  if (start_key.compare(end_key) > 0) {
    throw std::invalid_argument("Table deletion range is reversed");
  }
  if (root_buffer_id_ < 0)
    return false;

  const auto tail = last_record();
  const bool legacy_nonempty_tail = tail && tail->key().compare(start_key) < 0;

  NodeSession session(nodes_);
  bool deleted = false;
  auto indexes = live_indexes();
  auto cursor = start_key.clone();
  ++modification_count_;
  try {
    while (root_buffer_id_ >= 0) {
      std::unique_ptr<Record> record_value;
      if (schema_->use_fixed_key_nodes()) {
        record_value =
            open_fixed_root()->leaf_for(*cursor)->record_at_or_after(*cursor);
      } else {
        record_value =
            open_variable_root()->leaf_for(*cursor)->record_at_or_after(
                *cursor);
      }
      if (!record_value || record_value->key().compare(end_key) > 0)
        break;

      cursor = record_value->key().clone();
      std::size_t synchronized_indexes = 0;
      try {
        for (; synchronized_indexes < indexes.size(); ++synchronized_indexes) {
          indexes[synchronized_indexes]->delete_entry(*record_value);
        }
        std::shared_ptr<BTreeNode> root;
        if (schema_->use_fixed_key_nodes()) {
          auto fixed_root = open_fixed_root();
          root = fixed_root->leaf_for(*cursor)->delete_record(*cursor);
        } else {
          auto variable_root = open_variable_root();
          root = variable_root->leaf_for(*cursor)->delete_record(*cursor);
        }
        update_root(root);
      } catch (...) {
        while (synchronized_indexes != 0) {
          indexes[--synchronized_indexes]->add_entry(*record_value);
        }
        throw;
      }
      deleted = true;
      // Reusing the removed key as an inclusive lower bound selects its
      // successor without needing a key-family-specific successor function.
    }
  } catch (...) {
    apply_record_delta(session.finish());
    throw;
  }
  const auto delta = session.finish();
  apply_record_delta(delta);
  return deleted || delta < 0 || legacy_nonempty_tail;
}

void Table::delete_all() {
  std::scoped_lock lock(*mutex_);
  check_mutation();
  if (root_buffer_id_ < 0)
    return;
  NodeSession session(nodes_);
  try {
    auto root = open_root();
    root->delete_tree();
    for (const auto &index : live_indexes())
      index->delete_all();
  } catch (...) {
    root_buffer_id_ = -1;
    record_count_ = 0;
    maximum_key_ = TableRecord::initial_maximum_key;
    metadata_->set_root_buffer_id(-1);
    metadata_->set_record_count(0);
    metadata_->set_maximum_key(maximum_key_);
    ++modification_count_;
    throw;
  }
  root_buffer_id_ = -1;
  record_count_ = 0;
  maximum_key_ = TableRecord::initial_maximum_key;
  metadata_->set_root_buffer_id(-1);
  metadata_->set_record_count(0);
  metadata_->set_maximum_key(maximum_key_);
  ++modification_count_;
  (void)session.finish();
}

bool Table::consistent(const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  task.checkpoint();
  check_valid();
  if (root_buffer_id_ < 0) {
    if (record_count_ != 0)
      return false;
    for (const auto &index : live_indexes()) {
      task.checkpoint();
      if (!index->consistent(task))
        return false;
    }
    task.checkpoint();
    return true;
  }
  try {
    (void)audit_storage(task);
    NodeSession session(nodes_);
    const auto tree_consistent = open_root()->consistent(task);
    (void)session.finish();
    if (!tree_consistent)
      return false;

    std::size_t actual_count = 0;
    const auto progress_total = static_cast<std::uint64_t>(record_count_);
    task.report("table-verify-records", 0, progress_total);
    auto records = iterator();
    while (records->has_next()) {
      task.checkpoint();
      if (!records->next())
        return false;
      ++actual_count;
      if (actual_count >
          static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        return false;
      }
      if (actual_count <= progress_total) {
        task.report("table-verify-records",
                    static_cast<std::uint64_t>(actual_count), progress_total);
      }
    }
    if (actual_count != static_cast<std::size_t>(record_count_))
      return false;
    for (const auto &index : live_indexes()) {
      task.checkpoint();
      if (!index->consistent(task))
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

StorageGraphAudit Table::audit_storage(const TaskContext &task,
                                       bool verify_record_count) {
  std::scoped_lock lock(*mutex_);
  task.checkpoint();
  check_valid();
  StorageGraphAudit result;
  const auto owner = name();
  if (root_buffer_id_ < 0) {
    if (verify_record_count && record_count_ != 0) {
      throw StorageIntegrityError(
          StorageIntegrityCode::record_count_mismatch, root_buffer_id_, owner,
          "empty tree has non-zero catalog record count");
    }
    return result;
  }

  NodeSession session(nodes_);
  std::shared_ptr<BTreeNode> root;
  try {
    root = open_root();
  } catch (const std::out_of_range &) {
    throw StorageIntegrityError(
        StorageIntegrityCode::invalid_buffer_reference, root_buffer_id_, owner,
        "root references a free or out-of-range buffer");
  } catch (const StorageIntegrityError &) {
    throw;
  } catch (const std::exception &error) {
    throw StorageIntegrityError(StorageIntegrityCode::wrong_node_family,
                                root_buffer_id_, owner, error.what());
  }
  enum class VisitState : std::uint8_t { active, complete };
  struct Visit final {
    std::int32_t id;
    bool leave;
  };
  std::unordered_map<std::int32_t, VisitState> states;
  std::unordered_set<std::int32_t> owned;
  struct LeafLinks final {
    std::int32_t previous;
    std::int32_t next;
  };
  std::unordered_map<std::int32_t, LeafLinks> leaf_links;
  std::vector<Visit> pending{{root_buffer_id_, false}};
  while (!pending.empty()) {
    task.checkpoint();
    const auto visit = pending.back();
    pending.pop_back();
    if (visit.leave) {
      states[visit.id] = VisitState::complete;
      continue;
    }
    const auto found = states.find(visit.id);
    if (found != states.end()) {
      throw StorageIntegrityError(
          found->second == VisitState::active
              ? StorageIntegrityCode::node_cycle
              : StorageIntegrityCode::duplicate_node_ownership,
          visit.id, owner);
    }
    if (buffers_.buffer_state(visit.id) !=
        BufferManager::BufferState::allocated) {
      throw StorageIntegrityError(
          StorageIntegrityCode::invalid_buffer_reference, visit.id, owner,
          "tree references a free or out-of-range buffer");
    }
    states.emplace(visit.id, VisitState::active);
    owned.insert(visit.id);
    result.buffer_ids.push_back(visit.id);
    pending.push_back({visit.id, true});

    std::shared_ptr<BTreeNode> node;
    try {
      if (schema_->use_long_key_nodes())
        node = nodes_.get_long_key_node(visit.id);
      else if (schema_->use_fixed_key_nodes())
        node = nodes_.get_fixed_key_node(visit.id);
      else
        node = nodes_.get_variable_key_node(visit.id);
    } catch (const std::out_of_range &) {
      throw StorageIntegrityError(
          StorageIntegrityCode::invalid_buffer_reference, visit.id, owner);
    } catch (const StorageIntegrityError &) {
      throw;
    } catch (const std::exception &error) {
      throw StorageIntegrityError(StorageIntegrityCode::wrong_node_family,
                                  visit.id, owner, error.what());
    }

    const auto references = node->buffer_references();
    if (dynamic_cast<InteriorNode *>(node.get()) != nullptr) {
      ++result.interior_node_count;
      for (auto iterator = references.rbegin(); iterator != references.rend();
           ++iterator) {
        pending.push_back({*iterator, false});
      }
      continue;
    }

    ++result.record_node_count;
    result.record_count += node->key_count();
    const auto link_offset = schema_->use_variable_key_nodes()
                                 ? VariableKeyNode::header_size
                                 : LongKeyNode::header_size;
    leaf_links.emplace(
        visit.id, LeafLinks{node->buffer_handle()->get_i32(link_offset),
                            node->buffer_handle()->get_i32(link_offset + 4)});
    for (const auto chain_id : references) {
      task.checkpoint();
      try {
        ChainedBuffer chain(buffers_, chain_id);
        const auto chain_ids = chain.storage_buffer_ids();
        for (const auto id : chain_ids) {
          if (!owned.insert(id).second) {
            throw StorageIntegrityError(
                StorageIntegrityCode::duplicate_buffer_ownership, id, owner,
                "B-Tree node or indirect records share storage");
          }
          result.buffer_ids.push_back(id);
        }
        ++result.chained_buffer_count;
      } catch (const StorageIntegrityError &) {
        throw;
      } catch (const std::out_of_range &) {
        throw StorageIntegrityError(
            StorageIntegrityCode::invalid_buffer_reference, chain_id, owner,
            "indirect record references a free or out-of-range buffer");
      } catch (const std::exception &error) {
        throw StorageIntegrityError(
            StorageIntegrityCode::chained_buffer_node_family, chain_id, owner,
            error.what());
      }
    }
  }
  if (!leaf_links.empty()) {
    std::int32_t head = -1;
    std::size_t head_count = 0;
    for (const auto &[id, links] : leaf_links) {
      task.checkpoint();
      if (links.previous < 0) {
        head = id;
        ++head_count;
      } else {
        const auto previous = leaf_links.find(links.previous);
        if (links.previous == id || previous == leaf_links.end() ||
            previous->second.next != id) {
          throw StorageIntegrityError(
              StorageIntegrityCode::leaf_link_mismatch, id, owner,
              "invalid or non-reciprocal previous leaf link");
        }
      }
      if (links.next >= 0) {
        const auto next = leaf_links.find(links.next);
        if (links.next == id || next == leaf_links.end() ||
            next->second.previous != id) {
          throw StorageIntegrityError(
              StorageIntegrityCode::leaf_link_mismatch, id, owner,
              "invalid or non-reciprocal next leaf link");
        }
      }
    }
    if (head_count != 1) {
      throw StorageIntegrityError(StorageIntegrityCode::leaf_link_mismatch,
                                  head, owner,
                                  "leaf chain does not have exactly one head");
    }
    std::unordered_set<std::int32_t> linked;
    auto current = head;
    while (current >= 0) {
      task.checkpoint();
      if (!linked.insert(current).second) {
        throw StorageIntegrityError(StorageIntegrityCode::leaf_link_mismatch,
                                    current, owner,
                                    "leaf chain contains a cycle");
      }
      current = leaf_links.at(current).next;
    }
    if (linked.size() != leaf_links.size()) {
      throw StorageIntegrityError(
          StorageIntegrityCode::leaf_link_mismatch, head, owner,
          "leaf chain does not cover every record node");
    }
  }
  try {
    if (!root->consistent(task)) {
      throw StorageIntegrityError(StorageIntegrityCode::btree_invariant,
                                  root_buffer_id_, owner);
    }
  } catch (const OperationCancelled &) {
    throw;
  } catch (const StorageIntegrityError &) {
    throw;
  } catch (const std::out_of_range &) {
    throw StorageIntegrityError(
        StorageIntegrityCode::invalid_buffer_reference, root_buffer_id_, owner,
        "tree traversal references a free or out-of-range buffer");
  } catch (const std::exception &error) {
    throw StorageIntegrityError(StorageIntegrityCode::wrong_node_family,
                                root_buffer_id_, owner, error.what());
  }
  (void)session.finish();
  if (verify_record_count &&
      result.record_count != static_cast<std::size_t>(record_count_)) {
    throw StorageIntegrityError(StorageIntegrityCode::record_count_mismatch,
                                root_buffer_id_, owner);
  }
  return result;
}

void Table::rebuild(const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  task.checkpoint();
  check_mutation();
  check_valid();
  if (root_buffer_id_ < 0) {
    auto indexes = live_indexes();
    const auto index_total = static_cast<std::uint64_t>(indexes.size());
    task.report("table-rebuild-clear-indexes", 0, index_total);
    for (std::size_t index = 0; index < indexes.size(); ++index) {
      task.checkpoint();
      indexes[index]->delete_all();
      task.report("table-rebuild-clear-indexes",
                  static_cast<std::uint64_t>(index + 1), index_total);
    }
    task.report("table-rebuild-records", 0, 0);
    task.checkpoint();
    if (record_count_ != 0) {
      record_count_ = 0;
      metadata_->set_record_count(0);
      ++modification_count_;
    }
    if (!consistent(task)) {
      throw std::runtime_error("Table is inconsistent after rebuild: " +
                               name());
    }
    return;
  }

  {
    NodeSession session(nodes_);
    if (!open_root()->consistent(task)) {
      throw std::runtime_error("low-level B-Tree is inconsistent: " + name());
    }
    (void)session.finish();
  }

  std::uint64_t actual_count = 0;
  std::optional<std::int64_t> upstream_rebuild_key;
  auto records = iterator();
  while (records->has_next()) {
    task.checkpoint();
    auto record_value = records->next();
    if (!record_value) {
      throw std::runtime_error("Table rebuild iterator returned no record");
    }
    if (actual_count ==
        static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) {
      throw std::overflow_error("Table rebuild record count is out of range");
    }
    ++actual_count;
    if (schema_->use_long_key_nodes()) {
      const auto key = record_value->key().as_integer();
      // The fixed baseline selects the smallest observed long key here and
      // only advances stored max-key metadata. Preserve that behavior until
      // an upstream compatibility decision explicitly changes the contract.
      if (!upstream_rebuild_key || *upstream_rebuild_key > key) {
        upstream_rebuild_key = key;
      }
    }
  }

  auto indexes = live_indexes();
  const auto index_total = static_cast<std::uint64_t>(indexes.size());
  task.report("table-rebuild-clear-indexes", 0, index_total);
  for (std::size_t index = 0; index < indexes.size(); ++index) {
    task.checkpoint();
    indexes[index]->delete_all();
    task.report("table-rebuild-clear-indexes",
                static_cast<std::uint64_t>(index + 1), index_total);
  }

  task.report("table-rebuild-records", 0, actual_count);
  std::uint64_t rebuilt = 0;
  records = iterator();
  while (records->has_next()) {
    task.checkpoint();
    auto record_value = records->next();
    if (!record_value) {
      throw std::runtime_error("Table rebuild iterator returned no record");
    }
    for (const auto &index : indexes) {
      task.checkpoint();
      index->add_entry(*record_value);
    }
    task.report("table-rebuild-records", ++rebuilt, actual_count);
  }
  if (rebuilt != actual_count) {
    throw std::runtime_error("Table changed during rebuild");
  }

  task.checkpoint();
  record_count_ = static_cast<std::int32_t>(actual_count);
  metadata_->set_record_count(record_count_);
  if (upstream_rebuild_key && *upstream_rebuild_key > maximum_key_) {
    maximum_key_ = *upstream_rebuild_key;
    metadata_->set_maximum_key(maximum_key_);
  }
  ++modification_count_;

  if (!consistent(task)) {
    throw std::runtime_error("Table is inconsistent after rebuild: " + name());
  }
}

TableStatistics Table::statistics() {
  std::scoped_lock lock(*mutex_);
  check_valid();
  TableStatistics result;
  result.name = metadata_->name();
  if (root_buffer_id_ < 0)
    return result;

  NodeSession session(nodes_);
  std::unordered_set<std::int32_t> visited;
  std::function<void(std::int32_t)> accumulate = [&](std::int32_t id) {
    if (id < 0 || !visited.insert(id).second) {
      throw std::runtime_error("Table statistics found invalid node graph");
    }
    std::shared_ptr<BTreeNode> node;
    if (schema_->use_long_key_nodes()) {
      node = nodes_.get_long_key_node(id);
    } else if (schema_->use_fixed_key_nodes()) {
      node = nodes_.get_fixed_key_node(id);
    } else {
      node = nodes_.get_variable_key_node(id);
    }
    ++result.buffer_count;
    const auto references = node->buffer_references();
    if (dynamic_cast<InteriorNode *>(node.get()) != nullptr) {
      ++result.interior_node_count;
      for (const auto child_id : references)
        accumulate(child_id);
      return;
    }
    ++result.record_node_count;
    for (const auto chain_id : references) {
      ChainedBuffer chain(buffers_, chain_id);
      const auto count = chain.buffer_count();
      result.chained_buffer_count += count;
      result.buffer_count += count;
    }
  };
  accumulate(root_buffer_id_);
  result.size_bytes =
      result.buffer_count * static_cast<std::size_t>(buffers_.buffer_size());
  (void)session.finish();
  return result;
}

void Table::attach_index(const std::shared_ptr<IndexTable> &index) {
  if (!index)
    throw std::invalid_argument("cannot attach a null index");
  std::scoped_lock lock(*mutex_);
  if (&index->storage_table().buffer_manager() != &buffers_) {
    throw std::invalid_argument("index uses a different BufferManager");
  }
  const auto column = index->column_index();
  for (auto iterator = indexes_.begin(); iterator != indexes_.end();) {
    auto existing = iterator->lock();
    if (!existing) {
      iterator = indexes_.erase(iterator);
      continue;
    }
    if (existing->column_index() == column) {
      throw std::invalid_argument("Table column already has an index");
    }
    ++iterator;
  }
  indexes_.push_back(index);
}

void Table::detach_index(std::size_t column_index) {
  std::scoped_lock lock(*mutex_);
  check_valid();
  std::erase_if(indexes_, [column_index](const auto &weak) {
    const auto index = weak.lock();
    return !index || index->column_index() == column_index;
  });
}

void Table::clear_indexes() {
  std::scoped_lock lock(*mutex_);
  check_valid();
  indexes_.clear();
}

std::vector<std::shared_ptr<IndexTable>> Table::live_indexes() {
  std::vector<std::shared_ptr<IndexTable>> result;
  for (auto iterator = indexes_.begin(); iterator != indexes_.end();) {
    auto index = iterator->lock();
    if (!index) {
      iterator = indexes_.erase(iterator);
      continue;
    }
    result.push_back(std::move(index));
    ++iterator;
  }
  return result;
}

std::vector<std::size_t> Table::indexed_columns() const {
  std::scoped_lock lock(*mutex_);
  check_valid();
  std::vector<std::size_t> result;
  for (const auto &weak : indexes_) {
    if (const auto index = weak.lock()) {
      result.push_back(index->column_index());
    }
  }
  std::sort(result.begin(), result.end());
  return result;
}

void Table::metadata_changed() {
  std::scoped_lock lock(*mutex_);
  check_valid();
  root_buffer_id_ = metadata_->root_buffer_id();
  record_count_ = metadata_->record_count();
  maximum_key_ = metadata_->maximum_key();
  ++modification_count_;
}

void Table::invalidate() noexcept {
  std::scoped_lock lock(*mutex_);
  if (!valid_)
    return;
  valid_ = false;
  indexes_.clear();
  ++modification_count_;
}

} // namespace llmghidra::db
