/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/index_table.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {
namespace {

void position_after(FieldKeyIterator &iterator, const Field &anchor) {
  if (!iterator.has_next())
    return;
  auto candidate = iterator.next();
  if (candidate && !candidate->equals(anchor)) {
    // Restore the logical position immediately before the first key greater
    // than an anchor which is not itself present.
    (void)iterator.previous();
  }
}

class PrimaryIndexKeyIterator final : public FieldKeyIterator {
public:
  PrimaryIndexKeyIterator(std::shared_ptr<FieldIndexTable> owner,
                          std::unique_ptr<FieldKeyIterator> storage,
                          const Field *minimum_value,
                          const Field *maximum_value,
                          std::shared_ptr<std::recursive_mutex> monitor)
      : owner_(std::move(owner)), storage_(std::move(storage)),
        minimum_value_(minimum_value ? minimum_value->clone() : nullptr),
        maximum_value_(maximum_value ? maximum_value->clone() : nullptr),
        monitor_(std::move(monitor)) {}

  bool has_next() override {
    std::scoped_lock lock(*monitor_);
    if (has_next_)
      return true;
    has_previous_ = false;
    while (storage_->has_next()) {
      auto field = storage_->next();
      if (!field)
        break;
      auto *index = dynamic_cast<IndexField *>(field.get());
      if (!index)
        throw std::runtime_error("index storage key type differs");
      if (in_range(*index)) {
        current_ = std::unique_ptr<IndexField>(
            static_cast<IndexField *>(field.release()));
        has_next_ = true;
        return true;
      }
    }
    return false;
  }

  bool has_previous() override {
    std::scoped_lock lock(*monitor_);
    if (has_previous_)
      return true;
    has_next_ = false;
    while (storage_->has_previous()) {
      auto field = storage_->previous();
      if (!field)
        break;
      auto *index = dynamic_cast<IndexField *>(field.get());
      if (!index)
        throw std::runtime_error("index storage key type differs");
      if (in_range(*index)) {
        current_ = std::unique_ptr<IndexField>(
            static_cast<IndexField *>(field.release()));
        has_previous_ = true;
        return true;
      }
    }
    return false;
  }

  std::unique_ptr<Field> next() override {
    std::scoped_lock lock(*monitor_);
    if (!has_next())
      throw std::out_of_range("no next indexed primary key");
    has_next_ = false;
    has_previous_ = true;
    last_primary_key_ = current_->primary_key().clone();
    return current_->primary_key().clone();
  }

  std::unique_ptr<Field> previous() override {
    std::scoped_lock lock(*monitor_);
    if (!has_previous()) {
      throw std::out_of_range("no previous indexed primary key");
    }
    has_next_ = true;
    has_previous_ = false;
    last_primary_key_ = current_->primary_key().clone();
    return current_->primary_key().clone();
  }

  bool delete_last() override {
    std::scoped_lock lock(*monitor_);
    if (!last_primary_key_)
      return false;
    auto key = std::move(last_primary_key_);
    return owner_->primary_table().delete_record(*key);
  }

private:
  [[nodiscard]] bool in_range(const IndexField &key) const {
    if (!minimum_value_ && !maximum_value_)
      return true;
    auto record = owner_->primary_table().record(key.primary_key());
    if (!record)
      return false;
    const auto &actual = record->field(owner_->column_index());
    return (!minimum_value_ || actual.compare(*minimum_value_) >= 0) &&
           (!maximum_value_ || actual.compare(*maximum_value_) <= 0);
  }

  std::shared_ptr<FieldIndexTable> owner_;
  std::unique_ptr<FieldKeyIterator> storage_;
  std::unique_ptr<Field> minimum_value_;
  std::unique_ptr<Field> maximum_value_;
  std::unique_ptr<IndexField> current_;
  std::unique_ptr<Field> last_primary_key_;
  std::shared_ptr<std::recursive_mutex> monitor_;
  bool has_next_ = false;
  bool has_previous_ = false;
};

class UniqueIndexValueIterator final : public FieldKeyIterator {
public:
  UniqueIndexValueIterator(std::shared_ptr<FieldIndexTable> owner,
                           std::unique_ptr<FieldKeyIterator> storage,
                           std::shared_ptr<std::recursive_mutex> monitor)
      : owner_(std::move(owner)), storage_(std::move(storage)),
        monitor_(std::move(monitor)) {}

  bool has_next() override {
    std::scoped_lock lock(*monitor_);
    if (has_next_)
      return true;
    has_previous_ = false;
    while (storage_->has_next()) {
      auto field = storage_->next();
      if (!field)
        break;
      auto *index = dynamic_cast<IndexField *>(field.get());
      if (!index)
        throw std::runtime_error("index storage key type differs");
      if (last_value_ && index->has_same_index_value(*last_value_))
        continue;
      current_ = std::unique_ptr<IndexField>(
          static_cast<IndexField *>(field.release()));
      has_next_ = true;
      return true;
    }
    return false;
  }

  bool has_previous() override {
    std::scoped_lock lock(*monitor_);
    if (has_previous_)
      return true;
    has_next_ = false;
    while (storage_->has_previous()) {
      auto field = storage_->previous();
      if (!field)
        break;
      auto *index = dynamic_cast<IndexField *>(field.get());
      if (!index)
        throw std::runtime_error("index storage key type differs");
      if (last_value_ && index->has_same_index_value(*last_value_))
        continue;
      current_ = std::unique_ptr<IndexField>(
          static_cast<IndexField *>(field.release()));
      has_previous_ = true;
      return true;
    }
    return false;
  }

  std::unique_ptr<Field> next() override {
    std::scoped_lock lock(*monitor_);
    if (!has_next())
      return nullptr;
    has_next_ = false;
    has_previous_ = true;
    last_value_ = std::unique_ptr<IndexField>(
        static_cast<IndexField *>(current_->clone().release()));
    return current_->indexed_field().clone();
  }

  std::unique_ptr<Field> previous() override {
    std::scoped_lock lock(*monitor_);
    if (!has_previous())
      return nullptr;
    has_next_ = true;
    has_previous_ = false;
    last_value_ = std::unique_ptr<IndexField>(
        static_cast<IndexField *>(current_->clone().release()));
    return current_->indexed_field().clone();
  }

  bool delete_last() override {
    std::scoped_lock lock(*monitor_);
    if (!last_value_)
      return false;
    auto keys = owner_->find_primary_keys(last_value_->indexed_field());
    for (const auto &key : keys) {
      if (!owner_->primary_table().delete_record(*key)) {
        throw std::runtime_error("indexed primary record disappeared");
      }
    }
    last_value_.reset();
    return true;
  }

private:
  std::shared_ptr<FieldIndexTable> owner_;
  std::unique_ptr<FieldKeyIterator> storage_;
  std::unique_ptr<IndexField> current_;
  std::unique_ptr<IndexField> last_value_;
  std::shared_ptr<std::recursive_mutex> monitor_;
  bool has_next_ = false;
  bool has_previous_ = false;
};

} // namespace

IndexTable::IndexTable(Table &primary_table,
                       std::shared_ptr<TableRecord> index_metadata)
    : primary_table_(primary_table),
      primary_keep_alive_(primary_table.weak_from_this().lock()),
      metadata_(std::move(index_metadata)) {
  if (!metadata_)
    throw std::invalid_argument("index metadata is required");
  if (!primary_table_.use_long_keys() && !primary_table_.use_fixed_keys()) {
    throw std::invalid_argument(
        "only fixed-length primary Table keys may be indexed");
  }
  const auto column = metadata_->indexed_column();
  if (column < 0 || static_cast<std::size_t>(column) >=
                        primary_table_.schema().field_count()) {
    throw std::invalid_argument("index column is outside primary schema");
  }
  column_index_ = static_cast<std::size_t>(column);
  sparse_ = primary_table_.schema().is_sparse(column_index_);
  if (metadata_->name() != primary_table_.name()) {
    throw std::invalid_argument("index and primary Table names differ");
  }
  index_table_ = std::make_unique<Table>(
      primary_table_.mutable_buffer_manager(), metadata_,
      primary_table_.mutation_guard(), primary_table_.database_monitor());
}

std::int64_t IndexTable::table_number() const {
  std::scoped_lock lock(*database_monitor());
  return metadata_->table_number();
}

TableStatistics IndexTable::statistics() {
  std::scoped_lock lock(*database_monitor());
  auto result = index_table_->statistics();
  result.index_column = static_cast<std::int32_t>(column_index_);
  return result;
}

bool IndexTable::consistent(const TaskContext &task) {
  std::scoped_lock lock(*database_monitor());
  task.checkpoint();
  if (!index_table_->consistent(task))
    return false;
  try {
    std::size_t expected_entries = 0;
    std::uint64_t scanned_primary = 0;
    const auto primary_total =
        static_cast<std::uint64_t>(primary_table_.record_count());
    task.report("index-verify-primary", 0, primary_total);
    auto primary_records = primary_table_.iterator();
    while (primary_records->has_next()) {
      task.checkpoint();
      auto record = primary_records->next();
      if (!record)
        return false;
      ++scanned_primary;
      if (scanned_primary <= primary_total) {
        task.report("index-verify-primary", scanned_primary, primary_total);
      }
      const auto &value = record->field(column_index_);
      if (sparse_ && value.is_null())
        continue;
      ++expected_entries;
      auto keys = find_primary_keys(value, task);
      const auto found = std::any_of(keys.begin(), keys.end(),
                                     [&](const std::unique_ptr<Field> &key) {
                                       return key && key->equals(record->key());
                                     });
      if (!found)
        return false;
    }
    if (expected_entries !=
        static_cast<std::size_t>(index_table_->record_count())) {
      return false;
    }

    std::uint64_t scanned_index = 0;
    const auto index_total =
        static_cast<std::uint64_t>(index_table_->record_count());
    task.report("index-verify-storage", 0, index_total);
    auto index_records = index_table_->iterator();
    while (index_records->has_next()) {
      task.checkpoint();
      auto record = index_records->next();
      if (!record)
        return false;
      ++scanned_index;
      if (scanned_index <= index_total) {
        task.report("index-verify-storage", scanned_index, index_total);
      }
      const auto *index_key = dynamic_cast<const IndexField *>(&record->key());
      if (!index_key)
        return false;
      auto primary = primary_table_.record(index_key->primary_key());
      if (!primary ||
          !primary->field(column_index_).equals(index_key->indexed_field())) {
        // Truncated variable values require prefix equality rather than full
        // equality; find_primary_keys performs the authoritative full check.
        if (!index_key->indexed_field().variable_length())
          return false;
        auto matches = find_primary_keys(primary ? primary->field(column_index_)
                                                 : index_key->indexed_field(),
                                         task);
        const auto found =
            std::any_of(matches.begin(), matches.end(),
                        [&](const std::unique_ptr<Field> &key) {
                          return key && key->equals(index_key->primary_key());
                        });
        if (!found)
          return false;
      }
    }
    task.checkpoint();
    return true;
  } catch (const OperationCancelled &) {
    throw;
  } catch (...) {
    return false;
  }
}

bool IndexTable::has_record(const Field &index_value) {
  std::scoped_lock lock(*database_monitor());
  return !find_primary_keys(index_value).empty();
}

std::size_t IndexTable::key_count(const Field &index_value) {
  std::scoped_lock lock(*database_monitor());
  return find_primary_keys(index_value).size();
}

void IndexTable::delete_all() {
  std::scoped_lock lock(*database_monitor());
  index_table_->delete_all();
}

std::shared_ptr<Schema>
FieldIndexTable::index_schema(const Table &primary_table,
                              std::size_t column_index) {
  const auto &primary_schema = primary_table.schema();
  if (column_index >= primary_schema.field_count()) {
    throw std::out_of_range("index column is outside primary schema");
  }
  if (!primary_table.use_long_keys() && !primary_table.use_fixed_keys()) {
    throw std::invalid_argument(
        "only fixed-length primary Table keys may be indexed");
  }
  if (!can_index(&primary_schema.field_type(column_index))) {
    throw std::invalid_argument("primary column type cannot be indexed");
  }
  std::vector<std::unique_ptr<Field>> fields;
  std::vector<std::string> names;
  return std::make_shared<Schema>(
      0,
      std::make_unique<IndexField>(primary_schema.field_type(column_index),
                                   primary_schema.key_type()),
      "IndexKey", std::move(fields), std::move(names));
}

std::shared_ptr<FieldIndexTable>
FieldIndexTable::create(Table &primary_table, std::int64_t table_number,
                        std::size_t column_index) {
  if (primary_table.record_count() != 0) {
    throw std::invalid_argument(
        "an index may only be created on an empty Table");
  }
  auto metadata =
      std::make_shared<TableRecord>(table_number, primary_table.name(),
                                    index_schema(primary_table, column_index),
                                    static_cast<std::int32_t>(column_index));
  auto result = std::shared_ptr<FieldIndexTable>(
      new FieldIndexTable(primary_table, std::move(metadata)));
  primary_table.attach_index(result);
  return result;
}

std::shared_ptr<FieldIndexTable>
FieldIndexTable::open(Table &primary_table,
                      std::shared_ptr<TableRecord> metadata) {
  auto result = std::shared_ptr<FieldIndexTable>(
      new FieldIndexTable(primary_table, std::move(metadata)));
  primary_table.attach_index(result);
  return result;
}

FieldIndexTable::FieldIndexTable(Table &primary_table,
                                 std::shared_ptr<TableRecord> metadata)
    : IndexTable(primary_table, std::move(metadata)) {
  const auto *stored =
      dynamic_cast<const IndexField *>(&index_table_->schema().key_type());
  if (!stored ||
      !stored->indexed_field().same_type(
          primary_table_.schema().field_type(column_index_)) ||
      !stored->primary_key().same_type(primary_table_.schema().key_type())) {
    throw std::invalid_argument(
        "stored index schema differs from primary Table");
  }
}

const IndexField &FieldIndexTable::index_key_type() const {
  std::scoped_lock lock(*database_monitor());
  const auto *result =
      dynamic_cast<const IndexField *>(&index_table_->schema().key_type());
  if (!result)
    throw std::logic_error("index Table key is not an IndexField");
  return *result;
}

void FieldIndexTable::require_primary_record(const Record &record) const {
  if (!record.has_same_schema(primary_table_.schema())) {
    throw std::invalid_argument("record schema differs from primary Table");
  }
}

std::vector<std::unique_ptr<Field>>
FieldIndexTable::find_primary_keys(const Field &index_value,
                                   const TaskContext &task) {
  std::scoped_lock lock(*database_monitor());
  task.checkpoint();
  if (!index_value.same_type(
          primary_table_.schema().field_type(column_index_))) {
    throw std::invalid_argument("index lookup value type differs");
  }
  auto minimum_primary = primary_table_.schema().key_type().minimum();
  auto probe = index_key_type().new_index_field(index_value, *minimum_primary);
  auto iterator = index_table_->field_key_iterator(*probe);
  std::vector<std::unique_ptr<Field>> result;
  while (iterator->has_next()) {
    task.checkpoint();
    auto field = iterator->next();
    if (!field)
      break;
    const auto *index = dynamic_cast<const IndexField *>(field.get());
    if (!index || !index->has_same_index_value(*probe))
      break;
    if (probe->uses_truncated_value()) {
      auto record = primary_table_.record(index->primary_key());
      if (!record || !index_value.equals(record->field(column_index_))) {
        continue;
      }
    }
    result.push_back(index->primary_key().clone());
  }
  task.checkpoint();
  return result;
}

void FieldIndexTable::add_entry(const Record &record) {
  std::scoped_lock lock(*database_monitor());
  require_primary_record(record);
  const auto &indexed = record.field(column_index_);
  if (sparse_ && indexed.is_null())
    return;
  auto key = index_key_type().new_index_field(indexed, record.key());
  auto entry = index_table_->schema().create_record(std::move(key));
  index_table_->put_record(*entry);
}

void FieldIndexTable::delete_entry(const Record &record) {
  std::scoped_lock lock(*database_monitor());
  require_primary_record(record);
  const auto &indexed = record.field(column_index_);
  if (sparse_ && indexed.is_null())
    return;
  auto key = index_key_type().new_index_field(indexed, record.key());
  (void)index_table_->delete_record(*key);
}

void FieldIndexTable::update_entry(const Record &old_record,
                                   const Record &new_record) {
  std::scoped_lock lock(*database_monitor());
  require_primary_record(old_record);
  require_primary_record(new_record);
  const auto &old_value = old_record.field(column_index_);
  const auto &new_value = new_record.field(column_index_);
  if (old_value.equals(new_value))
    return;
  delete_entry(old_record);
  try {
    add_entry(new_record);
  } catch (...) {
    add_entry(old_record);
    throw;
  }
}

std::unique_ptr<FieldKeyIterator> FieldIndexTable::index_iterator() {
  std::scoped_lock lock(*database_monitor());
  return std::make_unique<UniqueIndexValueIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      index_table_->field_key_iterator(), database_monitor());
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::index_iterator(const Field *minimum_value,
                                const Field *maximum_value, bool before) {
  std::scoped_lock lock(*database_monitor());
  if (primary_table_.schema().field_type(column_index_).variable_length()) {
    throw std::logic_error(
        "unique range iteration is unsupported for truncated index values");
  }
  auto minimum_primary = primary_table_.schema().key_type().minimum();
  auto maximum_primary = primary_table_.schema().key_type().maximum();
  auto minimum =
      minimum_value
          ? index_key_type().new_index_field(*minimum_value, *minimum_primary)
          : nullptr;
  auto maximum =
      maximum_value
          ? index_key_type().new_index_field(*maximum_value, *maximum_primary)
          : nullptr;
  auto storage =
      index_table_->field_key_iterator(minimum.get(), maximum.get(), before);
  return std::make_unique<UniqueIndexValueIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      std::move(storage), database_monitor());
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::index_iterator(const Field *minimum_value,
                                const Field *maximum_value,
                                const Field &start_value, bool before) {
  std::scoped_lock lock(*database_monitor());
  if (primary_table_.schema().field_type(column_index_).variable_length()) {
    throw std::logic_error(
        "unique range iteration is unsupported for truncated index values");
  }
  auto minimum_primary = primary_table_.schema().key_type().minimum();
  auto maximum_primary = primary_table_.schema().key_type().maximum();
  auto minimum =
      minimum_value
          ? index_key_type().new_index_field(*minimum_value, *minimum_primary)
          : nullptr;
  auto maximum =
      maximum_value
          ? index_key_type().new_index_field(*maximum_value, *maximum_primary)
          : nullptr;
  auto start = index_key_type().new_index_field(
      start_value, before ? *minimum_primary : *maximum_primary);
  auto storage = index_table_->field_key_iterator(minimum.get(), maximum.get(),
                                                  start.get());
  if (!before)
    position_after(*storage, *start);
  return std::make_unique<UniqueIndexValueIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      std::move(storage), database_monitor());
}

std::unique_ptr<FieldKeyIterator> FieldIndexTable::key_iterator() {
  std::scoped_lock lock(*database_monitor());
  return std::make_unique<PrimaryIndexKeyIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      index_table_->field_key_iterator(), nullptr, nullptr, database_monitor());
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::key_iterator_before(const Field &start_value) {
  std::scoped_lock lock(*database_monitor());
  auto primary = primary_table_.schema().key_type().minimum();
  auto start = index_key_type().new_index_field(start_value, *primary);
  auto storage = index_table_->field_key_iterator(*start);
  return std::make_unique<PrimaryIndexKeyIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      std::move(storage), nullptr, nullptr, database_monitor());
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::key_iterator_after(const Field &start_value) {
  std::scoped_lock lock(*database_monitor());
  auto primary = primary_table_.schema().key_type().maximum();
  auto start = index_key_type().new_index_field(start_value, *primary);
  auto storage = index_table_->field_key_iterator(*start);
  position_after(*storage, *start);
  return std::make_unique<PrimaryIndexKeyIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      std::move(storage), nullptr, nullptr, database_monitor());
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::key_iterator_before(const Field &start_value,
                                     const Field &primary_key) {
  std::scoped_lock lock(*database_monitor());
  auto start = index_key_type().new_index_field(start_value, primary_key);
  auto storage = index_table_->field_key_iterator(*start);
  return std::make_unique<PrimaryIndexKeyIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      std::move(storage), nullptr, nullptr, database_monitor());
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::key_iterator_after(const Field &start_value,
                                    const Field &primary_key) {
  std::scoped_lock lock(*database_monitor());
  auto start = index_key_type().new_index_field(start_value, primary_key);
  auto storage = index_table_->field_key_iterator(*start);
  position_after(*storage, *start);
  return std::make_unique<PrimaryIndexKeyIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      std::move(storage), nullptr, nullptr, database_monitor());
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::key_iterator(const Field *minimum_value,
                              const Field *maximum_value, bool before) {
  std::scoped_lock lock(*database_monitor());
  return key_iterator(minimum_value, maximum_value,
                      before ? minimum_value : maximum_value, before);
}

std::unique_ptr<FieldKeyIterator>
FieldIndexTable::key_iterator(const Field *minimum_value,
                              const Field *maximum_value,
                              const Field *start_value, bool before) {
  std::scoped_lock lock(*database_monitor());
  auto minimum_primary = primary_table_.schema().key_type().minimum();
  auto maximum_primary = primary_table_.schema().key_type().maximum();
  auto minimum =
      minimum_value
          ? index_key_type().new_index_field(*minimum_value, *minimum_primary)
          : nullptr;
  auto maximum =
      maximum_value
          ? index_key_type().new_index_field(*maximum_value, *maximum_primary)
          : nullptr;
  std::unique_ptr<IndexField> start;
  if (start_value) {
    start = index_key_type().new_index_field(
        *start_value, before ? *minimum_primary : *maximum_primary);
  }
  auto storage = start ? index_table_->field_key_iterator(
                             minimum.get(), maximum.get(), start.get())
                       : index_table_->field_key_iterator(
                             minimum.get(), maximum.get(), before);
  if (!before && start)
    position_after(*storage, *start);
  return std::make_unique<PrimaryIndexKeyIterator>(
      std::static_pointer_cast<FieldIndexTable>(shared_from_this()),
      std::move(storage), minimum_value, maximum_value, database_monitor());
}

} // namespace llmghidra::db
