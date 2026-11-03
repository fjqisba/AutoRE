/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/table.hpp"

#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {
namespace {

class TableLongKeyIterator final : public LongKeyIterator {
public:
  TableLongKeyIterator(Table &table, std::int64_t minimum_key,
                       std::int64_t maximum_key, std::int64_t start_key,
                       bool suppress_initial_previous,
                       std::shared_ptr<std::recursive_mutex> monitor,
                       std::shared_ptr<Table> keep_alive)
      : table_(table), monitor_(std::move(monitor)),
        keep_alive_(std::move(keep_alive)), minimum_key_(minimum_key),
        maximum_key_(maximum_key), next_anchor_(start_key),
        previous_anchor_(start_key),
        previous_disabled_(suppress_initial_previous),
        observed_generation_(table.modification_count()) {
    if (minimum_key_ > maximum_key_) {
      next_disabled_ = true;
      previous_disabled_ = true;
    }
  }

  bool has_next() override {
    std::scoped_lock lock(*monitor_);
    synchronize();
    if (next_disabled_)
      return false;
    if (next_value_)
      return true;
    auto record_value =
        next_anchor_
            ? (next_inclusive_ ? table_.record_at_or_after(*next_anchor_)
                               : table_.record_after(*next_anchor_))
            : table_.first_record();
    if (!record_value)
      return false;
    const auto key = record_value->key().as_integer();
    if (key < minimum_key_ || key > maximum_key_)
      return false;
    next_value_ = key;
    return true;
  }

  bool has_previous() override {
    std::scoped_lock lock(*monitor_);
    synchronize();
    if (previous_disabled_)
      return false;
    if (previous_value_)
      return true;
    auto record_value =
        previous_anchor_ ? (previous_inclusive_
                                ? table_.record_at_or_before(*previous_anchor_)
                                : table_.record_before(*previous_anchor_))
                         : table_.last_record();
    if (!record_value)
      return false;
    const auto key = record_value->key().as_integer();
    if (key < minimum_key_ || key > maximum_key_)
      return false;
    previous_value_ = key;
    return true;
  }

  std::int64_t next() override {
    std::scoped_lock lock(*monitor_);
    if (!has_next())
      throw std::out_of_range("no next Table long key");
    const auto key = *next_value_;
    next_value_.reset();
    previous_value_.reset();
    next_anchor_ = key;
    next_inclusive_ = false;
    next_disabled_ = false;
    previous_anchor_ = key;
    previous_inclusive_ = true;
    previous_disabled_ = false;
    last_key_ = key;
    return key;
  }

  std::int64_t previous() override {
    std::scoped_lock lock(*monitor_);
    if (!has_previous()) {
      throw std::out_of_range("no previous Table long key");
    }
    const auto key = *previous_value_;
    next_value_.reset();
    previous_value_.reset();
    previous_anchor_ = key;
    previous_inclusive_ = false;
    previous_disabled_ = false;
    next_anchor_ = key;
    next_inclusive_ = true;
    next_disabled_ = false;
    last_key_ = key;
    return key;
  }

  bool delete_last() override {
    std::scoped_lock lock(*monitor_);
    if (!last_key_)
      return false;
    const auto key = *last_key_;
    last_key_.reset();
    const auto result = table_.delete_record(key);
    observed_generation_ = table_.modification_count();
    next_value_.reset();
    previous_value_.reset();
    return result;
  }

private:
  void synchronize() {
    const auto generation = table_.modification_count();
    if (generation == observed_generation_)
      return;
    observed_generation_ = generation;
    next_value_.reset();
    previous_value_.reset();
  }

  Table &table_;
  std::shared_ptr<std::recursive_mutex> monitor_;
  std::shared_ptr<Table> keep_alive_;
  std::int64_t minimum_key_;
  std::int64_t maximum_key_;
  std::optional<std::int64_t> next_anchor_;
  std::optional<std::int64_t> previous_anchor_;
  bool next_inclusive_ = true;
  bool previous_inclusive_ = true;
  bool next_disabled_ = false;
  bool previous_disabled_ = false;
  std::optional<std::int64_t> next_value_;
  std::optional<std::int64_t> previous_value_;
  std::optional<std::int64_t> last_key_;
  std::uint64_t observed_generation_;
};

class TableFieldKeyIterator final : public FieldKeyIterator {
public:
  TableFieldKeyIterator(Table &table, const Field *minimum_key,
                        const Field *maximum_key, const Field *start_key,
                        bool suppress_initial_previous,
                        bool position_after_maximum,
                        std::shared_ptr<std::recursive_mutex> monitor,
                        std::shared_ptr<Table> keep_alive)
      : table_(table), monitor_(std::move(monitor)),
        keep_alive_(std::move(keep_alive)),
        minimum_key_(minimum_key ? minimum_key->clone() : nullptr),
        maximum_key_(maximum_key ? maximum_key->clone() : nullptr),
        next_anchor_(start_key ? start_key->clone() : nullptr),
        previous_anchor_(start_key ? start_key->clone() : nullptr),
        previous_disabled_(suppress_initial_previous),
        observed_generation_(table.modification_count()) {
    validate_key(minimum_key_.get());
    validate_key(maximum_key_.get());
    validate_key(next_anchor_.get());
    if (minimum_key_ && maximum_key_ &&
        minimum_key_->compare(*maximum_key_) > 0) {
      next_disabled_ = true;
      previous_disabled_ = true;
      return;
    }
    if (position_after_maximum) {
      next_anchor_.reset();
      next_disabled_ = true;
      previous_anchor_ = maximum_key_ ? maximum_key_->clone() : nullptr;
      previous_disabled_ = false;
    } else if (!start_key && minimum_key_) {
      next_anchor_ = minimum_key_->clone();
      previous_anchor_ = minimum_key_->clone();
      previous_disabled_ = false;
    }
  }

  bool has_next() override {
    std::scoped_lock lock(*monitor_);
    synchronize();
    if (next_disabled_)
      return false;
    if (next_value_)
      return true;
    auto record_value =
        next_anchor_
            ? (next_inclusive_ ? table_.record_at_or_after(*next_anchor_)
                               : table_.record_after(*next_anchor_))
            : table_.first_record();
    if (!record_value || !in_range(record_value->key()))
      return false;
    next_value_ = record_value->key().clone();
    return true;
  }

  bool has_previous() override {
    std::scoped_lock lock(*monitor_);
    synchronize();
    if (previous_disabled_)
      return false;
    if (previous_value_)
      return true;
    auto record_value =
        previous_anchor_ ? (previous_inclusive_
                                ? table_.record_at_or_before(*previous_anchor_)
                                : table_.record_before(*previous_anchor_))
                         : table_.last_record();
    if (!record_value || !in_range(record_value->key()))
      return false;
    previous_value_ = record_value->key().clone();
    return true;
  }

  std::unique_ptr<Field> next() override {
    std::scoped_lock lock(*monitor_);
    if (!has_next())
      return nullptr;
    auto key = std::move(next_value_);
    previous_value_.reset();
    next_anchor_ = key->clone();
    next_inclusive_ = false;
    next_disabled_ = false;
    previous_anchor_ = key->clone();
    previous_inclusive_ = true;
    previous_disabled_ = false;
    last_key_ = key->clone();
    return key;
  }

  std::unique_ptr<Field> previous() override {
    std::scoped_lock lock(*monitor_);
    if (!has_previous())
      return nullptr;
    auto key = std::move(previous_value_);
    next_value_.reset();
    previous_anchor_ = key->clone();
    previous_inclusive_ = false;
    previous_disabled_ = false;
    next_anchor_ = key->clone();
    next_inclusive_ = true;
    next_disabled_ = false;
    last_key_ = key->clone();
    return key;
  }

  bool delete_last() override {
    std::scoped_lock lock(*monitor_);
    if (!last_key_)
      return false;
    auto key = std::move(last_key_);
    const auto result = table_.delete_record(*key);
    observed_generation_ = table_.modification_count();
    next_value_.reset();
    previous_value_.reset();
    return result;
  }

private:
  void validate_key(const Field *key) const {
    if (!key)
      return;
    if (!key->same_type(table_.schema().key_type()) || key->is_null()) {
      throw std::invalid_argument("iterator key type differs or is null");
    }
  }

  [[nodiscard]] bool in_range(const Field &key) const {
    return (!minimum_key_ || key.compare(*minimum_key_) >= 0) &&
           (!maximum_key_ || key.compare(*maximum_key_) <= 0);
  }

  void synchronize() {
    const auto generation = table_.modification_count();
    if (generation == observed_generation_)
      return;
    observed_generation_ = generation;
    next_value_.reset();
    previous_value_.reset();
  }

  Table &table_;
  std::shared_ptr<std::recursive_mutex> monitor_;
  std::shared_ptr<Table> keep_alive_;
  std::unique_ptr<Field> minimum_key_;
  std::unique_ptr<Field> maximum_key_;
  std::unique_ptr<Field> next_anchor_;
  std::unique_ptr<Field> previous_anchor_;
  bool next_inclusive_ = true;
  bool previous_inclusive_ = true;
  bool next_disabled_ = false;
  bool previous_disabled_ = false;
  std::unique_ptr<Field> next_value_;
  std::unique_ptr<Field> previous_value_;
  std::unique_ptr<Field> last_key_;
  std::uint64_t observed_generation_;
};

class LongRecordIterator final : public RecordIterator {
public:
  LongRecordIterator(Table &table, std::unique_ptr<LongKeyIterator> keys,
                     std::shared_ptr<std::recursive_mutex> monitor)
      : table_(table), keys_(std::move(keys)), monitor_(std::move(monitor)) {}
  bool has_next() override {
    std::scoped_lock lock(*monitor_);
    return keys_->has_next();
  }
  bool has_previous() override {
    std::scoped_lock lock(*monitor_);
    return keys_->has_previous();
  }
  std::unique_ptr<Record> next() override {
    std::scoped_lock lock(*monitor_);
    if (!keys_->has_next())
      return nullptr;
    return table_.record(keys_->next());
  }
  std::unique_ptr<Record> previous() override {
    std::scoped_lock lock(*monitor_);
    if (!keys_->has_previous())
      return nullptr;
    return table_.record(keys_->previous());
  }
  bool delete_last() override {
    std::scoped_lock lock(*monitor_);
    return keys_->delete_last();
  }

private:
  Table &table_;
  std::unique_ptr<LongKeyIterator> keys_;
  std::shared_ptr<std::recursive_mutex> monitor_;
};

class FieldRecordIterator final : public RecordIterator {
public:
  FieldRecordIterator(Table &table, std::unique_ptr<FieldKeyIterator> keys,
                      std::shared_ptr<std::recursive_mutex> monitor)
      : table_(table), keys_(std::move(keys)), monitor_(std::move(monitor)) {}
  bool has_next() override {
    std::scoped_lock lock(*monitor_);
    return keys_->has_next();
  }
  bool has_previous() override {
    std::scoped_lock lock(*monitor_);
    return keys_->has_previous();
  }
  std::unique_ptr<Record> next() override {
    std::scoped_lock lock(*monitor_);
    auto key = keys_->next();
    return key ? table_.record(*key) : nullptr;
  }
  std::unique_ptr<Record> previous() override {
    std::scoped_lock lock(*monitor_);
    auto key = keys_->previous();
    return key ? table_.record(*key) : nullptr;
  }
  bool delete_last() override {
    std::scoped_lock lock(*monitor_);
    return keys_->delete_last();
  }

private:
  Table &table_;
  std::unique_ptr<FieldKeyIterator> keys_;
  std::shared_ptr<std::recursive_mutex> monitor_;
};

} // namespace

std::unique_ptr<LongKeyIterator> Table::long_key_iterator() {
  std::scoped_lock lock(*mutex_);
  require_long_key_schema();
  return std::make_unique<TableLongKeyIterator>(
      *this, std::numeric_limits<std::int64_t>::min(),
      std::numeric_limits<std::int64_t>::max(),
      std::numeric_limits<std::int64_t>::min(), true, mutex_,
      weak_from_this().lock());
}

std::unique_ptr<LongKeyIterator>
Table::long_key_iterator(std::int64_t start_key) {
  std::scoped_lock lock(*mutex_);
  return long_key_iterator(std::numeric_limits<std::int64_t>::min(),
                           std::numeric_limits<std::int64_t>::max(), start_key);
}

std::unique_ptr<LongKeyIterator>
Table::long_key_iterator(std::int64_t minimum_key, std::int64_t maximum_key,
                         std::int64_t start_key) {
  std::scoped_lock lock(*mutex_);
  require_long_key_schema();
  return std::make_unique<TableLongKeyIterator>(*this, minimum_key, maximum_key,
                                                start_key, false, mutex_,
                                                weak_from_this().lock());
}

std::unique_ptr<FieldKeyIterator> Table::field_key_iterator() {
  std::scoped_lock lock(*mutex_);
  if (schema_->use_long_key_nodes()) {
    throw std::invalid_argument("operation requires a Field-key table");
  }
  return std::make_unique<TableFieldKeyIterator>(*this, nullptr, nullptr,
                                                 nullptr, true, false, mutex_,
                                                 weak_from_this().lock());
}

std::unique_ptr<FieldKeyIterator>
Table::field_key_iterator(const Field &start_key) {
  std::scoped_lock lock(*mutex_);
  return field_key_iterator(nullptr, nullptr, &start_key);
}

std::unique_ptr<FieldKeyIterator>
Table::field_key_iterator(const Field *minimum_key, const Field *maximum_key,
                          const Field *start_key) {
  std::scoped_lock lock(*mutex_);
  if (schema_->use_long_key_nodes()) {
    throw std::invalid_argument("operation requires a Field-key table");
  }
  return std::make_unique<TableFieldKeyIterator>(
      *this, minimum_key, maximum_key, start_key,
      start_key == nullptr && minimum_key == nullptr, false, mutex_,
      weak_from_this().lock());
}

std::unique_ptr<FieldKeyIterator>
Table::field_key_iterator(const Field *minimum_key, const Field *maximum_key,
                          bool before) {
  std::scoped_lock lock(*mutex_);
  if (schema_->use_long_key_nodes()) {
    throw std::invalid_argument("operation requires a Field-key table");
  }
  return std::make_unique<TableFieldKeyIterator>(
      *this, minimum_key, maximum_key, before ? minimum_key : maximum_key,
      before, !before, mutex_, weak_from_this().lock());
}

std::unique_ptr<RecordIterator> Table::iterator() {
  std::scoped_lock lock(*mutex_);
  if (schema_->use_long_key_nodes()) {
    return std::make_unique<LongRecordIterator>(*this, long_key_iterator(),
                                                mutex_);
  }
  return std::make_unique<FieldRecordIterator>(*this, field_key_iterator(),
                                               mutex_);
}

std::unique_ptr<RecordIterator> Table::iterator(std::int64_t start_key) {
  std::scoped_lock lock(*mutex_);
  return std::make_unique<LongRecordIterator>(
      *this, long_key_iterator(start_key), mutex_);
}

std::unique_ptr<RecordIterator> Table::iterator(std::int64_t minimum_key,
                                                std::int64_t maximum_key,
                                                std::int64_t start_key) {
  std::scoped_lock lock(*mutex_);
  return std::make_unique<LongRecordIterator>(
      *this, long_key_iterator(minimum_key, maximum_key, start_key), mutex_);
}

std::unique_ptr<RecordIterator> Table::iterator(const Field &start_key) {
  std::scoped_lock lock(*mutex_);
  if (schema_->use_long_key_nodes()) {
    return iterator(start_key.as_integer());
  }
  return std::make_unique<FieldRecordIterator>(
      *this, field_key_iterator(start_key), mutex_);
}

std::unique_ptr<RecordIterator> Table::iterator(const Field *minimum_key,
                                                const Field *maximum_key,
                                                const Field *start_key) {
  std::scoped_lock lock(*mutex_);
  if (schema_->use_long_key_nodes()) {
    const auto minimum = minimum_key ? minimum_key->as_integer()
                                     : std::numeric_limits<std::int64_t>::min();
    const auto maximum = maximum_key ? maximum_key->as_integer()
                                     : std::numeric_limits<std::int64_t>::max();
    const auto start = start_key ? start_key->as_integer() : minimum;
    return iterator(minimum, maximum, start);
  }
  return std::make_unique<FieldRecordIterator>(
      *this, field_key_iterator(minimum_key, maximum_key, start_key), mutex_);
}

} // namespace llmghidra::db
