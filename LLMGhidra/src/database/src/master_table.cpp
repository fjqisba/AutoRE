/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/master_table.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::db {

MasterTable::MasterTable(BufferManager &buffers, DatabaseParameters &parameters,
                         std::function<void()> mutation_guard,
                         std::shared_ptr<std::recursive_mutex> database_monitor)
    : buffers_(buffers), parameters_(parameters),
      master_record_(std::make_shared<TableRecord>(
          0, "MASTER", TableRecord::storage_schema(),
          TableRecord::primary_table_index_column)),
      mutation_guard_(std::move(mutation_guard)) {
  master_record_->set_root_buffer_id(
      parameters_.get(DatabaseParameters::master_table_root_parameter));
  table_ = std::make_unique<Table>(buffers_, master_record_, mutation_guard_,
                                   std::move(database_monitor));

  // Validate the persisted catalog graph before any iterator follows it. A
  // malformed child cycle must be diagnosed instead of recursing forever
  // during open. The catalog count is reconstructed immediately below.
  (void)table_->audit_storage({}, false);

  auto stored = read_catalog_records();
  records_.reserve(stored.size());
  for (auto &record : stored) {
    records_.push_back(
        std::make_shared<TableRecord>(buffers_, std::move(record)));
  }
  if (!records_.empty()) {
    next_table_number_ = records_.back()->table_number() + 1;
  }
  update_catalog_metadata(records_.size(),
                          records_.empty() ? TableRecord::initial_maximum_key
                                           : records_.back()->table_number());
}

void MasterTable::check_mutation() const {
  if (mutation_guard_)
    mutation_guard_();
}

std::vector<std::unique_ptr<Record>> MasterTable::read_catalog_records() {
  std::vector<std::unique_ptr<Record>> result;
  auto iterator = table_->iterator();
  while (iterator->has_next()) {
    auto record = iterator->next();
    if (!record) {
      throw std::runtime_error("master table iterator returned no record");
    }
    result.push_back(std::move(record));
  }
  return result;
}

void MasterTable::update_catalog_metadata(std::size_t count,
                                          std::int64_t maximum_key) {
  if (count >
      static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::overflow_error("master table record count is out of range");
  }
  master_record_->set_record_count(static_cast<std::int32_t>(count));
  master_record_->set_maximum_key(maximum_key);
  table_->metadata_changed();
}

void MasterTable::synchronize_root_parameter() {
  parameters_.set(DatabaseParameters::master_table_root_parameter,
                  master_record_->root_buffer_id());
}

std::shared_ptr<TableRecord>
MasterTable::create_record(std::string name,
                           std::shared_ptr<const Schema> schema,
                           std::int32_t indexed_column) {
  check_mutation();
  if (!schema)
    throw std::invalid_argument("catalog schema is required");
  if (next_table_number_ == std::numeric_limits<std::int64_t>::max()) {
    throw std::overflow_error("master table number space exhausted");
  }
  auto result = std::make_shared<TableRecord>(
      next_table_number_++, std::move(name), std::move(schema), indexed_column);
  table_->put_record(result->record());
  synchronize_root_parameter();
  records_.push_back(result);
  std::sort(records_.begin(), records_.end(),
            [](const auto &left, const auto &right) {
              return left->table_number() < right->table_number();
            });
  return result;
}

void MasterTable::delete_record(std::int64_t table_number) {
  check_mutation();
  const auto found = std::find_if(
      records_.begin(), records_.end(), [table_number](const auto &record) {
        return record->table_number() == table_number;
      });
  if (found == records_.end()) {
    throw std::out_of_range("catalog table record not found");
  }
  if ((*found)->root_buffer_id() >= 0) {
    throw std::logic_error("cannot delete a non-empty table catalog record");
  }
  if (!table_->delete_record(table_number)) {
    throw std::runtime_error("catalog record disappeared during deletion");
  }
  synchronize_root_parameter();
  (*found)->invalidate();
  records_.erase(found);
}

const std::vector<std::shared_ptr<TableRecord>> &MasterTable::refresh() {
  const auto root =
      parameters_.get(DatabaseParameters::master_table_root_parameter);
  if (master_record_->root_buffer_id() != root) {
    master_record_->set_root_buffer_id(root);
    table_->metadata_changed();
  }

  auto stored = read_catalog_records();
  std::vector<std::shared_ptr<TableRecord>> refreshed;
  refreshed.reserve(stored.size());
  std::size_t old_index = 0;
  for (auto &record : stored) {
    const auto number = record->key().as_integer();
    while (old_index < records_.size() &&
           records_[old_index]->table_number() < number) {
      records_[old_index++]->invalidate();
    }
    if (old_index < records_.size() &&
        records_[old_index]->table_number() == number) {
      records_[old_index]->replace_record(buffers_, std::move(record));
      refreshed.push_back(records_[old_index++]);
    } else {
      refreshed.push_back(
          std::make_shared<TableRecord>(buffers_, std::move(record)));
    }
  }
  while (old_index < records_.size()) {
    records_[old_index++]->invalidate();
  }
  records_ = std::move(refreshed);

  const auto maximum = records_.empty() ? TableRecord::initial_maximum_key
                                        : records_.back()->table_number();
  update_catalog_metadata(records_.size(), maximum);
  if (maximum != TableRecord::initial_maximum_key &&
      maximum < std::numeric_limits<std::int64_t>::max()) {
    next_table_number_ = std::max(next_table_number_, maximum + 1);
  }
  return records_;
}

void MasterTable::flush() {
  check_mutation();
  for (const auto &record : records_) {
    if (record->record().dirty())
      table_->put_record(record->record());
  }
  // A variable-length catalog replacement can split or collapse the master
  // B-Tree even when no catalog entry was added or removed.
  synchronize_root_parameter();
}

void MasterTable::change_name(const std::string &old_name,
                              const std::string &new_name) {
  check_mutation();
  for (const auto &record : records_) {
    if (record->name() == old_name)
      record->set_name(new_name);
  }
}

bool MasterTable::dirty() const {
  return std::any_of(records_.begin(), records_.end(), [](const auto &record) {
    return record->record().dirty();
  });
}

std::int32_t MasterTable::root_buffer_id() const {
  return master_record_->root_buffer_id();
}

void MasterTable::invalidate() noexcept {
  if (table_)
    table_->invalidate();
  for (const auto &record : records_)
    record->invalidate();
  records_.clear();
}

} // namespace llmghidra::db
