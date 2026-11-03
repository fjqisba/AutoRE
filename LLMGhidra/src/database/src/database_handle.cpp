/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/database_handle.hpp"

#include "llmghidra/db/chained_buffer.hpp"

#include "llmghidra/db/database_change_set.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <set>
#include <utility>

namespace llmghidra::db {
namespace {

std::int64_t next_database_id() {
  static std::atomic<std::uint64_t> sequence{1};
  const auto ticks = static_cast<std::uint64_t>(
      std::chrono::system_clock::now().time_since_epoch().count());
  auto value = ticks ^ (sequence.fetch_add(1, std::memory_order_relaxed) << 17);
  value &= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  return static_cast<std::int64_t>(value == 0 ? 1 : value);
}

} // namespace

DatabaseHandle::DatabaseHandle(std::int32_t requested_buffer_size,
                               std::size_t approximate_cache_size,
                               std::int32_t maximum_undos)
    : buffers_(std::make_unique<BufferManager>(
          requested_buffer_size, approximate_cache_size, maximum_undos)) {
  initialize_new();
}

DatabaseHandle::DatabaseHandle(std::shared_ptr<LocalBufferFile> source_file,
                               std::size_t approximate_cache_size,
                               std::int32_t maximum_undos, bool read_only)
    : buffers_(std::make_unique<BufferManager>(
          std::move(source_file), approximate_cache_size, maximum_undos)),
      read_only_(read_only) {
  initialize_existing();
}

DatabaseHandle::~DatabaseHandle() { close(); }

void DatabaseHandle::initialize_new() {
  parameters_ = std::make_unique<DatabaseParameters>(*buffers_, true);
  parameters_->set(DatabaseParameters::master_table_root_parameter, -1);
  write_database_id(next_database_id());
  master_table_ = std::make_unique<MasterTable>(
      *buffers_, *parameters_, [this] { check_transaction(); }, mutex_);
  buffers_->clear_checkpoints();
}

void DatabaseHandle::initialize_existing() {
  parameters_ = std::make_unique<DatabaseParameters>(*buffers_, false);
  read_database_id();
  master_table_ = std::make_unique<MasterTable>(
      *buffers_, *parameters_, [this] { check_transaction(); }, mutex_);
  load_tables();
}

void DatabaseHandle::require_open_locked() const {
  if (closed_ || !buffers_)
    throw ClosedDatabaseError();
}

void DatabaseHandle::write_database_id(std::int64_t id) {
  database_id_ = id;
  const auto raw = static_cast<std::uint64_t>(id);
  parameters_->set(DatabaseParameters::database_id_high_parameter,
                   static_cast<std::int32_t>(raw >> 32));
  parameters_->set(DatabaseParameters::database_id_low_parameter,
                   static_cast<std::int32_t>(raw & 0xffffffffULL));
}

void DatabaseHandle::read_database_id() {
  try {
    const auto high = static_cast<std::uint32_t>(
        parameters_->get(DatabaseParameters::database_id_high_parameter));
    const auto low = static_cast<std::uint32_t>(
        parameters_->get(DatabaseParameters::database_id_low_parameter));
    database_id_ = static_cast<std::int64_t>(
        (static_cast<std::uint64_t>(high) << 32) | low);
  } catch (const std::out_of_range &) {
    database_id_ = 0;
  }
}

void DatabaseHandle::check_transaction() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (transaction_active_)
    return;
  if (waiting_for_new_transaction_)
    throw TerminatedTransactionError();
  throw NoTransactionError();
}

std::int64_t DatabaseHandle::start_transaction() {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (transaction_active_) {
    throw std::logic_error("database transaction is already active");
  }
  if (last_transaction_id_ == std::numeric_limits<std::int64_t>::max()) {
    throw std::overflow_error("database transaction ID space exhausted");
  }
  waiting_for_new_transaction_ = false;
  transaction_active_ = true;
  return ++last_transaction_id_;
}

bool DatabaseHandle::end_transaction_locked(std::int64_t id, bool commit) {
  require_open_locked();
  if (!transaction_active_ || id != last_transaction_id_) {
    throw std::logic_error("database transaction ID is not active");
  }
  try {
    const bool catalog_dirty = master_table_->dirty();
    const bool buffer_dirty = !buffers_->at_checkpoint();
    if (commit) {
      if (catalog_dirty)
        master_table_->flush();
      const bool checkpoint_created = buffers_->checkpoint();
      transaction_active_ = false;
      return checkpoint_created;
    }

    if (buffer_dirty)
      (void)buffers_->undo(false);
    if (buffer_dirty || catalog_dirty)
      reload_tables();
    transaction_active_ = false;
    return false;
  } catch (...) {
    transaction_active_ = false;
    throw;
  }
}

bool DatabaseHandle::end_transaction(std::int64_t id, bool commit) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  return end_transaction_locked(id, commit);
}

void DatabaseHandle::terminate_transaction(std::int64_t id, bool commit) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  (void)end_transaction_locked(id, commit);
  waiting_for_new_transaction_ = true;
}

bool DatabaseHandle::transaction_active() const {
  std::scoped_lock lock(*mutex_);
  return transaction_active_;
}

bool DatabaseHandle::has_uncommitted_changes() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  return !buffers_->at_checkpoint() || master_table_->dirty();
}

bool DatabaseHandle::can_undo() const {
  std::scoped_lock lock(*mutex_);
  return !closed_ && !transaction_active_ && buffers_ &&
         buffers_->has_undo_checkpoints();
}

bool DatabaseHandle::can_redo() const {
  std::scoped_lock lock(*mutex_);
  return !closed_ && !transaction_active_ && buffers_ &&
         buffers_->has_redo_checkpoints();
}

bool DatabaseHandle::undo() {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (transaction_active_ || !buffers_->undo(true))
    return false;
  reload_tables();
  return true;
}

bool DatabaseHandle::redo() {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (transaction_active_ || !buffers_->redo())
    return false;
  reload_tables();
  return true;
}

std::size_t DatabaseHandle::available_undo_count() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  return buffers_->available_undo_count();
}

std::size_t DatabaseHandle::available_redo_count() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  return buffers_->available_redo_count();
}

void DatabaseHandle::set_max_undos(std::int32_t maximum_undos) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (transaction_active_) {
    throw std::logic_error("cannot change undo depth during a transaction");
  }
  buffers_->set_max_undos(maximum_undos);
}

void DatabaseHandle::load_tables() {
  tables_.clear();
  indexes_.clear();
  for (const auto &metadata : master_table_->records()) {
    if (metadata->indexed_column() >= 0)
      continue;
    auto table = std::make_shared<Table>(
        *buffers_, metadata, [this] { check_transaction(); }, mutex_);
    if (!tables_.emplace(table->name(), table).second) {
      throw std::runtime_error("duplicate primary table name in catalog");
    }
  }
  for (const auto &metadata : master_table_->records()) {
    if (metadata->indexed_column() < 0)
      continue;
    const auto primary = tables_.find(metadata->name());
    if (primary == tables_.end()) {
      throw std::runtime_error("index catalog record has no primary table");
    }
    auto index = FieldIndexTable::open(*primary->second, metadata);
    indexes_.emplace(metadata->table_number(), std::move(index));
  }
}

void DatabaseHandle::reload_tables() {
  for (auto &[name, table] : tables_) {
    (void)name;
    if (table->valid())
      table->clear_indexes();
  }

  parameters_->refresh();
  read_database_id();
  const auto &records = master_table_->refresh();

  std::unordered_map<std::int64_t, std::shared_ptr<Table>> old_tables;
  for (auto &[name, table] : tables_) {
    (void)name;
    if (table->valid())
      old_tables.emplace(table->table_number(), table);
  }
  auto old_indexes = std::move(indexes_);
  tables_.clear();

  std::set<std::int64_t> reused_tables;
  for (const auto &metadata : records) {
    if (metadata->indexed_column() >= 0)
      continue;
    std::shared_ptr<Table> table;
    const auto old = old_tables.find(metadata->table_number());
    if (old != old_tables.end() && old->second->valid()) {
      table = old->second;
      table->metadata_changed();
      reused_tables.insert(metadata->table_number());
    } else {
      table = std::make_shared<Table>(
          *buffers_, metadata, [this] { check_transaction(); }, mutex_);
    }
    if (!tables_.emplace(metadata->name(), table).second) {
      throw std::runtime_error("duplicate primary table name after reload");
    }
  }
  for (auto &[number, table] : old_tables) {
    if (!reused_tables.contains(number))
      table->invalidate();
  }

  std::set<std::int64_t> reused_indexes;
  for (const auto &metadata : records) {
    if (metadata->indexed_column() < 0)
      continue;
    const auto primary = tables_.find(metadata->name());
    if (primary == tables_.end()) {
      throw std::runtime_error("index has no primary table after reload");
    }
    std::shared_ptr<FieldIndexTable> index;
    const auto old = old_indexes.find(metadata->table_number());
    if (old != old_indexes.end() &&
        &old->second->primary_table() == primary->second.get() &&
        old->second->storage_table().valid()) {
      index = old->second;
      index->storage_table().metadata_changed();
      primary->second->attach_index(index);
      reused_indexes.insert(metadata->table_number());
    } else {
      index = FieldIndexTable::open(*primary->second, metadata);
    }
    indexes_.emplace(metadata->table_number(), std::move(index));
  }
  for (auto &[number, index] : old_indexes) {
    if (!reused_indexes.contains(number))
      index->storage_table().invalidate();
  }
}

std::shared_ptr<Table>
DatabaseHandle::get_table(const std::string &name) const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  const auto found = tables_.find(name);
  return found == tables_.end() ? nullptr : found->second;
}

std::vector<std::shared_ptr<Table>> DatabaseHandle::tables() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  std::vector<std::shared_ptr<Table>> result;
  result.reserve(tables_.size());
  for (const auto &[name, table] : tables_) {
    (void)name;
    result.push_back(table);
  }
  std::sort(result.begin(), result.end(),
            [](const auto &left, const auto &right) {
              return left->table_number() < right->table_number();
            });
  return result;
}

std::size_t DatabaseHandle::table_count() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  return tables_.size();
}

bool DatabaseHandle::consistent(const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  task.checkpoint();
  require_open_locked();
  try {
    StorageAuditOptions options;
    options.reject_unclaimed_buffers = false;
    (void)audit_storage(task, options);
  } catch (const OperationCancelled &) {
    throw;
  } catch (...) {
    return false;
  }
  const auto ordered = tables();
  const auto total = static_cast<std::uint64_t>(ordered.size());
  task.report("database-verify", 0, total);
  bool result = true;
  std::uint64_t completed = 0;
  for (const auto &table : ordered) {
    task.checkpoint();
    try {
      if (!table->consistent(task))
        result = false;
    } catch (const OperationCancelled &) {
      throw;
    } catch (...) {
      result = false;
    }
    task.report("database-verify", ++completed, total);
  }
  return result;
}

StorageGraphAudit
DatabaseHandle::audit_storage(const TaskContext &task,
                              const StorageAuditOptions &options) {
  std::scoped_lock lock(*mutex_);
  task.checkpoint();
  require_open_locked();
  StorageGraphAudit result;
  std::unordered_map<std::int32_t, std::string> owners;
  const auto claim = [&](const StorageGraphAudit &part,
                         const std::string &owner) {
    result.interior_node_count += part.interior_node_count;
    result.record_node_count += part.record_node_count;
    result.chained_buffer_count += part.chained_buffer_count;
    result.record_count += part.record_count;
    for (const auto id : part.buffer_ids) {
      const auto [found, inserted] = owners.emplace(id, owner);
      if (!inserted) {
        throw StorageIntegrityError(
            StorageIntegrityCode::duplicate_buffer_ownership, id, owner,
            "already owned by " + found->second);
      }
      result.buffer_ids.push_back(id);
    }
  };

  // Buffer 0 is the DBParms root and is outside all Table graphs.
  owners.emplace(0, "DBParms");
  result.buffer_ids.push_back(0);
  for (const auto id : options.externally_owned_buffer_ids) {
    if (buffers_->buffer_state(id) != BufferManager::BufferState::allocated) {
      throw StorageIntegrityError(
          StorageIntegrityCode::invalid_buffer_reference, id,
          "external-storage-buffer",
          "registered application buffer is free or out of range");
    }
    const auto [found, inserted] =
        owners.emplace(id, "external-storage-buffer");
    if (!inserted) {
      throw StorageIntegrityError(
          StorageIntegrityCode::duplicate_buffer_ownership, id,
          "external-storage-buffer", "already owned by " + found->second);
    }
    result.buffer_ids.push_back(id);
  }
  claim(master_table_->audit_storage(task), "MASTER");
  for (const auto &table : tables()) {
    task.checkpoint();
    claim(table->audit_storage(task), table->name());
  }
  std::vector<std::pair<std::int64_t, std::shared_ptr<FieldIndexTable>>>
      ordered_indexes(indexes_.begin(), indexes_.end());
  std::sort(ordered_indexes.begin(), ordered_indexes.end(),
            [](const auto &left, const auto &right) {
              return left.first < right.first;
            });
  for (const auto &[number, index] : ordered_indexes) {
    task.checkpoint();
    claim(index->storage_table().audit_storage(task),
          index->primary_table().name() + ".index." +
              std::to_string(index->column_index()) + "." +
              std::to_string(number));
  }

  if (options.reject_unclaimed_buffers) {
    for (const auto id : buffers_->allocated_buffer_ids()) {
      task.checkpoint();
      if (!owners.contains(id)) {
        throw StorageIntegrityError(StorageIntegrityCode::orphan_buffer, id,
                                    "database");
      }
    }
  }
  return result;
}

bool DatabaseHandle::rebuild(const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  task.checkpoint();
  require_open_locked();
  check_transaction();
  const auto ordered = tables();
  const auto total = static_cast<std::uint64_t>(ordered.size());
  task.report("database-rebuild", 0, total);
  std::uint64_t completed = 0;
  for (const auto &table : ordered) {
    task.checkpoint();
    try {
      table->rebuild(task);
    } catch (const OperationCancelled &) {
      throw;
    } catch (...) {
      return false;
    }
    task.report("database-rebuild", ++completed, total);
  }
  return true;
}

std::shared_ptr<Table>
DatabaseHandle::create_table(std::string name,
                             std::shared_ptr<const Schema> schema,
                             const std::vector<std::size_t> &indexed_columns) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (!schema)
    throw std::invalid_argument("table schema is required");
  if (tables_.contains(name)) {
    throw std::invalid_argument("table already exists: " + name);
  }
  check_transaction();
  std::set<std::size_t> unique_columns;
  for (const auto column : indexed_columns) {
    if (column >= schema->field_count()) {
      throw std::out_of_range("indexed column is outside table schema");
    }
    if (!unique_columns.insert(column).second) {
      throw std::invalid_argument("duplicate indexed column");
    }
  }

  auto metadata = master_table_->create_record(
      name, std::move(schema), TableRecord::primary_table_index_column);
  auto table = std::make_shared<Table>(
      *buffers_, metadata, [this] { check_transaction(); }, mutex_);
  tables_.emplace(table->name(), table);
  for (const auto column : indexed_columns) {
    (void)create_index_locked(table, column);
  }
  return table;
}

std::shared_ptr<FieldIndexTable>
DatabaseHandle::create_index_locked(const std::shared_ptr<Table> &table,
                                    std::size_t column_index) {
  if (!table || !table->valid())
    throw std::invalid_argument("invalid table");
  const auto indexed_columns = table->indexed_columns();
  if (indexed_columns.end() !=
      std::find(indexed_columns.begin(), indexed_columns.end(), column_index)) {
    throw std::invalid_argument("table column already has an index");
  }
  auto schema = FieldIndexTable::index_schema(*table, column_index);
  auto metadata =
      master_table_->create_record(table->name(), std::move(schema),
                                   static_cast<std::int32_t>(column_index));
  auto index = FieldIndexTable::open(*table, metadata);
  auto records = table->iterator();
  while (records->has_next()) {
    auto record = records->next();
    if (record)
      index->add_entry(*record);
  }
  indexes_.emplace(metadata->table_number(), index);
  return index;
}

std::shared_ptr<FieldIndexTable>
DatabaseHandle::create_index(const std::string &table_name,
                             std::size_t column_index) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  check_transaction();
  const auto found = tables_.find(table_name);
  if (found == tables_.end())
    throw std::out_of_range("table not found");
  return create_index_locked(found->second, column_index);
}

std::shared_ptr<FieldIndexTable>
DatabaseHandle::get_index(const std::string &table_name,
                          std::size_t column_index) const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  const auto table = tables_.find(table_name);
  if (table == tables_.end())
    return nullptr;
  for (const auto &[number, index] : indexes_) {
    (void)number;
    if (&index->primary_table() == table->second.get() &&
        index->column_index() == column_index) {
      return index;
    }
  }
  return nullptr;
}

bool DatabaseHandle::remove_index_locked(const std::shared_ptr<Table> &table,
                                         std::size_t column_index) {
  auto found =
      std::find_if(indexes_.begin(), indexes_.end(), [&](const auto &entry) {
        return &entry.second->primary_table() == table.get() &&
               entry.second->column_index() == column_index;
      });
  if (found == indexes_.end())
    return false;
  auto index = found->second;
  const auto table_number = found->first;
  index->delete_all();
  master_table_->delete_record(table_number);
  index->storage_table().invalidate();
  indexes_.erase(found);
  table->detach_index(column_index);
  return true;
}

bool DatabaseHandle::remove_index(const std::string &table_name,
                                  std::size_t column_index) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  check_transaction();
  const auto table = tables_.find(table_name);
  if (table == tables_.end())
    return false;
  return remove_index_locked(table->second, column_index);
}

bool DatabaseHandle::rename_table(const std::string &old_name,
                                  const std::string &new_name) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  const auto found = tables_.find(old_name);
  if (found == tables_.end())
    return false;
  check_transaction();
  if (tables_.contains(new_name)) {
    throw std::invalid_argument("table already exists: " + new_name);
  }
  auto table = found->second;
  master_table_->change_name(old_name, new_name);
  tables_.erase(found);
  tables_.emplace(new_name, std::move(table));
  return true;
}

bool DatabaseHandle::delete_table(const std::string &name) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  const auto found = tables_.find(name);
  if (found == tables_.end())
    return false;
  check_transaction();
  auto table = found->second;
  const auto columns = table->indexed_columns();
  for (const auto column : columns) {
    if (!remove_index_locked(table, column)) {
      throw std::runtime_error("attached index disappeared during deletion");
    }
  }
  table->delete_all();
  master_table_->delete_record(table->table_number());
  table->invalidate();
  tables_.erase(found);
  return true;
}

std::int64_t DatabaseHandle::database_id() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  return database_id_;
}

std::int64_t DatabaseHandle::reset_database_id(LocalBufferFile &file) {
  if (file.closed())
    throw ClosedDatabaseError();
  if (file.read_only())
    throw ReadOnlyDatabaseError();

  DataBuffer parameters;
  file.get(parameters, 0);
  if (parameters.empty() ||
      parameters.get_u8(DatabaseParameters::node_type_offset) !=
          DatabaseParameters::node_type ||
      parameters.get_u8(DatabaseParameters::version_offset) !=
          DatabaseParameters::storage_version) {
    throw std::runtime_error("invalid database parameter buffer");
  }
  const auto data_length =
      parameters.get_i32(DatabaseParameters::data_length_offset);
  constexpr auto required_parameter_count =
      DatabaseParameters::database_id_low_parameter + 1;
  constexpr auto required_data_length =
      1 + required_parameter_count * sizeof(std::int32_t);
  if (data_length < static_cast<std::int32_t>(required_data_length)) {
    throw std::runtime_error("database identity parameters are missing");
  }

  const auto id = next_database_id();
  const auto raw = static_cast<std::uint64_t>(id);
  const auto parameter_offset = [](std::size_t index) {
    return DatabaseParameters::parameter_base_offset +
           index * sizeof(std::int32_t);
  };
  parameters.put_i32(
      parameter_offset(DatabaseParameters::database_id_high_parameter),
      static_cast<std::int32_t>(raw >> 32));
  parameters.put_i32(
      parameter_offset(DatabaseParameters::database_id_low_parameter),
      static_cast<std::int32_t>(raw & 0xffffffffULL));
  parameters.set_dirty(true);
  file.put(parameters, 0);
  if (!file.flush()) {
    throw std::runtime_error("unable to persist reset database identity");
  }
  return id;
}

DatabaseHandle &DatabaseHandle::scratch_database() {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (!scratch_database_) {
    scratch_database_ = std::make_unique<DatabaseHandle>();
    (void)scratch_database_->start_transaction();
  }
  return *scratch_database_;
}

void DatabaseHandle::close_scratch_database() noexcept {
  std::scoped_lock lock(*mutex_);
  if (scratch_database_)
    scratch_database_->close();
  scratch_database_.reset();
}

void DatabaseHandle::save_as(
    const std::shared_ptr<LocalBufferFile> &destination,
    bool associate_with_new_file, const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_ && associate_with_new_file)
    throw ReadOnlyDatabaseError();
  if (transaction_active_ || !buffers_->at_checkpoint() ||
      master_table_->dirty()) {
    throw std::logic_error("database must be committed before save_as");
  }
  buffers_->save_as(destination, associate_with_new_file, task);
}

bool DatabaseHandle::can_save() const {
  std::scoped_lock lock(*mutex_);
  return !closed_ && !read_only_ && buffers_ && buffers_->can_save();
}

void DatabaseHandle::save(std::string comment, const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (transaction_active_ || !buffers_->at_checkpoint() ||
      master_table_->dirty()) {
    throw std::logic_error("database must be committed before save");
  }
  buffers_->save(comment, task);
}

void DatabaseHandle::save(std::string comment, DatabaseChangeSet &change_set,
                          const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  if (transaction_active_ || !buffers_->at_checkpoint() ||
      master_table_->dirty()) {
    throw std::logic_error("database must be committed before save");
  }
  buffers_->save(comment, change_set, task);
}

bool DatabaseHandle::take_recovery_snapshot(DatabaseChangeSet &change_set,
                                            const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_)
    throw ReadOnlyDatabaseError();
  return buffers_->take_recovery_snapshot(change_set, task);
}

void DatabaseHandle::read_recovery_change_set(DatabaseChangeSet &change_set,
                                              const TaskContext &task) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  buffers_->read_recovery_change_set(change_set, task);
}

const BufferManager &DatabaseHandle::buffer_manager() const {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  return *buffers_;
}

std::shared_ptr<DataBuffer>
DatabaseHandle::get_data_buffer(std::int32_t buffer_id) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  return buffers_->get_buffer(buffer_id);
}

std::shared_ptr<DataBuffer> DatabaseHandle::create_data_buffer() {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  check_transaction();
  return buffers_->create_buffer();
}

std::unique_ptr<ChainedBuffer> DatabaseHandle::create_chained_buffer(
    std::int32_t size, bool enable_obfuscation) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  check_transaction();
  return std::make_unique<ChainedBuffer>(size, enable_obfuscation, *buffers_);
}

std::unique_ptr<ChainedBuffer> DatabaseHandle::create_layered_chained_buffer(
    std::int32_t size,
    const Buffer &uninitialized_source,
    std::size_t source_offset) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  check_transaction();
  return std::make_unique<ChainedBuffer>(
      size, false, &uninitialized_source, source_offset, *buffers_);
}

std::unique_ptr<ChainedBuffer> DatabaseHandle::open_chained_buffer(
    std::int32_t first_buffer_id) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  auto result = std::make_unique<ChainedBuffer>(*buffers_, first_buffer_id);
  if (read_only_) result->set_read_only();
  return result;
}

std::unique_ptr<ChainedBuffer> DatabaseHandle::open_layered_chained_buffer(
    std::int32_t first_buffer_id,
    const Buffer &uninitialized_source,
    std::size_t source_offset) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  auto result = std::make_unique<ChainedBuffer>(
      *buffers_, first_buffer_id, &uninitialized_source, source_offset);
  if (read_only_) result->set_read_only();
  return result;
}

void DatabaseHandle::release_data_buffer(
    const std::shared_ptr<DataBuffer> &buffer) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  if (read_only_ && buffer && buffer->dirty()) {
    buffer->set_dirty(false);
    try {
      buffers_->release_buffer(buffer);
    } catch (...) {
      buffer->set_dirty(true);
      throw;
    }
    throw ReadOnlyDatabaseError();
  }
  buffers_->release_buffer(buffer);
}

void DatabaseHandle::delete_data_buffer(std::int32_t buffer_id) {
  std::scoped_lock lock(*mutex_);
  require_open_locked();
  check_transaction();
  buffers_->delete_buffer(buffer_id);
}

bool DatabaseHandle::closed() const noexcept {
  std::scoped_lock lock(*mutex_);
  return closed_;
}

bool DatabaseHandle::read_only() const noexcept {
  std::scoped_lock lock(*mutex_);
  return read_only_;
}

void DatabaseHandle::close() noexcept {
  std::scoped_lock lock(*mutex_);
  if (closed_)
    return;
  if (scratch_database_)
    scratch_database_->close();
  scratch_database_.reset();
  for (auto &[number, index] : indexes_) {
    (void)number;
    index->storage_table().invalidate();
  }
  for (auto &[name, table] : tables_) {
    (void)name;
    table->invalidate();
  }
  indexes_.clear();
  tables_.clear();
  if (master_table_)
    master_table_->invalidate();
  master_table_.reset();
  parameters_.reset();
  buffers_.reset();
  transaction_active_ = false;
  waiting_for_new_transaction_ = false;
  closed_ = true;
}

} // namespace llmghidra::db
