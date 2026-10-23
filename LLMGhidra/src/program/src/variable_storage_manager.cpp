#include "llmghidra/program/variable_storage_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/index_table.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/language_translator.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr const char *variable_storage_table_name = "Variable Storage";
constexpr std::size_t hash_column = 0;
constexpr std::size_t storage_column = 1;

} // namespace

std::shared_ptr<db::Schema> VariableStorageManager::current_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        schema_version,
        std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Key", std::move(fields), std::vector<std::string>{"Hash", "Storage"});
}

VariableStorageManager::VariableStorageManager(
    std::shared_ptr<db::DatabaseHandle> database,
    std::shared_ptr<AddressFactory> address_factory,
    ProgramOpenMode mode,
    bool create)
    : database_(std::move(database)), address_factory_(std::move(address_factory)),
      mode_(mode) {
    if (!database_ || !address_factory_) {
        throw std::invalid_argument(
            "variable storage manager requires a database and address factory");
    }
    if (create) {
        table_ = database_->create_table(
            variable_storage_table_name, current_schema(), {hash_column});
        return;
    }
    bind_existing_table(mode_ == ProgramOpenMode::read_only ||
                        mode_ == ProgramOpenMode::upgrade);
    if (!table_ && mode_ == ProgramOpenMode::upgrade) {
        table_ = database_->create_table(
            variable_storage_table_name, current_schema(), {hash_column});
    }
}

void VariableStorageManager::bind_existing_table(bool allow_missing) {
    table_ = database_->get_table(variable_storage_table_name);
    if (!table_) {
        if (allow_missing) return;
        throw std::runtime_error("missing Ghidra Variable Storage table");
    }
    if (!table_->schema().equals(*current_schema())) {
        throw std::runtime_error("unsupported Ghidra Variable Storage schema version");
    }
    const auto indexed = table_->indexed_columns();
    if (indexed.size() != 1 || indexed.front() != hash_column) {
        throw std::runtime_error("Ghidra Variable Storage hash index is missing");
    }
}

bool VariableStorageManager::has_table() const noexcept {
    return static_cast<bool>(table_);
}

std::size_t VariableStorageManager::size() const {
    return table_ ? static_cast<std::size_t>(table_->record_count()) : 0;
}

std::optional<VariableStorageRecord> VariableStorageManager::record(
    const Address &variable_address) const {
    if (!variable_address.is_variable_address()) {
        throw std::invalid_argument("address is not in Ghidra VARIABLE space");
    }
    if (!table_ || variable_address.offset() >
                       static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return std::nullopt;
    }
    const auto row = table_->record(static_cast<std::int64_t>(variable_address.offset()));
    if (!row) return std::nullopt;
    const auto serialization = row->field(storage_column).as_string();
    if (!serialization) {
        throw std::runtime_error("Variable Storage record has null serialization");
    }
    return VariableStorageRecord{row->key().as_integer(),
                                 row->field(hash_column).as_integer(),
                                 *serialization};
}

std::optional<VariableStorage> VariableStorageManager::storage(
    const Address &variable_address) const {
    const auto row = record(variable_address);
    if (!row) return std::nullopt;
    try {
        return VariableStorage::deserialize(*address_factory_, row->serialization);
    }
    catch (const std::exception &) {
        // Upstream represents an undecodable persisted storage as BAD_STORAGE.
        return VariableStorage::bad();
    }
}

std::optional<std::int64_t> VariableStorageManager::find_matching_key(
    const VariableStorage &storage_value) const {
    if (!table_) return std::nullopt;
    db::IntegerField hash(db::FieldType::int64, storage_value.long_hash());
    const auto index = database_->get_index(variable_storage_table_name, hash_column);
    if (!index) {
        throw std::runtime_error("Ghidra Variable Storage hash index is missing");
    }
    for (const auto &primary_key : index->find_primary_keys(hash)) {
        const auto row = table_->record(*primary_key);
        if (row && row->field(storage_column).as_string() ==
                       storage_value.serialization()) {
            return row->key().as_integer();
        }
    }
    return std::nullopt;
}

std::optional<Address> VariableStorageManager::address_for(
    const VariableStorage &storage_value,
    bool create) {
    if (const auto key = find_matching_key(storage_value)) {
        return variable_space()->address(static_cast<std::uint64_t>(*key));
    }
    if (!create) return std::nullopt;
    require_mutation();
    if (!table_) {
        table_ = database_->create_table(
            variable_storage_table_name, current_schema(), {hash_column});
    }
    auto key = table_->next_long_key();
    if (key <= 0) key = 1;
    auto row = current_schema()->create_record(key);
    row->set_integer(hash_column, storage_value.long_hash());
    row->set_string(storage_column, storage_value.serialization());
    table_->put_record(*row);
    return variable_space()->address(static_cast<std::uint64_t>(key));
}

std::vector<VariableStorageRecord> VariableStorageManager::all() const {
    std::vector<VariableStorageRecord> result;
    if (!table_) return result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (!row) continue;
        const auto serialization = row->field(storage_column).as_string();
        if (!serialization) {
            throw std::runtime_error("Variable Storage record has null serialization");
        }
        result.push_back({row->key().as_integer(),
                          row->field(hash_column).as_integer(),
                          *serialization});
    }
    return result;
}

void VariableStorageManager::set_language(
    std::shared_ptr<AddressFactory> new_address_factory,
    const LanguageTranslator &translator) {
    if (!new_address_factory) {
        throw std::invalid_argument(
            "variable-storage language change requires an address factory");
    }
    require_mutation();
    if (&translator.old_address_factory() != address_factory_.get() ||
        &translator.new_address_factory() != new_address_factory.get()) {
        throw std::invalid_argument(
            "language translator address factories do not match Variable Storage");
    }
    if (!table_) {
        address_factory_ = std::move(new_address_factory);
        return;
    }

    struct StagedStorage {
        std::int64_t key{};
        std::int64_t hash{};
        std::string serialization;
    };
    std::vector<StagedStorage> staged;
    staged.reserve(static_cast<std::size_t>(table_->record_count()));
    for (const auto &record_value : all()) {
        const auto translated_serialization =
            VariableStorage::translate_serialization(
                *new_address_factory, translator,
                record_value.serialization);
        if (record_value.serialization == "<BAD>" ||
            record_value.serialization == "<UNASSIGNED>" ||
            record_value.serialization == "<VOID>" ||
            record_value.serialization.empty()) {
            staged.push_back({record_value.id, record_value.hash,
                              translated_serialization});
            continue;
        }
        const auto translated_storage = VariableStorage::deserialize(
            *new_address_factory, translated_serialization);
        staged.push_back({record_value.id,
                          translated_storage.long_hash(),
                          translated_serialization});
    }

    for (const auto &entry : staged) {
        auto row = current_schema()->create_record(entry.key);
        row->set_integer(hash_column, entry.hash);
        row->set_string(storage_column, entry.serialization);
        table_->put_record(*row);
    }
    address_factory_ = std::move(new_address_factory);
}

void VariableStorageManager::rebind_address_factory(
    std::shared_ptr<AddressFactory> address_factory) {
    if (!address_factory) {
        throw std::invalid_argument(
            "variable-storage address factory must not be null");
    }
    address_factory_ = std::move(address_factory);
    invalidate_cache();
}

void VariableStorageManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

void VariableStorageManager::invalidate_cache() {
    bind_existing_table(mode_ == ProgramOpenMode::read_only ||
                        mode_ == ProgramOpenMode::upgrade);
}

} // namespace llmghidra::program
