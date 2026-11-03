#include "llmghidra/program/legacy_variable_storage_upgrade.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <bit>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {

bool LegacyVariableStorageUpgrade::present(
    const std::shared_ptr<db::DatabaseHandle> &database) {
    return database && static_cast<bool>(database->get_table(table_name));
}

std::shared_ptr<db::Schema> LegacyVariableStorageUpgrade::schema(int version) {
    if (version != 0 && version != 1) {
        throw std::invalid_argument(
            "unsupported legacy VariableStorage schema version");
    }
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Key", std::move(fields),
        std::vector<std::string>{"Address", "NamespaceID", "SymCount"});
}

LegacyVariableStorageUpgrade::LegacyVariableStorageUpgrade(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map)
    : database_(std::move(database)), address_map_(&address_map) {
    if (!database_) {
        throw std::invalid_argument(
            "legacy variable storage upgrade requires a database");
    }
    table_ = database_->get_table(table_name);
    if (!table_) {
        throw std::runtime_error("missing legacy VariableStorage table");
    }
    const int version = table_->schema().version();
    if (!table_->schema().equals(*schema(version))) {
        throw std::runtime_error("unsupported legacy VariableStorage schema");
    }
    // OldVariableStorageDBAdapterV0V1 only constrains the schema version.  Its
    // namespace lookup uses Table.findRecords(), which remains valid when the
    // historical table has no physical NamespaceID index.  Keep this adapter
    // equally permissive and scan in_namespace() below so real V0/V1 projects
    // are not rejected solely because an optional accelerator is absent.
}

LegacyVariableStorageRecord LegacyVariableStorageUpgrade::decode(
    const db::Record &record) const {
    const auto old_key = std::bit_cast<std::uint64_t>(
        record.field(0).as_integer());
    const Address storage = address_map_->decode(old_key);
    if (!storage.is_valid()) {
        throw std::runtime_error(
            "legacy VariableStorage row contains an undecodable address");
    }
    return {record.key().as_integer(), old_key, storage,
            record.field(1).as_integer(),
            static_cast<std::int32_t>(record.field(2).as_integer())};
}

std::vector<LegacyVariableStorageRecord>
LegacyVariableStorageUpgrade::records() const {
    std::vector<LegacyVariableStorageRecord> result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        if (const auto row = iterator->next()) result.push_back(decode(*row));
    }
    return result;
}

std::optional<LegacyVariableStorageRecord>
LegacyVariableStorageUpgrade::record(std::int64_t variable_id) const {
    const auto row = table_->record(variable_id);
    return row ? std::optional<LegacyVariableStorageRecord>(decode(*row))
               : std::nullopt;
}

std::vector<LegacyVariableStorageRecord>
LegacyVariableStorageUpgrade::in_namespace(std::int64_t namespace_id) const {
    std::vector<LegacyVariableStorageRecord> result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (row && row->field(1).as_integer() == namespace_id) {
            result.push_back(decode(*row));
        }
    }
    return result;
}

void LegacyVariableStorageUpgrade::delete_source_table() {
    database_->check_transaction();
    if (database_->get_table(table_name) &&
        !database_->delete_table(table_name)) {
        throw std::runtime_error(
            "failed to delete legacy VariableStorage table");
    }
}

} // namespace llmghidra::program
