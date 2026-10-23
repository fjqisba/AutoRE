#include "llmghidra/program/legacy_function_upgrade.hpp"

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
namespace {

constexpr const char *stack_table_name = "Stack Variables";
constexpr const char *register_table_name = "Register Parameters";
constexpr const char *shared_ranges_table_name = "Shared Ranges - Functions";
constexpr const char *shared_map_table_name = "Shared Map - Functions";
constexpr const char *unused_function_variables_table_name = "Function Variables";
constexpr const char *unused_function_ranges_table_name = "Function Var Ranges";

[[nodiscard]] std::shared_ptr<db::Table> require_table(
    const std::shared_ptr<db::DatabaseHandle> &database,
    const char *name) {
    auto table = database->get_table(name);
    if (!table) {
        throw std::runtime_error(std::string("missing legacy function table: ") + name);
    }
    return table;
}

void require_schema(const db::Table &table,
                    const db::Schema &expected,
                    const char *name) {
    if (!table.schema().equals(expected)) {
        throw std::runtime_error(std::string("unsupported legacy schema: ") + name);
    }
}

[[nodiscard]] Address decode_required(PersistentAddressMap &address_map,
                                      std::uint64_t key,
                                      const char *context) {
    const Address address = address_map.decode(key);
    if (!address.is_valid()) {
        throw std::runtime_error(std::string(context) +
                                 " contains an undecodable address");
    }
    return address;
}

} // namespace

bool LegacyFunctionUpgrade::present(
    const std::shared_ptr<db::DatabaseHandle> &database) {
    return database && static_cast<bool>(database->get_table(function_table_name));
}

std::shared_ptr<db::Schema> LegacyFunctionUpgrade::function_schema(int version) {
    if (version != 0 && version != 1) {
        throw std::invalid_argument("unsupported legacy Functions version");
    }
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    std::vector<std::string> names{"Return DataType ID", "StackDepth",
                                   "StackParamOffset", "StackReturnOffset",
                                   "StackLocalSize"};
    if (version == 1) {
        fields.push_back(std::make_unique<db::StringField>());
        names.emplace_back("RepeatableComment");
    }
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Entry Point", std::move(fields), std::move(names));
}

std::shared_ptr<db::Schema> LegacyFunctionUpgrade::stack_schema(int version) {
    if (version != 0 && version != 1) {
        throw std::invalid_argument("unsupported legacy Stack Variables version");
    }
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    std::vector<std::string> names{"Function ID", "Offset", "DataType ID",
                                   "Name", "Comment"};
    if (version == 1) {
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        names.emplace_back("DataType Length");
    }
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Key", std::move(fields), std::move(names));
}

std::shared_ptr<db::Schema> LegacyFunctionUpgrade::register_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "Key",
        std::move(fields),
        std::vector<std::string>{"Function ID", "Register", "DataType ID",
                                 "Name", "Comment"});
}

std::shared_ptr<db::Schema> LegacyFunctionUpgrade::shared_range_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "From",
        std::move(fields), std::vector<std::string>{"To"});
}

std::shared_ptr<db::Schema> LegacyFunctionUpgrade::shared_map_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "Key",
        std::move(fields), std::vector<std::string>{"Value", "Range Key"});
}

LegacyFunctionUpgrade::LegacyFunctionUpgrade(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map)
    : database_(std::move(database)), address_map_(&address_map) {
    if (!database_) {
        throw std::invalid_argument("legacy function upgrade requires a database");
    }
    functions_ = require_table(database_, function_table_name);
    stack_variables_ = require_table(database_, stack_table_name);
    register_parameters_ = require_table(database_, register_table_name);
    shared_ranges_ = require_table(database_, shared_ranges_table_name);
    shared_map_ = require_table(database_, shared_map_table_name);

    function_version_ = functions_->schema().version();
    stack_version_ = stack_variables_->schema().version();
    require_schema(*functions_, *function_schema(function_version_),
                   function_table_name);
    require_schema(*stack_variables_, *stack_schema(stack_version_),
                   stack_table_name);
    require_schema(*register_parameters_, *register_schema(),
                   register_table_name);
    require_schema(*shared_ranges_, *shared_range_schema(),
                   shared_ranges_table_name);
    require_schema(*shared_map_, *shared_map_schema(), shared_map_table_name);
    const auto map_indexes = shared_map_->indexed_columns();
    if (map_indexes != std::vector<std::size_t>{0, 1}) {
        throw std::runtime_error(
            "legacy Shared Map - Functions index contract mismatch");
    }
}

AddressSet LegacyFunctionUpgrade::body(std::int64_t function_key) const {
    AddressSet result;
    auto iterator = shared_map_->iterator();
    while (iterator->has_next()) {
        const auto map_record = iterator->next();
        if (!map_record || map_record->field(0).as_integer() != function_key) {
            continue;
        }
        const auto range_record = shared_ranges_->record(
            map_record->field(1).as_integer());
        if (!range_record) {
            throw std::runtime_error(
                "legacy function map references a missing shared range");
        }
        const auto start_key = std::bit_cast<std::uint64_t>(
            range_record->key().as_integer());
        const auto end_key = std::bit_cast<std::uint64_t>(
            range_record->field(0).as_integer());
        const Address start = decode_required(*address_map_, start_key,
                                              "legacy function body");
        const Address end = decode_required(*address_map_, end_key,
                                            "legacy function body");
        result.add(start, end);
    }
    return result;
}

std::vector<LegacyStackVariableRecord>
LegacyFunctionUpgrade::stack_variables(std::int64_t function_key) const {
    std::vector<LegacyStackVariableRecord> result;
    auto iterator = stack_variables_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record || record->field(0).as_integer() != function_key) continue;
        result.push_back(
            {record->key().as_integer(),
             static_cast<std::int32_t>(record->field(1).as_integer()),
             record->field(2).as_integer(),
             stack_version_ == 1
                 ? static_cast<std::int32_t>(record->field(5).as_integer())
                 : 1,
             record->field(3).as_string().value_or(std::string{}),
             record->field(4).as_string()});
    }
    return result;
}

std::vector<LegacyRegisterParameterRecord>
LegacyFunctionUpgrade::register_parameters(std::int64_t function_key) const {
    std::vector<LegacyRegisterParameterRecord> result;
    auto iterator = register_parameters_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record || record->field(0).as_integer() != function_key) continue;
        result.push_back(
            {record->key().as_integer(),
             record->field(1).as_string().value_or(std::string{}),
             record->field(2).as_integer(),
             record->field(3).as_string().value_or(std::string{}),
             record->field(4).as_string()});
    }
    return result;
}

std::vector<LegacyFunctionRecord> LegacyFunctionUpgrade::records() const {
    std::vector<LegacyFunctionRecord> result;
    auto iterator = functions_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record) continue;
        LegacyFunctionRecord value;
        value.old_entry_key = std::bit_cast<std::uint64_t>(
            record->key().as_integer());
        value.entry = decode_required(*address_map_, value.old_entry_key,
                                      "legacy Functions key");
        value.return_data_type_id = record->field(0).as_integer();
        value.stack_depth = static_cast<std::int32_t>(
            record->field(1).as_integer());
        value.stack_parameter_offset = static_cast<std::int32_t>(
            record->field(2).as_integer());
        value.stack_return_offset = static_cast<std::int32_t>(
            record->field(3).as_integer());
        value.stack_local_size = static_cast<std::int32_t>(
            record->field(4).as_integer());
        value.repeatable_comment = function_version_ == 1
                                       ? record->field(5).as_string()
                                       : std::optional<std::string>(std::string{});
        value.body = body(record->key().as_integer());
        value.stack_variables = stack_variables(record->key().as_integer());
        value.register_parameters = register_parameters(record->key().as_integer());
        result.push_back(std::move(value));
    }
    return result;
}

void LegacyFunctionUpgrade::delete_source_tables() {
    database_->check_transaction();
    for (const char *name : {shared_ranges_table_name, shared_map_table_name,
                             function_table_name, stack_table_name,
                             register_table_name,
                             unused_function_variables_table_name,
                             unused_function_ranges_table_name}) {
        if (database_->get_table(name) && !database_->delete_table(name)) {
            throw std::runtime_error(std::string("failed to delete legacy table: ") +
                                     name);
        }
    }
}

} // namespace llmghidra::program
