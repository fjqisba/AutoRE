#include "llmghidra/program/data_type_manager.hpp"

#include "llmghidra/db/field.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/program_architecture.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cctype>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr std::size_t table_count =
    static_cast<std::size_t>(DataTypeTable::instance_setting_names) + 1;

[[nodiscard]] std::vector<std::unique_ptr<db::Field>> fields(
    std::initializer_list<db::FieldType> types) {
    std::vector<std::unique_ptr<db::Field>> result;
    result.reserve(types.size());
    for (const auto type : types) result.push_back(db::make_field(type));
    return result;
}

[[nodiscard]] std::shared_ptr<db::Schema> schema(
    int version,
    db::FieldType key_type,
    std::string key_name,
    std::initializer_list<db::FieldType> field_types,
    std::vector<std::string> field_names) {
    return std::make_shared<db::Schema>(
        version, db::make_field(key_type), std::move(key_name),
        fields(field_types), std::move(field_names));
}

[[nodiscard]] std::int64_t now_millis() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] std::unique_ptr<db::Record> get_record(
    const std::shared_ptr<db::Table> &table,
    std::int64_t id) {
    if (table->schema().key_type().type() == db::FieldType::int64) {
        return table->record(id);
    }
    db::IntegerField key(table->schema().key_type().type(), id);
    return table->record(key);
}

[[nodiscard]] bool erase_record(const std::shared_ptr<db::Table> &table,
                                std::int64_t id) {
    if (table->schema().key_type().type() == db::FieldType::int64) {
        return table->delete_record(id);
    }
    db::IntegerField key(table->schema().key_type().type(), id);
    return table->delete_record(key);
}

[[nodiscard]] bool ends_with_decimal_conflict_suffix(const std::string &name,
                                                     std::size_t suffix_at) {
    constexpr std::string_view suffix = ".conflict";
    if (name.compare(suffix_at, suffix.size(), suffix) != 0) return false;
    std::size_t cursor = suffix_at + suffix.size();
    if (cursor == name.size()) return true;
    if (name[cursor] == '_') ++cursor;
    if (cursor == name.size()) return false;
    return std::all_of(name.begin() + static_cast<std::ptrdiff_t>(cursor), name.end(),
                       [](unsigned char value) { return std::isdigit(value) != 0; });
}

[[nodiscard]] std::string conflict_base_name(const std::string &name) {
    constexpr std::string_view suffix = ".conflict";
    auto offset = name.rfind(suffix);
    if (offset != std::string::npos && ends_with_decimal_conflict_suffix(name, offset)) {
        return name.substr(0, offset);
    }
    return name;
}

[[nodiscard]] std::int64_t next_local_universal_id() noexcept {
    // Native equivalent of UniversalIdGenerator: 43 time bits, a 16-bit
    // process session discriminator and five per-millisecond sequence bits.
    static std::mutex mutex;
    static const std::uint64_t session =
        (static_cast<std::uint64_t>(now_millis()) >> 4U) & 0xffffULL;
    static std::uint64_t base_time = 0;
    static std::uint64_t id_base = 0;
    static std::uint32_t instance_count = 32;
    std::scoped_lock lock(mutex);
    if (instance_count >= 32) {
        auto current = static_cast<std::uint64_t>(now_millis());
        if (current <= base_time) current = base_time + 1;
        base_time = current;
        id_base = (base_time << 21U) | (session << 5U);
        instance_count = 0;
    }
    return std::bit_cast<std::int64_t>(id_base + instance_count++);
}

enum class LegacyDataTypeSchema {
    current,
    missing,
    array_v0,
    pointer_v0,
    pointer_v1,
    typedef_v0,
    typedef_v1,
    composite_v0,
    composite_v1,
    composite_v2_v4,
    composite_v5,
    function_definition_v0,
    function_definition_v1,
    function_parameter_v0,
    enumeration_v0,
    enumeration_value_v0,
    settings_v0,
};

[[nodiscard]] bool schema_matches(
    const db::Table &table,
    int version,
    db::FieldType key_type,
    const std::string &key_name,
    std::initializer_list<db::FieldType> field_types,
    std::vector<std::string> field_names) {
    const auto candidate = schema(version, key_type, key_name, field_types,
                                  std::move(field_names));
    return table.schema().equals(*candidate);
}

[[nodiscard]] bool historically_optional(DataTypeTable id) noexcept {
    switch (id) {
    case DataTypeTable::calling_conventions:
    case DataTypeTable::function_definitions:
    case DataTypeTable::function_parameters:
    case DataTypeTable::enumerations:
    case DataTypeTable::enumeration_values:
    case DataTypeTable::source_archives:
    case DataTypeTable::parent_child:
    case DataTypeTable::default_setting_names:
    case DataTypeTable::instance_setting_names:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] LegacyDataTypeSchema classify_legacy_schema(
    DataTypeTable id,
    const std::shared_ptr<db::Table> &table,
    const db::Schema &current_schema) {
    using F = db::FieldType;
    if (!table) {
        if (historically_optional(id)) return LegacyDataTypeSchema::missing;
        throw std::runtime_error("missing Ghidra data-type table");
    }
    if (table->schema().equals(current_schema)) {
        return LegacyDataTypeSchema::current;
    }
    switch (id) {
    case DataTypeTable::arrays:
        if (schema_matches(*table, 0, F::int64, "Array ID",
                           {F::int64, F::int32, F::int32},
                           {"Data Type ID", "Dimension", "Length"})) {
            return LegacyDataTypeSchema::array_v0;
        }
        break;
    case DataTypeTable::pointers:
        if (schema_matches(*table, 0, F::int64, "Pointer ID",
                           {F::int64, F::int32},
                           {"Data Type ID", "Size"})) {
            return LegacyDataTypeSchema::pointer_v0;
        }
        if (schema_matches(*table, 1, F::int64, "Pointer ID",
                           {F::int64, F::int64},
                           {"Data Type ID", "Category ID"})) {
            return LegacyDataTypeSchema::pointer_v1;
        }
        break;
    case DataTypeTable::typedefs:
        if (schema_matches(*table, 0, F::int64, "Typedef ID",
                           {F::int64, F::string, F::int64},
                           {"Data Type ID", "Name", "Category ID"})) {
            return LegacyDataTypeSchema::typedef_v0;
        }
        if (schema_matches(
                *table, 1, F::int64, "Typedef ID",
                {F::int64, F::string, F::int64, F::int64, F::int64,
                 F::int64, F::int64},
                {"Data Type ID", "Name", "Category ID", "Source Archive ID",
                 "Universal Data Type ID", "Source Sync Time",
                 "Last Change Time"})) {
            return LegacyDataTypeSchema::typedef_v1;
        }
        break;
    case DataTypeTable::composites:
        if (schema_matches(*table, 0, F::int64, "Data Type ID",
                           {F::string, F::string, F::boolean, F::int64,
                            F::int32, F::int32},
                           {"Name", "Comment", "Is Union", "Category ID",
                            "Length", "Number Of Components"})) {
            return LegacyDataTypeSchema::composite_v0;
        }
        if (schema_matches(
                *table, 1, F::int64, "Data Type ID",
                {F::string, F::string, F::boolean, F::int64, F::int32,
                 F::int32, F::int64, F::int64, F::int64, F::int64},
                {"Name", "Comment", "Is Union", "Category ID", "Length",
                 "Number Of Components", "Source Archive ID",
                 "Source Data Type ID", "Source Sync Time",
                 "Last Change Time"})) {
            return LegacyDataTypeSchema::composite_v1;
        }
        if (table->schema().version() >= 2 && table->schema().version() <= 4 &&
            schema_matches(
                *table, table->schema().version(), F::int64, "Data Type ID",
                {F::string, F::string, F::boolean, F::int64, F::int32,
                 F::int32, F::int64, F::int64, F::int64, F::int64,
                 F::int32, F::int32},
                {"Name", "Comment", "Is Union", "Category ID", "Length",
                 "Number Of Components", "Source Archive ID",
                 "Source Data Type ID", "Source Sync Time", "Last Change Time",
                 "Pack", "MinAlign"})) {
            return LegacyDataTypeSchema::composite_v2_v4;
        }
        if (schema_matches(
                *table, 5, F::int64, "Data Type ID",
                {F::string, F::string, F::boolean, F::int64, F::int32,
                 F::int32, F::int32, F::int64, F::int64, F::int64,
                 F::int64, F::int32, F::int32},
                {"Name", "Comment", "Is Union", "Category ID", "Length",
                 "Alignment", "Number Of Components", "Source Archive ID",
                 "Source Data Type ID", "Source Sync Time", "Last Change Time",
                 "Pack", "MinAlign"})) {
            return LegacyDataTypeSchema::composite_v5;
        }
        break;
    case DataTypeTable::function_definitions:
        if (schema_matches(*table, 0, F::int64, "Data Type ID",
                           {F::string, F::string, F::int64, F::int64, F::byte},
                           {"Name", "Comment", "Category ID", "Return Type ID",
                            "Flags"})) {
            return LegacyDataTypeSchema::function_definition_v0;
        }
        if (schema_matches(
                *table, 1, F::int64, "Data Type ID",
                {F::string, F::string, F::int64, F::int64, F::byte,
                 F::int64, F::int64, F::int64, F::int64},
                {"Name", "Comment", "Category ID", "Return Type ID", "Flags",
                 "Source Archive ID", "Source Data Type ID", "Source Sync Time",
                 "Last Change Time"})) {
            return LegacyDataTypeSchema::function_definition_v1;
        }
        break;
    case DataTypeTable::function_parameters:
        if (schema_matches(
                *table, 0, F::int64, "Parameter ID",
                {F::int64, F::int64, F::string, F::string, F::int32},
                {"Parent ID", "Data Type ID", "Name", "Comment", "Ordinal"})) {
            return LegacyDataTypeSchema::function_parameter_v0;
        }
        break;
    case DataTypeTable::enumerations:
        if (schema_matches(*table, 0, F::int64, "Enum ID",
                           {F::string, F::string, F::int64, F::byte},
                           {"Name", "Comment", "Category ID", "Size"})) {
            return LegacyDataTypeSchema::enumeration_v0;
        }
        break;
    case DataTypeTable::enumeration_values:
        if (schema_matches(*table, 0, F::int64, "Enum Value ID",
                           {F::string, F::int64, F::int64},
                           {"Name", "Value", "Enum ID"})) {
            return LegacyDataTypeSchema::enumeration_value_v0;
        }
        break;
    case DataTypeTable::default_settings:
    case DataTypeTable::instance_settings:
        if (schema_matches(
                *table, 0, F::int64, "SettingsID",
                {F::int64, F::string, F::int64, F::string, F::binary},
                {"AssociationID", "Settings Name", "Long Value", "String Value",
                 "Byte Value"})) {
            return LegacyDataTypeSchema::settings_v0;
        }
        break;
    default:
        break;
    }
    throw std::runtime_error("unsupported Ghidra data-type table schema");
}

void copy_columns(const db::Record &source, db::Record &destination) {
    if (source.column_count() != destination.column_count()) {
        throw std::invalid_argument("record column counts differ during data-type migration");
    }
    for (std::size_t column = 0; column < source.column_count(); ++column) {
        destination.set_field(column, source.field_copy(column));
    }
}

} // namespace

struct DataTypeManager::TableSlot {
    DataTypeTable id{};
    std::string name;
    std::shared_ptr<db::Schema> expected_schema;
    std::vector<std::size_t> indexes;
    std::optional<DataTypeKind> data_type_kind;
    std::shared_ptr<db::Table> table;
};

std::vector<std::unique_ptr<DataTypeManager::TableSlot>>
DataTypeManager::table_descriptors() {
    using T = DataTypeTable;
    using K = DataTypeKind;
    using F = db::FieldType;
    std::vector<std::unique_ptr<DataTypeManager::TableSlot>> result(table_count);
    auto add = [&](T id, std::string name, std::shared_ptr<db::Schema> expected,
                   std::vector<std::size_t> indexes = {},
                   std::optional<K> kind = std::nullopt) {
        auto value = std::make_unique<DataTypeManager::TableSlot>();
        value->id = id;
        value->name = std::move(name);
        value->expected_schema = std::move(expected);
        value->indexes = std::move(indexes);
        value->data_type_kind = kind;
        result[static_cast<std::size_t>(id)] = std::move(value);
    };

    add(T::categories, "Categories",
        schema(0, F::int64, "Category ID", {F::string, F::int64},
               {"Name", "Parent ID"}), {1});
    add(T::builtins, "Built-in datatypes",
        schema(0, F::int64, "Data Type ID", {F::string, F::string, F::int64},
               {"Name", "Class Name", "Category ID"}), {2}, K::builtin);
    add(T::arrays, "Arrays",
        schema(1, F::int64, "Array ID", {F::int64, F::int32, F::int32, F::int64},
               {"Data Type ID", "Dimension", "Length", "Cat ID"}),
        {3}, K::array);
    add(T::pointers, "Pointers",
        schema(2, F::int64, "Pointer ID", {F::int64, F::int64, F::byte},
               {"Data Type ID", "Category ID", "Length"}),
        {1}, K::pointer);
    add(T::typedefs, "Typedefs",
        schema(2, F::int64, "Typedef ID",
               {F::int64, F::int16, F::string, F::int64, F::int64, F::int64,
                F::int64, F::int64},
               {"Data Type ID", "Flags", "Name", "Category ID",
                "Source Archive ID", "Universal Data Type ID", "Source Sync Time",
                "Last Change Time"}),
        {3, 5}, K::typedef_type);
    add(T::composites, "Composite Data Types",
        schema(6, F::int64, "Data Type ID",
               {F::string, F::string, F::boolean, F::int64, F::int32, F::int32,
                F::int32, F::int64, F::int64, F::int64, F::int64, F::int32,
                F::int32},
               {"Name", "Comment", "Is Union", "Category ID", "Length",
                "Alignment", "Number Of Components", "Source Archive ID",
                "Source Data Type ID", "Source Sync Time", "Last Change Time",
                "Pack", "MinAlign"}),
        {3, 8}, K::composite);
    add(T::components, "Component Data Types",
        schema(0, F::int64, "Data Type ID",
               {F::int64, F::int32, F::int64, F::string, F::string, F::int32,
                F::int32},
               {"Parent", "Offset", "Data Type ID", "Field Name", "Comment",
                "Component Size", "Ordinal"}),
        {0}, K::component);
    add(T::function_definitions, "Function Definitions",
        schema(2, F::int64, "Data Type ID",
               {F::string, F::string, F::int64, F::int64, F::byte, F::byte,
                F::int64, F::int64, F::int64, F::int64},
               {"Name", "Comment", "Category ID", "Return Type ID", "Flags",
                "Call Conv ID", "Source Archive ID", "Source Data Type ID",
                "Source Sync Time", "Last Change Time"}),
        {2, 7}, K::function_definition);
    add(T::function_parameters, "Function Parameters",
        schema(1, F::int64, "Parameter ID",
               {F::int64, F::int64, F::string, F::string, F::int32, F::int32},
               {"Parent ID", "Data Type ID", "Name", "Comment", "Ordinal",
                "Data Type Length"}),
        {0}, K::function_parameter);
    add(T::enumerations, "Enumeration Data Types",
        schema(1, F::int64, "Enum ID",
               {F::string, F::string, F::int64, F::byte, F::int64, F::int64,
                F::int64, F::int64},
               {"Name", "Comment", "Category ID", "Size", "Source Archive ID",
                "Source Data Type ID", "Source Sync Time", "Last Change Time"}),
        {2, 5}, K::enumeration);
    add(T::enumeration_values, "Enumeration Values",
        schema(1, F::int64, "Enum Value ID",
               {F::string, F::int64, F::int64, F::string},
               {"Name", "Value", "Enum ID", "Comment"}), {2});
    add(T::calling_conventions, "Calling Conventions",
        schema(0, F::byte, "ID", {F::string}, {"Name"}));
    add(T::source_archives, "Data Type Archive IDs",
        schema(0, F::int64, "Archive ID",
               {F::string, F::string, F::byte, F::int64, F::boolean},
               {"Domain File ID", "Name", "Type", "Last Sync Time", "Dirty Flag"}));
    add(T::parent_child, "DT_PARENT_CHILD",
        schema(0, F::int64, "KEY", {F::int64, F::int64},
               {"Parent ID", "Child ID"}), {0, 1});
    add(T::default_settings, "Default Settings",
        schema(1, F::int64, "SettingsID",
               {F::int64, F::int16, F::int64, F::string},
               {"AssociationID", "Settings Name Index", "Long Value", "String Value"}),
        {0});
    add(T::default_setting_names, "Default Settings Names",
        schema(1, F::int64, "NameIndex", {F::string}, {"Settings Name"}));
    add(T::instance_settings, "Instance Settings",
        schema(1, F::int64, "SettingsID",
               {F::int64, F::int16, F::int64, F::string},
               {"AssociationID", "Settings Name Index", "Long Value", "String Value"}),
        {0});
    add(T::instance_setting_names, "Instance Settings Names",
        schema(1, F::int64, "NameIndex", {F::string}, {"Settings Name"}));
    return result;
}

DataTypeManager::DataTypeManager(std::shared_ptr<db::DatabaseHandle> database,
                                 ProgramOpenMode mode,
                                 bool create,
                                 PersistentAddressMap *address_map,
                                 const ProgramArchitecture *architecture)
    : database_(std::move(database)), address_map_(address_map),
      architecture_(architecture), mode_(mode),
      tables_(table_descriptors()) {
    if (!database_) throw std::invalid_argument("data-type manager requires a database");
    if (create) {
        create_tables();
    }
    else {
        const bool missing_properties = !database_->get_table("DataTypeManager");
        std::int32_t stored_version = 1;
        if (missing_properties && mode_ == ProgramOpenMode::update) {
            throw std::runtime_error("data-type manager requires schema upgrade");
        }
        if (missing_properties && mode_ == ProgramOpenMode::read_only) {
            auto &scratch = database_->scratch_database();
            auto scratch_owner = std::shared_ptr<db::DatabaseHandle>(
                &scratch, [](db::DatabaseHandle *) {});
            properties_ = std::make_unique<StringMap>(
                std::move(scratch_owner), "DataTypeManager", true);
        }
        else if (!missing_properties) {
            properties_ = std::make_unique<StringMap>(
                database_, "DataTypeManager", false);
            stored_version = properties_->get_int("DB Version", 1);
        }
        if (stored_version > manager_database_version) {
            throw std::runtime_error("data-type manager schema is newer than supported");
        }
        if (stored_version < manager_database_version && mode_ == ProgramOpenMode::update) {
            throw std::runtime_error("data-type manager requires schema upgrade");
        }
        open_tables();
        if (missing_properties && mode_ == ProgramOpenMode::upgrade) {
            properties_ = std::make_unique<StringMap>(
                database_, "DataTypeManager", true);
        }
        if (mode_ == ProgramOpenMode::upgrade &&
            (missing_properties || stored_version < manager_database_version)) {
            properties_->put("DB Version", std::to_string(manager_database_version));
            properties_->put("GHIDRA Version", "12.1.3");
        }
    }
}

void DataTypeManager::create_tables() {
    // Preserve DataTypeManagerDB.initializeAdapters() creation order. Besides
    // logical compatibility, table/root allocation order is observable in raw
    // Program DB fixtures and must not depend on this enum's declaration order.
    constexpr DataTypeTable adapter_order[] = {
        DataTypeTable::calling_conventions,
        DataTypeTable::builtins,
        DataTypeTable::categories,
        DataTypeTable::arrays,
        DataTypeTable::typedefs,
        DataTypeTable::composites,
        DataTypeTable::components,
        DataTypeTable::function_definitions,
        DataTypeTable::function_parameters,
        DataTypeTable::default_settings,
        DataTypeTable::default_setting_names,
        DataTypeTable::pointers,
        DataTypeTable::enumerations,
        DataTypeTable::enumeration_values,
        DataTypeTable::parent_child,
        DataTypeTable::source_archives,
    };
    for (const auto id : adapter_order) {
        auto &entry = tables_.at(static_cast<std::size_t>(id));
        entry->table = database_->create_table(entry->name, entry->expected_schema,
                                               entry->indexes);
    }
    auto local_archive = slot(DataTypeTable::source_archives)
                             .expected_schema->create_record(local_archive_id);
    local_archive->set_integer(3, now_millis());
    local_archive->set_boolean(4, false);
    slot(DataTypeTable::source_archives).table->put_record(*local_archive);

    // DataTypeManagerDB writes its version map only after every core adapter.
    properties_ = std::make_unique<StringMap>(database_, "DataTypeManager", true);
    properties_->put("DB Version", std::to_string(manager_database_version));
    properties_->put("GHIDRA Version", "12.1.3");

    // ProgramBasedDataTypeManagerDB installs instance settings after the base
    // DataTypeManagerDB constructor has completed.
    for (const auto id : {DataTypeTable::instance_settings,
                          DataTypeTable::instance_setting_names}) {
        auto &entry = tables_.at(static_cast<std::size_t>(id));
        entry->table = database_->create_table(entry->name, entry->expected_schema,
                                               entry->indexes);
    }
}

void DataTypeManager::open_tables() {
    std::array<LegacyDataTypeSchema, table_count> legacy{};
    std::array<std::shared_ptr<db::Table>, table_count> source{};
    std::array<std::shared_ptr<db::Table>, table_count> staged{};
    std::array<bool, table_count> needs_staging{};
    bool migration_required = false;

    for (std::size_t index = 0; index < tables_.size(); ++index) {
        auto &entry = *tables_[index];
        source[index] = database_->get_table(entry.name);
        try {
            legacy[index] = classify_legacy_schema(
                entry.id, source[index], *entry.expected_schema);
        }
        catch (const std::exception &error) {
            throw std::runtime_error("unsupported schema for Ghidra data-type table '" +
                                     entry.name + "': " + error.what());
        }
        needs_staging[index] = legacy[index] != LegacyDataTypeSchema::current;
        migration_required = migration_required || needs_staging[index];
    }

    const auto index_of = [](DataTypeTable id) {
        return static_cast<std::size_t>(id);
    };
    const auto require_settings_name_pair = [&](DataTypeTable values,
                                                DataTypeTable names) {
        const auto value_index = index_of(values);
        const auto name_index = index_of(names);
        if (legacy[value_index] == LegacyDataTypeSchema::settings_v0) {
            if (source[name_index] &&
                !source[name_index]->schema().equals(
                    *tables_[name_index]->expected_schema)) {
                throw std::runtime_error(
                    "legacy settings table has an incompatible names table");
            }
            needs_staging[name_index] = true;
            migration_required = true;
            return;
        }
        if (legacy[value_index] == LegacyDataTypeSchema::current &&
            !source[name_index]) {
            throw std::runtime_error(
                "current settings table is missing its names table");
        }
    };
    require_settings_name_pair(DataTypeTable::default_settings,
                               DataTypeTable::default_setting_names);
    require_settings_name_pair(DataTypeTable::instance_settings,
                               DataTypeTable::instance_setting_names);

    // Ghidra forces an Instance Settings rewrite whenever AddressMapDB has
    // just been upgraded, even when the settings schema itself is already V1.
    const bool rekey_instance_settings =
        mode_ == ProgramOpenMode::upgrade && address_map_ &&
        address_map_->upgraded();
    if (rekey_instance_settings) {
        needs_staging[index_of(DataTypeTable::instance_settings)] = true;
        needs_staging[index_of(DataTypeTable::instance_setting_names)] = true;
        migration_required = true;
    }

    // V1 function definitions stored a generic convention ordinal inside the
    // flags byte. A normalized current-schema view needs a real convention
    // table and stable IDs in both READ_ONLY and UPGRADE modes.
    if (legacy[index_of(DataTypeTable::function_definitions)] ==
        LegacyDataTypeSchema::function_definition_v1) {
        needs_staging[index_of(DataTypeTable::calling_conventions)] = true;
        migration_required = true;
    }

    const bool migrate_v5_flex_arrays =
        legacy[index_of(DataTypeTable::composites)] ==
        LegacyDataTypeSchema::composite_v5;
    if (migrate_v5_flex_arrays) {
        needs_staging[index_of(DataTypeTable::arrays)] = true;
        needs_staging[index_of(DataTypeTable::components)] = true;
        needs_staging[index_of(DataTypeTable::parent_child)] = true;
        migration_required = true;
    }

    if (!migration_required) {
        for (std::size_t index = 0; index < tables_.size(); ++index) {
            tables_[index]->table = source[index];
        }
        return;
    }
    if (mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("data-type manager requires schema upgrade");
    }

    auto &scratch = database_->scratch_database();
    for (std::size_t index = 0; index < tables_.size(); ++index) {
        if (!needs_staging[index]) continue;
        const auto staging_name = "__LLMGHIDRA_DTM_" + std::to_string(index);
        if (scratch.get_table(staging_name)) {
            if (!scratch.delete_table(staging_name)) {
                throw std::runtime_error("failed to reset data-type staging table");
            }
        }
        staged[index] = scratch.create_table(
            staging_name, tables_[index]->expected_schema,
            tables_[index]->indexes);
    }

    const auto selected_table = [&](DataTypeTable id) -> std::shared_ptr<db::Table> {
        const auto index = index_of(id);
        return staged[index] ? staged[index] : source[index];
    };
    const auto translate_record = [&](std::size_t index,
                                      const db::Record &old_record) {
        auto value = tables_[index]->expected_schema->create_record(
            old_record.key().clone());
        const auto kind = legacy[index];
        switch (kind) {
        case LegacyDataTypeSchema::current:
        case LegacyDataTypeSchema::composite_v5:
            copy_columns(old_record, *value);
            break;
        case LegacyDataTypeSchema::array_v0:
            value->set_integer(0, old_record.field(0).as_integer());
            value->set_integer(1, old_record.field(1).as_integer());
            value->set_integer(2, old_record.field(2).as_integer());
            value->set_integer(3, root_category_id);
            break;
        case LegacyDataTypeSchema::pointer_v0:
            value->set_integer(0, old_record.field(0).as_integer());
            value->set_integer(1, root_category_id);
            value->set_integer(2, -1);
            break;
        case LegacyDataTypeSchema::pointer_v1:
            value->set_integer(0, old_record.field(0).as_integer());
            value->set_integer(1, old_record.field(1).as_integer());
            value->set_integer(2, -1);
            break;
        case LegacyDataTypeSchema::typedef_v0:
            value->set_integer(0, old_record.field(0).as_integer());
            value->set_integer(1, 0);
            value->set_string(2, old_record.field(1).as_string());
            value->set_integer(3, old_record.field(2).as_integer());
            value->set_integer(4, local_archive_id);
            value->set_integer(5, next_local_universal_id());
            value->set_integer(6, 0);
            value->set_integer(7, 0);
            break;
        case LegacyDataTypeSchema::typedef_v1:
            value->set_integer(0, old_record.field(0).as_integer());
            value->set_integer(1, 0);
            value->set_string(2, old_record.field(1).as_string());
            value->set_integer(3, old_record.field(2).as_integer());
            for (std::size_t column = 3; column <= 6; ++column) {
                value->set_integer(column + 1,
                                   old_record.field(column).as_integer());
            }
            break;
        case LegacyDataTypeSchema::composite_v0:
            value->set_string(0, old_record.field(0).as_string());
            value->set_string(1, old_record.field(1).as_string());
            value->set_boolean(2, old_record.field(2).as_boolean());
            value->set_integer(3, old_record.field(3).as_integer());
            value->set_integer(4, old_record.field(4).as_integer());
            // V0's fixed translator left the newly introduced alignment field
            // at the schema default (zero), unlike V1-V4 which use -1.
            value->set_integer(5, 0);
            value->set_integer(6, old_record.field(5).as_integer());
            value->set_integer(7, local_archive_id);
            value->set_integer(8, next_local_universal_id());
            value->set_integer(9, 0);
            value->set_integer(10, 0);
            value->set_integer(11, CompositeDataType::no_packing);
            value->set_integer(12, CompositeDataType::default_alignment);
            break;
        case LegacyDataTypeSchema::composite_v1:
            value->set_string(0, old_record.field(0).as_string());
            value->set_string(1, old_record.field(1).as_string());
            value->set_boolean(2, old_record.field(2).as_boolean());
            value->set_integer(3, old_record.field(3).as_integer());
            value->set_integer(4, old_record.field(4).as_integer());
            value->set_integer(5, -1);
            value->set_integer(6, old_record.field(5).as_integer());
            for (std::size_t column = 6; column <= 9; ++column) {
                value->set_integer(column + 1,
                                   old_record.field(column).as_integer());
            }
            value->set_integer(11, CompositeDataType::no_packing);
            value->set_integer(12, CompositeDataType::default_alignment);
            break;
        case LegacyDataTypeSchema::composite_v2_v4:
            value->set_string(0, old_record.field(0).as_string());
            value->set_string(1, old_record.field(1).as_string());
            value->set_boolean(2, old_record.field(2).as_boolean());
            value->set_integer(3, old_record.field(3).as_integer());
            value->set_integer(4, old_record.field(4).as_integer());
            value->set_integer(5, -1);
            value->set_integer(6, old_record.field(5).as_integer());
            for (std::size_t column = 6; column <= 9; ++column) {
                value->set_integer(column + 1,
                                   old_record.field(column).as_integer());
            }
            value->set_integer(11, old_record.field(10).as_integer());
            value->set_integer(12, old_record.field(11).as_integer());
            break;
        case LegacyDataTypeSchema::function_definition_v0:
            value->set_string(0, old_record.field(0).as_string());
            value->set_string(1, old_record.field(1).as_string());
            value->set_integer(2, old_record.field(2).as_integer());
            value->set_integer(3, old_record.field(3).as_integer());
            value->set_integer(4, old_record.field(4).as_integer());
            value->set_integer(5, 0);
            value->set_integer(6, local_archive_id);
            value->set_integer(7, next_local_universal_id());
            value->set_integer(8, 0);
            value->set_integer(9, 0);
            break;
        case LegacyDataTypeSchema::function_parameter_v0:
            for (std::size_t column = 0; column < 5; ++column) {
                value->set_field(column, old_record.field_copy(column));
            }
            value->set_integer(5, 1);
            break;
        case LegacyDataTypeSchema::enumeration_v0:
            for (std::size_t column = 0; column < 4; ++column) {
                value->set_field(column, old_record.field_copy(column));
            }
            value->set_integer(4, local_archive_id);
            value->set_integer(5, next_local_universal_id());
            value->set_integer(6, 0);
            value->set_integer(7, 0);
            break;
        case LegacyDataTypeSchema::enumeration_value_v0:
            for (std::size_t column = 0; column < 3; ++column) {
                value->set_field(column, old_record.field_copy(column));
            }
            value->set_null(3);
            break;
        case LegacyDataTypeSchema::function_definition_v1:
        case LegacyDataTypeSchema::settings_v0:
        case LegacyDataTypeSchema::missing:
            throw std::logic_error("data-type record requires coordinated translation");
        }
        return value;
    };

    // Calling conventions must be populated before V1 function definitions
    // are translated, because their generic ordinals allocate real V0 IDs.
    const auto calling_index = index_of(DataTypeTable::calling_conventions);
    if (staged[calling_index] && source[calling_index]) {
        auto iterator = source[calling_index]->iterator();
        while (iterator->has_next()) {
            auto old_record = iterator->next();
            auto value = tables_[calling_index]->expected_schema->create_record(
                old_record->key().clone());
            copy_columns(*old_record, *value);
            staged[calling_index]->put_record(*value);
        }
    }
    const auto calling_convention_id = [&](std::string_view name) {
        if (name == "unknown") return std::int64_t{0};
        if (name == "default") return std::int64_t{1};
        auto table = selected_table(DataTypeTable::calling_conventions);
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (record->field(0).as_string() ==
                std::optional<std::string>(std::string(name))) {
                return record->key().as_integer();
            }
        }
        for (std::int64_t id = 2; id <= std::numeric_limits<std::int8_t>::max();
             ++id) {
            if (get_record(table, id)) continue;
            auto record = tables_[calling_index]->expected_schema->create_record(
                std::make_unique<db::IntegerField>(db::FieldType::byte, id));
            record->set_string(0, std::string(name));
            table->put_record(*record);
            return id;
        }
        return std::int64_t{0};
    };

    constexpr std::array<std::string_view, 6> generic_calling_conventions = {
        "unknown", "__stdcall", "__cdecl", "__fastcall", "__thiscall",
        "__vectorcall"};
    for (std::size_t index = 0; index < tables_.size(); ++index) {
        if (!staged[index] || index == calling_index ||
            tables_[index]->id == DataTypeTable::default_settings ||
            tables_[index]->id == DataTypeTable::default_setting_names ||
            tables_[index]->id == DataTypeTable::instance_settings ||
            tables_[index]->id == DataTypeTable::instance_setting_names ||
            tables_[index]->id == DataTypeTable::parent_child ||
            legacy[index] == LegacyDataTypeSchema::missing) {
            continue;
        }
        auto iterator = source[index]->iterator();
        while (iterator->has_next()) {
            auto old_record = iterator->next();
            if (legacy[index] ==
                LegacyDataTypeSchema::function_definition_v1) {
                auto value = tables_[index]->expected_schema->create_record(
                    old_record->key().clone());
                value->set_string(0, old_record->field(0).as_string());
                value->set_string(1, old_record->field(1).as_string());
                value->set_integer(2, old_record->field(2).as_integer());
                value->set_integer(3, old_record->field(3).as_integer());
                const auto old_flags = static_cast<std::uint8_t>(
                    old_record->field(4).as_integer());
                constexpr std::uint8_t generic_mask = 0x1e;
                const auto ordinal = static_cast<std::size_t>(
                    (old_flags & generic_mask) >> 1U);
                value->set_integer(4, old_flags & ~generic_mask);
                const auto convention =
                    ordinal < generic_calling_conventions.size()
                        ? generic_calling_conventions[ordinal]
                        : generic_calling_conventions[0];
                value->set_integer(5, calling_convention_id(convention));
                value->set_integer(6, local_archive_id);
                value->set_integer(7, next_local_universal_id());
                value->set_integer(8, 0);
                value->set_integer(9, 0);
                staged[index]->put_record(*value);
                continue;
            }
            auto value = translate_record(index, *old_record);
            staged[index]->put_record(*value);
        }
    }

    const auto translate_settings = [&](DataTypeTable value_id,
                                        DataTypeTable name_id,
                                        bool rekey_addresses) {
        const auto value_index = index_of(value_id);
        const auto name_index = index_of(name_id);
        if (!staged[value_index]) return;
        if (!staged[name_index]) {
            throw std::logic_error("staged settings table has no names table");
        }
        if (legacy[value_index] == LegacyDataTypeSchema::settings_v0) {
            std::map<std::optional<std::string>, std::int16_t> name_ids;
            std::int16_t next_name_id = 1;
            auto iterator = source[value_index]->iterator();
            while (iterator->has_next()) {
                auto old_record = iterator->next();
                const auto name = old_record->field(1).as_string();
                auto [position, inserted] = name_ids.emplace(name, next_name_id);
                if (inserted) {
                    if (next_name_id == std::numeric_limits<std::int16_t>::max()) {
                        throw std::overflow_error("too many legacy settings names");
                    }
                    auto name_record = tables_[name_index]->expected_schema->create_record(
                        next_name_id);
                    name_record->set_string(0, name);
                    staged[name_index]->put_record(*name_record);
                    ++next_name_id;
                }
                auto value = tables_[value_index]->expected_schema->create_record(
                    old_record->key().clone());
                auto association = old_record->field(0).as_integer();
                if (rekey_addresses) {
                    const auto old_key = std::bit_cast<std::uint64_t>(association);
                    const auto address =
                        address_map_->factory()->decode_old_index(old_key);
                    association = std::bit_cast<std::int64_t>(
                        address_map_->key(address, true));
                }
                value->set_integer(0, association);
                value->set_integer(1, position->second);
                value->set_integer(2, old_record->field(2).as_integer());
                value->set_string(3, old_record->field(3).as_string());
                staged[value_index]->put_record(*value);
            }
            return;
        }

        auto name_iterator = source[name_index]->iterator();
        while (name_iterator->has_next()) {
            auto old_record = name_iterator->next();
            auto value = tables_[name_index]->expected_schema->create_record(
                old_record->key().clone());
            copy_columns(*old_record, *value);
            staged[name_index]->put_record(*value);
        }
        auto value_iterator = source[value_index]->iterator();
        while (value_iterator->has_next()) {
            auto old_record = value_iterator->next();
            auto value = tables_[value_index]->expected_schema->create_record(
                old_record->key().clone());
            copy_columns(*old_record, *value);
            if (rekey_addresses) {
                const auto old_key = std::bit_cast<std::uint64_t>(
                    old_record->field(0).as_integer());
                const auto address = address_map_->factory()->decode_old_index(old_key);
                value->set_integer(0, std::bit_cast<std::int64_t>(
                                          address_map_->key(address, true)));
            }
            staged[value_index]->put_record(*value);
        }
    };
    translate_settings(DataTypeTable::default_settings,
                       DataTypeTable::default_setting_names, false);
    translate_settings(DataTypeTable::instance_settings,
                       DataTypeTable::instance_setting_names,
                       rekey_instance_settings);

    std::vector<std::int64_t> packed_flex_composites;
    std::vector<std::pair<std::int64_t, std::int64_t>> flex_array_elements;
    if (migrate_v5_flex_arrays) {
        auto array_table = selected_table(DataTypeTable::arrays);
        auto component_table = selected_table(DataTypeTable::components);
        auto composite_table = selected_table(DataTypeTable::composites);
        const auto array_index = index_of(DataTypeTable::arrays);

        const auto category_for_type = [&](std::int64_t id) {
            DataTypeTable table_id;
            std::size_t category_column;
            if (id <= 0) return root_category_id;
            switch (kind(id)) {
            case DataTypeKind::builtin:
                table_id = DataTypeTable::builtins;
                category_column = 2;
                break;
            case DataTypeKind::array:
                table_id = DataTypeTable::arrays;
                category_column = 3;
                break;
            case DataTypeKind::pointer:
                table_id = DataTypeTable::pointers;
                category_column = 1;
                break;
            case DataTypeKind::typedef_type:
                table_id = DataTypeTable::typedefs;
                category_column = 3;
                break;
            case DataTypeKind::composite:
                table_id = DataTypeTable::composites;
                category_column = 3;
                break;
            case DataTypeKind::function_definition:
                table_id = DataTypeTable::function_definitions;
                category_column = 2;
                break;
            case DataTypeKind::enumeration:
                table_id = DataTypeTable::enumerations;
                category_column = 2;
                break;
            default:
                return root_category_id;
            }
            const auto record = get_record(selected_table(table_id), id);
            return record ? record->field(category_column).as_integer()
                          : root_category_id;
        };
        const auto zero_length_array = [&](std::int64_t element_id) {
            const auto category_id = category_for_type(element_id);
            auto iterator = array_table->iterator();
            while (iterator->has_next()) {
                auto record = iterator->next();
                if (record->field(0).as_integer() == element_id &&
                    record->field(1).as_integer() == 0 &&
                    record->field(3).as_integer() == category_id) {
                    return record->key().as_integer();
                }
            }
            const auto id = make_id(DataTypeKind::array,
                                    array_table->next_long_key());
            auto record = tables_[array_index]->expected_schema->create_record(id);
            record->set_integer(0, element_id);
            record->set_integer(1, 0);
            record->set_integer(2, -1);
            record->set_integer(3, category_id);
            array_table->put_record(*record);
            flex_array_elements.emplace_back(id, element_id);
            return id;
        };

        std::vector<std::unique_ptr<db::Record>> composites;
        auto composite_iterator = composite_table->iterator();
        while (composite_iterator->has_next()) {
            composites.push_back(composite_iterator->next());
        }
        for (auto &composite : composites) {
            if (composite->field(2).as_boolean()) continue;
            const auto composite_id = composite->key().as_integer();
            std::vector<std::unique_ptr<db::Record>> components;
            auto component_iterator = component_table->iterator();
            while (component_iterator->has_next()) {
                auto component = component_iterator->next();
                if (component->field(0).as_integer() == composite_id) {
                    components.push_back(std::move(component));
                }
            }
            db::Record *flex = nullptr;
            std::int32_t defined_count = 0;
            for (auto &component : components) {
                if (component->field(6).as_integer() < 0) {
                    if (flex) {
                        throw std::runtime_error(
                            "V5 structure contains multiple legacy flex arrays");
                    }
                    flex = component.get();
                }
                else {
                    ++defined_count;
                }
            }
            if (!flex) continue;

            const bool packed = composite->field(11).as_integer() >=
                                CompositeDataType::default_packing;
            const auto next_ordinal = packed
                ? defined_count
                : static_cast<std::int32_t>(composite->field(6).as_integer());
            const auto array_id = zero_length_array(
                flex->field(2).as_integer());
            flex->set_integer(1, composite->field(4).as_integer());
            flex->set_integer(2, array_id);
            flex->set_integer(6, next_ordinal);
            component_table->put_record(*flex);
            composite->set_integer(6, static_cast<std::int64_t>(next_ordinal) + 1);
            composite_table->put_record(*composite);
            if (packed) packed_flex_composites.push_back(composite_id);
        }
    }

    const auto source_archive_index = index_of(DataTypeTable::source_archives);
    if (staged[source_archive_index] &&
        legacy[source_archive_index] == LegacyDataTypeSchema::missing) {
        auto local = tables_[source_archive_index]->expected_schema->create_record(
            local_archive_id);
        local->set_integer(3, now_millis());
        local->set_boolean(4, false);
        staged[source_archive_index]->put_record(*local);
    }

    const auto parent_index = index_of(DataTypeTable::parent_child);
    if (staged[parent_index]) {
        if (legacy[parent_index] == LegacyDataTypeSchema::current &&
            !migrate_v5_flex_arrays) {
            auto iterator = source[parent_index]->iterator();
            while (iterator->has_next()) {
                auto old_record = iterator->next();
                auto value = tables_[parent_index]->expected_schema->create_record(
                    old_record->key().clone());
                copy_columns(*old_record, *value);
                staged[parent_index]->put_record(*value);
            }
        }
        else {
            std::set<std::pair<std::int64_t, std::int64_t>> dependencies;
            const auto collect = [&](DataTypeTable id,
                                     std::size_t parent_column,
                                     std::size_t child_column,
                                     bool key_is_parent) {
                auto table = selected_table(id);
                auto iterator = table->iterator();
                while (iterator->has_next()) {
                    auto record = iterator->next();
                    const auto parent = key_is_parent
                        ? record->key().as_integer()
                        : record->field(parent_column).as_integer();
                    const auto child = record->field(child_column).as_integer();
                    if (parent > 0 && child > 0) {
                        dependencies.emplace(parent, child);
                    }
                }
            };
            collect(DataTypeTable::arrays, 0, 0, true);
            collect(DataTypeTable::pointers, 0, 0, true);
            collect(DataTypeTable::typedefs, 0, 0, true);
            collect(DataTypeTable::components, 0, 2, false);
            collect(DataTypeTable::function_definitions, 0, 3, true);
            collect(DataTypeTable::function_parameters, 0, 1, false);
            for (const auto &[parent, child] : dependencies) {
                auto value = tables_[parent_index]->expected_schema->create_record(
                    staged[parent_index]->next_long_key());
                value->set_integer(0, parent);
                value->set_integer(1, child);
                staged[parent_index]->put_record(*value);
            }
        }
    }

    if (mode_ == ProgramOpenMode::upgrade) {
        // Every record has now been translated successfully. Only at this point
        // may source tables be replaced; Program::open owns the encompassing
        // transaction and rolls the entire set back on any failure.
        for (std::size_t index = 0; index < tables_.size(); ++index) {
            if (!staged[index]) continue;
            if (source[index] && !database_->delete_table(tables_[index]->name)) {
                throw std::runtime_error("failed to replace legacy data-type table: " +
                                         tables_[index]->name);
            }
            auto replacement = database_->create_table(
                tables_[index]->name, tables_[index]->expected_schema,
                tables_[index]->indexes);
            auto iterator = staged[index]->iterator();
            while (iterator->has_next()) {
                auto record = iterator->next();
                replacement->put_record(*record);
            }
            source[index] = std::move(replacement);
        }
    }

    for (std::size_t index = 0; index < tables_.size(); ++index) {
        tables_[index]->table = mode_ == ProgramOpenMode::read_only && staged[index]
                                    ? staged[index]
                                    : source[index];
        if (!tables_[index]->table ||
            !tables_[index]->table->schema().equals(
                *tables_[index]->expected_schema)) {
            throw std::runtime_error("data-type migration did not produce current schema: " +
                                     tables_[index]->name);
        }
    }

    if (architecture_) {
        for (const auto &[array_id, element_id] : flex_array_elements) {
            const auto metrics = data_type_metrics(
                element_id, architecture_->data_organization);
            auto record = this->record(DataTypeTable::arrays, array_id);
            if (!record) {
                throw std::runtime_error("migrated flex-array datatype is missing");
            }
            record->set_integer(2, metrics.dynamic ? 1 : -1);
            slot(DataTypeTable::arrays).table->put_record(*record);
        }
    }
    if (mode_ == ProgramOpenMode::upgrade &&
        !packed_flex_composites.empty() && !architecture_) {
        throw std::runtime_error(
            "packed V5 flex-array migration requires ProgramArchitecture");
    }
    if (mode_ == ProgramOpenMode::upgrade && architecture_) {
        for (const auto composite_id : packed_flex_composites) {
            (void)repack_composite(composite_id,
                                   architecture_->data_organization,
                                   architecture_->endian,
                                   DataTypeUpdateMode::preserve_timestamps);
        }
    }
}

DataTypeManager::TableSlot &DataTypeManager::slot(DataTypeTable id) {
    return *tables_.at(static_cast<std::size_t>(id));
}

const DataTypeManager::TableSlot &DataTypeManager::slot(DataTypeTable id) const {
    return *tables_.at(static_cast<std::size_t>(id));
}

std::int64_t DataTypeManager::make_id(DataTypeKind kind,
                                      std::int64_t table_key_value) noexcept {
    const auto low = std::bit_cast<std::uint64_t>(table_key_value) & 0x00ffffffffffffffULL;
    const auto value = (static_cast<std::uint64_t>(kind) << kind_shift) | low;
    return std::bit_cast<std::int64_t>(value);
}

DataTypeKind DataTypeManager::kind(std::int64_t id) noexcept {
    return static_cast<DataTypeKind>(std::bit_cast<std::uint64_t>(id) >> kind_shift);
}

std::uint64_t DataTypeManager::table_key(std::int64_t id) noexcept {
    return std::bit_cast<std::uint64_t>(id) & 0x00ffffffffffffffULL;
}

std::shared_ptr<db::Table> DataTypeManager::table(DataTypeTable id) const {
    return slot(id).table;
}

std::unique_ptr<db::Record> DataTypeManager::record(DataTypeTable id,
                                                    std::int64_t key) const {
    return get_record(slot(id).table, key);
}

std::vector<std::unique_ptr<db::Record>> DataTypeManager::records(
    DataTypeTable id) const {
    std::vector<std::unique_ptr<db::Record>> result;
    auto iterator = slot(id).table->iterator();
    while (iterator->has_next()) {
        if (auto value = iterator->next()) result.push_back(std::move(value));
    }
    return result;
}

std::vector<std::int64_t> DataTypeManager::record_ids_by_index(
    DataTypeTable id,
    std::size_t column,
    const db::Field &value) const {
    const auto &entry = slot(id);
    if (entry.table != database_->get_table(entry.name)) {
        std::vector<std::int64_t> result;
        auto iterator = entry.table->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (record->field_equals(column, value)) {
                result.push_back(record->key().as_integer());
            }
        }
        return result;
    }
    const auto index = database_->get_index(entry.name, column);
    if (!index) throw std::invalid_argument("requested data-type column is not indexed");
    std::vector<std::int64_t> result;
    for (auto &key : index->find_primary_keys(value)) {
        result.push_back(key->as_integer());
    }
    return result;
}

void DataTypeManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

std::int64_t DataTypeManager::allocate_key(TableSlot &entry) {
    if (entry.id == DataTypeTable::calling_conventions) {
        for (std::int64_t id = 2; id <= std::numeric_limits<std::int8_t>::max(); ++id) {
            if (!get_record(entry.table, id)) return id;
        }
        throw std::overflow_error("all Ghidra calling-convention IDs are allocated");
    }
    auto next = entry.table->next_long_key();
    if (entry.id == DataTypeTable::categories && next == root_category_id) next = 1;
    if (entry.id == DataTypeTable::builtins && next <= 100) next = 100;
    return entry.data_type_kind ? make_id(*entry.data_type_kind, next) : next;
}

std::unique_ptr<db::Record> DataTypeManager::new_record(DataTypeTable id) {
    require_mutation();
    auto &entry = slot(id);
    const auto key = allocate_key(entry);
    if (entry.expected_schema->key_type().type() == db::FieldType::int64) {
        return entry.expected_schema->create_record(key);
    }
    return entry.expected_schema->create_record(
        std::make_unique<db::IntegerField>(entry.expected_schema->key_type().type(), key));
}

void DataTypeManager::put(DataTypeTable id, db::Record &value) {
    require_mutation();
    if (!value.has_same_schema(slot(id).table->schema())) {
        throw std::invalid_argument("record does not match the selected data-type table");
    }
    slot(id).table->put_record(value);
}

bool DataTypeManager::erase(DataTypeTable id, std::int64_t key) {
    require_mutation();
    return erase_record(slot(id).table, key);
}

CategoryRecord DataTypeManager::create_category(std::string name,
                                                std::int64_t parent_id) {
    require_mutation();
    if (name.empty() || name == "/") {
        throw std::invalid_argument("category name is invalid");
    }
    if (parent_id != root_category_id && !category(parent_id)) {
        throw std::out_of_range("parent category does not exist");
    }
    for (const auto &existing : child_categories(parent_id)) {
        if (existing.name == name) throw std::invalid_argument("duplicate category name");
    }
    auto value = new_record(DataTypeTable::categories);
    value->set_string(0, name);
    value->set_integer(1, parent_id);
    CategoryRecord result{value->key().as_integer(), std::move(name), parent_id};
    put(DataTypeTable::categories, *value);
    record_manager_change(nullptr, false);
    return result;
}

std::optional<CategoryRecord> DataTypeManager::category(std::int64_t id) const {
    if (id == root_category_id) return CategoryRecord{id, "/", -1};
    auto value = record(DataTypeTable::categories, id);
    if (!value) return std::nullopt;
    return CategoryRecord{id, value->field(0).as_string().value_or(std::string{}),
                          value->field(1).as_integer()};
}

std::vector<CategoryRecord> DataTypeManager::child_categories(
    std::int64_t parent_id) const {
    db::IntegerField parent(db::FieldType::int64, parent_id);
    std::vector<CategoryRecord> result;
    for (const auto id : record_ids_by_index(DataTypeTable::categories, 1, parent)) {
        if (auto value = category(id)) result.push_back(std::move(*value));
    }
    return result;
}

void DataTypeManager::update_category(CategoryRecord value) {
    require_mutation();
    if (value.id == root_category_id || value.name.empty() || value.name == "/") {
        throw std::invalid_argument("root or invalid category cannot be updated");
    }
    if (!category(value.id)) throw std::out_of_range("category does not exist");
    if (value.parent_id == value.id) throw std::invalid_argument("category cycle");
    if (value.parent_id != root_category_id && !category(value.parent_id)) {
        throw std::out_of_range("parent category does not exist");
    }
    for (auto cursor = category(value.parent_id); cursor && cursor->id != root_category_id;
         cursor = category(cursor->parent_id)) {
        if (cursor->id == value.id) throw std::invalid_argument("category cycle");
    }
    for (const auto &existing : child_categories(value.parent_id)) {
        if (existing.id != value.id && existing.name == value.name) {
            throw std::invalid_argument("duplicate category name");
        }
    }
    auto raw = slot(DataTypeTable::categories).expected_schema->create_record(value.id);
    raw->set_string(0, value.name);
    raw->set_integer(1, value.parent_id);
    put(DataTypeTable::categories, *raw);
    record_manager_change(nullptr, false);
}

bool DataTypeManager::remove_category(std::int64_t id) {
    require_mutation();
    if (id == root_category_id) throw std::invalid_argument("root category cannot be removed");
    if (!child_categories(id).empty()) {
        throw std::logic_error("category still contains child categories");
    }
    for (const auto table_id : {DataTypeTable::builtins, DataTypeTable::arrays,
                                DataTypeTable::pointers, DataTypeTable::typedefs,
                                DataTypeTable::composites,
                                DataTypeTable::function_definitions,
                                DataTypeTable::enumerations}) {
        const auto category_column = table_id == DataTypeTable::builtins ? 2U :
                                     table_id == DataTypeTable::arrays ? 3U :
                                     table_id == DataTypeTable::pointers ? 1U :
                                     table_id == DataTypeTable::typedefs ? 3U :
                                     table_id == DataTypeTable::composites ? 3U : 2U;
        db::IntegerField key(db::FieldType::int64, id);
        if (!record_ids_by_index(table_id, category_column, key).empty()) {
            throw std::logic_error("category still contains data types");
        }
    }
    const bool removed = erase(DataTypeTable::categories, id);
    if (removed) record_manager_change(nullptr, false);
    return removed;
}

std::uint8_t DataTypeManager::calling_convention_id(const std::string &name,
                                                    bool create) {
    if (name.empty()) return 0;
    for (auto &value : records(DataTypeTable::calling_conventions)) {
        if (value->field(0).as_string() == std::optional<std::string>(name)) {
            return static_cast<std::uint8_t>(value->key().as_integer());
        }
    }
    if (!create) return 0;
    auto value = new_record(DataTypeTable::calling_conventions);
    value->set_string(0, name);
    const auto id = static_cast<std::uint8_t>(value->key().as_integer());
    put(DataTypeTable::calling_conventions, *value);
    return id;
}

std::optional<std::string> DataTypeManager::calling_convention_name(
    std::uint8_t id) const {
    if (id == 0) return std::string("unknown");
    if (id == 1) return std::string("default");
    auto value = record(DataTypeTable::calling_conventions, id);
    return value ? value->field(0).as_string() : std::nullopt;
}

SourceArchiveRecord DataTypeManager::create_source_archive(
    SourceArchiveRecord value) {
    require_mutation();
    if (value.id == local_archive_id || value.id == builtin_archive_id) {
        throw std::invalid_argument("source archive ID is reserved");
    }
    if (static_cast<std::uint8_t>(value.type) >
        static_cast<std::uint8_t>(SourceArchiveType::temporary)) {
        throw std::invalid_argument("source archive type is invalid");
    }
    if (source_archive(value.id)) {
        throw std::invalid_argument("source archive ID already exists");
    }
    auto raw = slot(DataTypeTable::source_archives)
                   .expected_schema->create_record(value.id);
    raw->set_string(0, value.domain_file_id);
    raw->set_string(1, value.name);
    raw->set_integer(2, static_cast<std::uint8_t>(value.type));
    raw->set_integer(3, value.last_sync_time);
    raw->set_boolean(4, value.dirty);
    put(DataTypeTable::source_archives, *raw);
    return value;
}

std::optional<SourceArchiveRecord> DataTypeManager::source_archive(
    std::int64_t id) const {
    auto raw = record(DataTypeTable::source_archives, id);
    if (!raw) return std::nullopt;
    if (id == local_archive_id) {
        return SourceArchiveRecord{id, std::nullopt, std::nullopt,
                                   SourceArchiveType::program,
                                   raw->field(3).as_integer(),
                                   raw->field(4).as_boolean()};
    }
    const auto type_value = raw->field(2).as_integer();
    if (type_value < 0 || type_value >
                              static_cast<std::int64_t>(SourceArchiveType::temporary)) {
        throw std::runtime_error("source archive record has an invalid type");
    }
    return SourceArchiveRecord{
        id, raw->field(0).as_string(), raw->field(1).as_string(),
        static_cast<SourceArchiveType>(type_value), raw->field(3).as_integer(),
        raw->field(4).as_boolean()};
}

std::vector<SourceArchiveRecord> DataTypeManager::source_archives() const {
    std::vector<SourceArchiveRecord> result;
    for (auto &raw : records(DataTypeTable::source_archives)) {
        if (auto value = source_archive(raw->key().as_integer())) {
            result.push_back(std::move(*value));
        }
    }
    return result;
}

void DataTypeManager::update_source_archive(SourceArchiveRecord value) {
    require_mutation();
    if (value.id == local_archive_id) {
        auto raw = record(DataTypeTable::source_archives, local_archive_id);
        if (!raw) throw std::runtime_error("local source archive record is missing");
        // Ghidra leaves the local row's delegated identity columns null.
        raw->set_integer(3, value.last_sync_time);
        raw->set_boolean(4, value.dirty);
        put(DataTypeTable::source_archives, *raw);
        return;
    }
    else if (value.id == builtin_archive_id || !source_archive(value.id)) {
        throw std::out_of_range("source archive does not exist");
    }
    if (static_cast<std::uint8_t>(value.type) >
        static_cast<std::uint8_t>(SourceArchiveType::temporary)) {
        throw std::invalid_argument("source archive type is invalid");
    }
    auto raw = slot(DataTypeTable::source_archives)
                   .expected_schema->create_record(value.id);
    raw->set_string(0, value.domain_file_id);
    raw->set_string(1, value.name);
    raw->set_integer(2, static_cast<std::uint8_t>(value.type));
    raw->set_integer(3, value.last_sync_time);
    raw->set_boolean(4, value.dirty);
    put(DataTypeTable::source_archives, *raw);
}

bool DataTypeManager::remove_source_archive(std::int64_t id) {
    require_mutation();
    if (id == local_archive_id || id == builtin_archive_id) {
        throw std::invalid_argument("reserved source archive cannot be removed");
    }
    if (!source_archive(id)) return false;
    for (const auto &type : all_data_types()) {
        const bool referenced = std::visit(
            [id](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, TypedefDataType> ||
                              std::is_same_v<T, EnumDataType> ||
                              std::is_same_v<T, CompositeDataType> ||
                              std::is_same_v<T, FunctionDefinitionDataType>) {
                    return value.provenance.source_archive_id == id;
                }
                return false;
            },
            type);
        if (referenced) {
            throw std::logic_error("source archive is still referenced by data types");
        }
    }
    return erase(DataTypeTable::source_archives, id);
}

void DataTypeManager::replace_source_archive(
    std::int64_t old_id,
    SourceArchiveRecord replacement) {
    require_mutation();
    if (old_id == local_archive_id || old_id == builtin_archive_id ||
        !source_archive(old_id)) {
        throw std::out_of_range("source archive to replace does not exist");
    }
    if (replacement.id == old_id) {
        throw std::invalid_argument("source archive replacement IDs must differ");
    }
    if (auto existing = source_archive(replacement.id)) {
        replacement = *existing;
    }
    else {
        replacement = create_source_archive(std::move(replacement));
    }

    auto types = all_data_types();
    for (auto &type : types) {
        bool changed = false;
        std::visit(
            [&](auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, TypedefDataType> ||
                              std::is_same_v<T, EnumDataType> ||
                              std::is_same_v<T, CompositeDataType> ||
                              std::is_same_v<T, FunctionDefinitionDataType>) {
                    if (value.provenance.source_archive_id == old_id) {
                        value.provenance.source_archive_id = replacement.id;
                        changed = true;
                    }
                }
            },
            type);
        if (changed) {
            (void)update_data_type(std::move(type),
                                   DataTypeUpdateMode::preserve_timestamps);
        }
    }
    if (!erase(DataTypeTable::source_archives, old_id)) {
        throw std::runtime_error("source archive disappeared during replacement");
    }
    replacement.last_sync_time = 0;
    update_source_archive(std::move(replacement));
}

DataType DataTypeManager::associate_data_type_with_archive(
    std::int64_t id,
    std::int64_t source_archive_id,
    std::int64_t source_universal_id,
    std::int64_t source_change_time) {
    require_mutation();
    require_source_archive(source_archive_id);
    if (source_archive_id == local_archive_id || source_universal_id == 0) {
        throw std::invalid_argument("external source archive identity is required");
    }
    auto value = data_type(id);
    if (!value) throw std::out_of_range("data type does not exist");
    bool settable = false;
    std::visit(
        [&](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                if (item.provenance.source_archive_id != local_archive_id &&
                    item.provenance.source_archive_id != source_archive_id) {
                    throw std::logic_error(
                        "data type is already associated with another archive");
                }
                item.provenance.source_archive_id = source_archive_id;
                item.provenance.universal_id = source_universal_id;
                item.provenance.last_change_time =
                    source_change_time == 0 ? now_millis() : source_change_time;
                item.provenance.source_sync_time = item.provenance.last_change_time;
                settable = true;
            }
        },
        *value);
    if (!settable) {
        throw std::invalid_argument("data type kind cannot carry source identity");
    }
    return update_data_type(std::move(*value),
                            DataTypeUpdateMode::preserve_timestamps);
}

DataType DataTypeManager::disassociate_data_type(std::int64_t id) {
    require_mutation();
    auto value = data_type(id);
    if (!value) throw std::out_of_range("data type does not exist");
    bool settable = false;
    bool already_local = false;
    std::visit(
        [&](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                settable = true;
                already_local =
                    item.provenance.source_archive_id == local_archive_id;
                if (!already_local) {
                    item.provenance.source_archive_id = local_archive_id;
                    item.provenance.universal_id = next_local_universal_id();
                    item.provenance.source_sync_time = 0;
                }
            }
        },
        *value);
    if (!settable) {
        throw std::invalid_argument("data type kind cannot carry source identity");
    }
    if (already_local) return *value;
    return update_data_type(std::move(*value), DataTypeUpdateMode::local_change);
}

std::int16_t DataTypeManager::setting_name_index(bool instance,
                                                 const std::string &name,
                                                 bool create) {
    const auto names_table = instance ? DataTypeTable::instance_setting_names
                                      : DataTypeTable::default_setting_names;
    for (auto &value : records(names_table)) {
        if (value->field(0).as_string() == std::optional<std::string>(name)) {
            return static_cast<std::int16_t>(value->key().as_integer());
        }
    }
    if (!create) return -1;
    auto value = new_record(names_table);
    if (value->key().as_integer() > std::numeric_limits<std::int16_t>::max()) {
        throw std::overflow_error("too many data-type setting names");
    }
    value->set_string(0, name);
    const auto index = static_cast<std::int16_t>(value->key().as_integer());
    put(names_table, *value);
    return index;
}

std::optional<std::string> DataTypeManager::setting_name(bool instance,
                                                        std::int16_t index) const {
    const auto names_table = instance ? DataTypeTable::instance_setting_names
                                      : DataTypeTable::default_setting_names;
    auto value = record(names_table, index);
    return value ? value->field(0).as_string() : std::nullopt;
}

void DataTypeManager::set_setting(bool instance, DataTypeSetting setting) {
    require_mutation();
    if (setting.name.empty()) throw std::invalid_argument("setting name must not be empty");
    const auto settings_table = instance ? DataTypeTable::instance_settings
                                         : DataTypeTable::default_settings;
    const auto name_index = setting_name_index(instance, setting.name, true);
    db::IntegerField association(db::FieldType::int64, setting.association_id);
    std::unique_ptr<db::Record> target;
    for (const auto id : record_ids_by_index(settings_table, 0, association)) {
        auto candidate = record(settings_table, id);
        if (candidate->field(1).as_integer() == name_index) {
            target = std::move(candidate);
            break;
        }
    }
    if (!target) target = new_record(settings_table);
    target->set_integer(0, setting.association_id);
    target->set_integer(1, name_index);
    target->set_integer(2, setting.long_value);
    target->set_string(3, std::move(setting.string_value));
    put(settings_table, *target);
    if (!instance) {
        const auto changed = data_type(setting.association_id);
        record_manager_change(changed ? &*changed : nullptr, changed.has_value());
    }
}

std::vector<DataTypeSetting> DataTypeManager::settings(
    bool instance,
    std::int64_t association_id) const {
    const auto settings_table = instance ? DataTypeTable::instance_settings
                                         : DataTypeTable::default_settings;
    db::IntegerField association(db::FieldType::int64, association_id);
    std::vector<DataTypeSetting> result;
    for (const auto id : record_ids_by_index(settings_table, 0, association)) {
        auto value = record(settings_table, id);
        const auto name = setting_name(
            instance, static_cast<std::int16_t>(value->field(1).as_integer()));
        if (!name) throw std::runtime_error("setting references a missing name");
        result.push_back({association_id, *name, value->field(2).as_integer(),
                          value->field(3).as_string()});
    }
    return result;
}

void DataTypeManager::clear_settings(bool instance,
                                     std::int64_t association_id) {
    require_mutation();
    const auto settings_table = instance ? DataTypeTable::instance_settings
                                         : DataTypeTable::default_settings;
    db::IntegerField association(db::FieldType::int64, association_id);
    for (const auto id : record_ids_by_index(settings_table, 0, association)) {
        (void)erase(settings_table, id);
    }
    if (!instance) {
        const auto changed = data_type(association_id);
        record_manager_change(changed ? &*changed : nullptr, changed.has_value());
    }
}

void DataTypeManager::require_category(std::int64_t id) const {
    if (!category(id)) throw std::out_of_range("data-type category does not exist");
}

void DataTypeManager::require_data_type(std::int64_t id) const {
    if (id == 0 || id == -1 || id == -2) return;
    if (!contains_data_type(id)) throw std::out_of_range("referenced data type does not exist");
}

void DataTypeManager::require_unique_name(std::int64_t category_id,
                                          const std::string &name,
                                          std::optional<std::int64_t> except_id) const {
    if (name.empty()) throw std::invalid_argument("data-type name must not be empty");
    struct NamedTable {
        DataTypeTable table;
        std::size_t name_column;
        std::size_t category_column;
    };
    constexpr NamedTable named_tables[] = {
        {DataTypeTable::builtins, 0, 2},
        {DataTypeTable::typedefs, 2, 3},
        {DataTypeTable::composites, 0, 3},
        {DataTypeTable::function_definitions, 0, 2},
        {DataTypeTable::enumerations, 0, 2},
    };
    for (const auto &entry : named_tables) {
        for (auto &value : records(entry.table)) {
            if (except_id && value->key().as_integer() == *except_id) continue;
            if (value->field(entry.category_column).as_integer() == category_id &&
                value->field(entry.name_column).as_string() ==
                    std::optional<std::string>(name)) {
                throw std::invalid_argument("duplicate data-type name in category");
            }
        }
    }
}

void DataTypeManager::require_source_archive(std::int64_t id) const {
    if (id == local_archive_id || id == builtin_archive_id) return;
    if (!source_archive(id)) {
        throw std::out_of_range("data type source archive does not exist");
    }
}

std::int64_t DataTypeManager::data_type_id(const DataType &value) noexcept {
    return std::visit([](const auto &item) { return item.id; }, value);
}

std::optional<std::int64_t> DataTypeManager::data_type_category(
    const DataType &value) noexcept {
    return std::visit(
        [](const auto &item) -> std::optional<std::int64_t> {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, BitFieldDataType>) {
                return std::nullopt;
            }
            else {
                return item.category_id;
            }
        },
        value);
}

std::optional<std::string> DataTypeManager::data_type_name(
    const DataType &value) {
    return std::visit(
        [](const auto &item) -> std::optional<std::string> {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, BuiltinDataType> ||
                          std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                return item.name;
            }
            return std::nullopt;
        },
        value);
}

void DataTypeManager::set_data_type_id(DataType &value, std::int64_t id) noexcept {
    std::visit([id](auto &item) { item.id = id; }, value);
}

void DataTypeManager::set_data_type_name(DataType &value, std::string name) {
    const bool changed = std::visit(
        [&](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, BuiltinDataType> ||
                          std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                item.name = std::move(name);
                return true;
            }
            return false;
        },
        value);
    if (!changed) throw std::invalid_argument("data type has an automatic name");
}

void DataTypeManager::apply_update_timestamp(DataType &value,
                                             DataTypeUpdateMode mode) {
    std::visit(
        [mode](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                if (item.provenance.universal_id == 0) {
                    item.provenance.universal_id = next_local_universal_id();
                }
                if (mode == DataTypeUpdateMode::local_change) {
                    item.provenance.last_change_time = now_millis();
                }
                else if (mode == DataTypeUpdateMode::source_sync) {
                    if (item.provenance.last_change_time == 0) {
                        item.provenance.last_change_time = now_millis();
                    }
                    item.provenance.source_sync_time =
                        item.provenance.last_change_time;
                }
            }
        },
        value);
}

void DataTypeManager::record_manager_change(const DataType *changed,
                                            bool dirty_source_archive) {
    auto local = record(DataTypeTable::source_archives, local_archive_id);
    if (local) {
        local->set_integer(3, now_millis());
        put(DataTypeTable::source_archives, *local);
    }
    if (!changed || !dirty_source_archive) return;
    std::optional<std::int64_t> source_id;
    std::visit(
        [&](const auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                source_id = item.provenance.source_archive_id;
            }
        },
        *changed);
    if (!source_id || *source_id == builtin_archive_id) return;
    auto source = record(DataTypeTable::source_archives, *source_id);
    if (source) {
        source->set_boolean(4, true);
        put(DataTypeTable::source_archives, *source);
    }
}

void DataTypeManager::validate_data_type(
    const DataType &value,
    std::optional<std::int64_t> updating_id) const {
    const auto id = data_type_id(value);
    if (updating_id) {
        const auto existing = data_type(*updating_id);
        if (!existing) throw std::out_of_range("data type to update does not exist");
        if (id != *updating_id || value.index() != existing->index()) {
            throw std::invalid_argument("data type update must preserve ID and kind");
        }
    }
    const auto category_id = data_type_category(value);
    if (category_id) require_category(*category_id);
    const auto name = data_type_name(value);
    if (name) require_unique_name(*category_id, *name, updating_id);

    std::vector<std::int64_t> dependencies;
    std::visit(
        [&](const auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, BuiltinDataType>) {
                if (item.class_name.empty()) {
                    throw std::invalid_argument("builtin class name is empty");
                }
            }
            else if constexpr (std::is_same_v<T, ArrayDataType>) {
                if (item.element_count < 0 || item.element_length < -1 ||
                    item.element_length == 0) {
                    throw std::invalid_argument("array dimensions or element length are invalid");
                }
                dependencies.push_back(item.element_type_id);
            }
            else if constexpr (std::is_same_v<T, PointerDataType>) {
                if (item.length < -1 || item.length == 0 || item.length > 127) {
                    throw std::invalid_argument(
                        "pointer length is outside the persisted byte range");
                }
                dependencies.push_back(item.referenced_type_id);
            }
            else if constexpr (std::is_same_v<T, TypedefDataType>) {
                if (item.flags > static_cast<std::uint16_t>(
                                     std::numeric_limits<std::int16_t>::max())) {
                    throw std::invalid_argument(
                        "typedef flags exceed the persisted short range");
                }
                require_source_archive(item.provenance.source_archive_id);
                dependencies.push_back(item.referenced_type_id);
            }
            else if constexpr (std::is_same_v<T, EnumDataType>) {
                require_source_archive(item.provenance.source_archive_id);
                if (item.size == 0 || item.size > 16) {
                    throw std::invalid_argument("enum size must be between 1 and 16 bytes");
                }
                std::set<std::string> names;
                for (const auto &enum_value : item.values) {
                    if (enum_value.name.empty() || !names.insert(enum_value.name).second) {
                        throw std::invalid_argument(
                            "enum value names must be non-empty and unique");
                    }
                }
            }
            else if constexpr (std::is_same_v<T, CompositeDataType>) {
                require_source_archive(item.provenance.source_archive_id);
                if (item.packing < CompositeDataType::no_packing ||
                    item.minimum_alignment < CompositeDataType::machine_alignment ||
                    item.alignment <= 0 || item.length < 0) {
                    throw std::invalid_argument(
                        "composite packing, alignment, or length is invalid");
                }
                std::int32_t ordinal = 0;
                for (const auto &component : item.components) {
                    if (component.length < 0 || component.offset < 0 ||
                        component.ordinal != ordinal++ ||
                        (item.is_union && component.offset != 0)) {
                        throw std::invalid_argument("composite component layout is invalid");
                    }
                    dependencies.push_back(component.data_type_id);
                }
            }
            else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                require_source_archive(item.provenance.source_archive_id);
                if (item.calling_convention_id > 1 &&
                    !calling_convention_name(item.calling_convention_id)) {
                    throw std::out_of_range("calling convention does not exist");
                }
                dependencies.push_back(item.return_type_id);
                std::int32_t ordinal = 0;
                for (const auto &parameter : item.parameters) {
                    if (parameter.ordinal != ordinal++ ||
                        parameter.data_type_length < 0) {
                        throw std::invalid_argument(
                            "function-definition parameter layout is invalid");
                    }
                    dependencies.push_back(parameter.data_type_id);
                }
            }
            else if constexpr (std::is_same_v<T, BitFieldDataType>) {
                if (item.bit_offset > 7 || item.base_type_id <= 0) {
                    throw std::invalid_argument("bitfield layout or base is invalid");
                }
                dependencies.push_back(item.base_type_id);
            }
        },
        value);

    std::optional<DataTypeProvenance> identity;
    std::visit(
        [&](const auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                identity = item.provenance;
            }
        },
        value);
    if (identity) {
        if (identity->universal_id == 0) {
            throw std::invalid_argument("stored data type requires a universal ID");
        }
        const auto matching = data_type_by_universal_id(
            identity->source_archive_id, identity->universal_id);
        if (matching && (!updating_id || data_type_id(*matching) != *updating_id)) {
            throw std::invalid_argument(
                "data type universal identity already exists in source archive");
        }
    }

    for (const auto child_id : dependencies) {
        require_data_type(child_id);
        if (!updating_id || child_id <= 0) continue;
        if (child_id == *updating_id) {
            throw std::invalid_argument("data type cannot directly contain itself");
        }
        // A pointer has fixed size and is the legal recursion break used by
        // structures such as `struct node { node *next; }`.
        if (kind(child_id) != DataTypeKind::pointer &&
            depends_on(child_id, *updating_id)) {
            throw std::invalid_argument("data type dependency cycle");
        }
    }
}

void DataTypeManager::add_dependency(std::int64_t parent_id,
                                     std::int64_t child_id) {
    if (child_id <= 0) return;
    db::IntegerField parent(db::FieldType::int64, parent_id);
    for (const auto record_id :
         record_ids_by_index(DataTypeTable::parent_child, 0, parent)) {
        auto existing = record(DataTypeTable::parent_child, record_id);
        if (existing->field(1).as_integer() == child_id) return;
    }
    auto value = new_record(DataTypeTable::parent_child);
    value->set_integer(0, parent_id);
    value->set_integer(1, child_id);
    put(DataTypeTable::parent_child, *value);
}

void DataTypeManager::remove_dependencies(std::int64_t parent_id) {
    db::IntegerField parent(db::FieldType::int64, parent_id);
    for (const auto record_id :
         record_ids_by_index(DataTypeTable::parent_child, 0, parent)) {
        (void)erase(DataTypeTable::parent_child, record_id);
    }
}

std::vector<std::int64_t> DataTypeManager::parent_data_types(
    std::int64_t child_id) const {
    db::IntegerField child(db::FieldType::int64, child_id);
    std::vector<std::int64_t> result;
    for (const auto record_id :
         record_ids_by_index(DataTypeTable::parent_child, 1, child)) {
        auto value = record(DataTypeTable::parent_child, record_id);
        result.push_back(value->field(0).as_integer());
    }
    // Bitfields are virtual IDs rather than rows. A composite references the
    // encoded bitfield ID, so its base typedef/enum/integer must still be
    // treated as referenced when deciding whether that base can be removed.
    for (auto &edge : records(DataTypeTable::parent_child)) {
        const auto encoded_child = edge->field(1).as_integer();
        if (encoded_child <= 0 || kind(encoded_child) != DataTypeKind::bitfield) continue;
        const auto bitfield = data_type(encoded_child);
        if (!bitfield || !std::holds_alternative<BitFieldDataType>(*bitfield) ||
            std::get<BitFieldDataType>(*bitfield).base_type_id != child_id) {
            continue;
        }
        const auto parent_id = edge->field(0).as_integer();
        if (std::ranges::find(result, parent_id) == result.end()) {
            result.push_back(parent_id);
        }
    }
    return result;
}

std::vector<std::int64_t> DataTypeManager::child_data_types(
    std::int64_t parent_id) const {
    db::IntegerField parent(db::FieldType::int64, parent_id);
    std::vector<std::int64_t> result;
    for (const auto record_id :
         record_ids_by_index(DataTypeTable::parent_child, 0, parent)) {
        auto value = record(DataTypeTable::parent_child, record_id);
        result.push_back(value->field(1).as_integer());
    }
    return result;
}

BuiltinDataType DataTypeManager::create_builtin(BuiltinDataType value) {
    require_mutation();
    value.id = 0;
    validate_data_type(DataType{value}, std::nullopt);
    require_category(value.category_id);
    require_unique_name(value.category_id, value.name);
    if (value.class_name.empty()) throw std::invalid_argument("builtin class name is empty");
    auto raw = new_record(DataTypeTable::builtins);
    raw->set_string(0, value.name);
    raw->set_string(1, value.class_name);
    raw->set_integer(2, value.category_id);
    value.id = raw->key().as_integer();
    put(DataTypeTable::builtins, *raw);
    const DataType changed = value;
    record_manager_change(&changed, false);
    return value;
}

ArrayDataType DataTypeManager::create_array(ArrayDataType value) {
    require_mutation();
    value.id = 0;
    validate_data_type(DataType{value}, std::nullopt);
    require_data_type(value.element_type_id);
    require_category(value.category_id);
    if (value.element_count < 0 || value.element_length < -1 ||
        value.element_length == 0) {
        throw std::invalid_argument("array dimensions or element length are invalid");
    }
    auto raw = new_record(DataTypeTable::arrays);
    raw->set_integer(0, value.element_type_id);
    raw->set_integer(1, value.element_count);
    raw->set_integer(2, value.element_length);
    raw->set_integer(3, value.category_id);
    value.id = raw->key().as_integer();
    put(DataTypeTable::arrays, *raw);
    add_dependency(value.id, value.element_type_id);
    const DataType changed = value;
    record_manager_change(&changed, false);
    return value;
}

PointerDataType DataTypeManager::create_pointer(PointerDataType value) {
    require_mutation();
    value.id = 0;
    validate_data_type(DataType{value}, std::nullopt);
    require_data_type(value.referenced_type_id);
    require_category(value.category_id);
    if (value.length < -1 || value.length == 0 || value.length > 127) {
        throw std::invalid_argument("pointer length is outside the persisted byte range");
    }
    auto raw = new_record(DataTypeTable::pointers);
    raw->set_integer(0, value.referenced_type_id);
    raw->set_integer(1, value.category_id);
    raw->set_integer(2, value.length);
    value.id = raw->key().as_integer();
    put(DataTypeTable::pointers, *raw);
    add_dependency(value.id, value.referenced_type_id);
    const DataType changed = value;
    record_manager_change(&changed, false);
    return value;
}

TypedefDataType DataTypeManager::create_typedef(TypedefDataType value) {
    require_mutation();
    value.id = 0;
    if (value.provenance.universal_id == 0) {
        value.provenance.universal_id = next_local_universal_id();
    }
    validate_data_type(DataType{value}, std::nullopt);
    require_data_type(value.referenced_type_id);
    require_category(value.category_id);
    require_unique_name(value.category_id, value.name);
    if (value.flags > static_cast<std::uint16_t>(std::numeric_limits<std::int16_t>::max())) {
        throw std::invalid_argument("typedef flags exceed the persisted short range");
    }
    const auto timestamp = value.provenance.last_change_time == 0
                               ? now_millis()
                               : value.provenance.last_change_time;
    value.provenance.last_change_time = timestamp;
    value.provenance.source_sync_time = timestamp;
    auto raw = new_record(DataTypeTable::typedefs);
    raw->set_integer(0, value.referenced_type_id);
    raw->set_integer(1, value.flags);
    raw->set_string(2, value.name);
    raw->set_integer(3, value.category_id);
    raw->set_integer(4, value.provenance.source_archive_id);
    raw->set_integer(5, value.provenance.universal_id);
    raw->set_integer(6, value.provenance.source_sync_time);
    raw->set_integer(7, value.provenance.last_change_time);
    value.id = raw->key().as_integer();
    put(DataTypeTable::typedefs, *raw);
    add_dependency(value.id, value.referenced_type_id);
    const DataType changed = value;
    record_manager_change(&changed, false);
    return value;
}

EnumDataType DataTypeManager::create_enum(EnumDataType value) {
    require_mutation();
    value.id = 0;
    if (value.provenance.universal_id == 0) {
        value.provenance.universal_id = next_local_universal_id();
    }
    validate_data_type(DataType{value}, std::nullopt);
    require_category(value.category_id);
    require_unique_name(value.category_id, value.name);
    if (value.size == 0 || value.size > 16) {
        throw std::invalid_argument("enum size must be between 1 and 16 bytes");
    }
    const auto timestamp = value.provenance.last_change_time == 0
                               ? now_millis()
                               : value.provenance.last_change_time;
    value.provenance.last_change_time = timestamp;
    value.provenance.source_sync_time = timestamp;
    auto raw = new_record(DataTypeTable::enumerations);
    raw->set_string(0, value.name);
    raw->set_string(1, value.comment);
    raw->set_integer(2, value.category_id);
    raw->set_integer(3, value.size);
    raw->set_integer(4, value.provenance.source_archive_id);
    raw->set_integer(5, value.provenance.universal_id);
    raw->set_integer(6, value.provenance.source_sync_time);
    raw->set_integer(7, value.provenance.last_change_time);
    value.id = raw->key().as_integer();
    put(DataTypeTable::enumerations, *raw);

    std::set<std::string> names;
    for (auto &item : value.values) {
        if (item.name.empty() || !names.insert(item.name).second) {
            throw std::invalid_argument("enum value names must be non-empty and unique");
        }
        auto value_record = new_record(DataTypeTable::enumeration_values);
        value_record->set_string(0, item.name);
        value_record->set_integer(1, item.value);
        value_record->set_integer(2, value.id);
        value_record->set_string(3, item.comment);
        item.record_id = value_record->key().as_integer();
        put(DataTypeTable::enumeration_values, *value_record);
    }
    const DataType changed = value;
    record_manager_change(&changed, false);
    return value;
}

CompositeDataType DataTypeManager::create_composite(CompositeDataType value) {
    require_mutation();
    value.id = 0;
    if (value.provenance.universal_id == 0) {
        value.provenance.universal_id = next_local_universal_id();
    }
    if (value.packing >= CompositeDataType::default_packing) value.length = 0;
    validate_data_type(DataType{value}, std::nullopt);
    require_category(value.category_id);
    require_unique_name(value.category_id, value.name);
    if (value.packing < CompositeDataType::no_packing ||
        value.minimum_alignment < CompositeDataType::machine_alignment ||
        value.alignment <= 0 || value.length < 0) {
        throw std::invalid_argument("composite packing, alignment, or length is invalid");
    }
    const auto timestamp = value.provenance.last_change_time == 0
                               ? now_millis()
                               : value.provenance.last_change_time;
    value.provenance.last_change_time = timestamp;
    value.provenance.source_sync_time = timestamp;
    auto raw = new_record(DataTypeTable::composites);
    raw->set_string(0, value.name);
    raw->set_string(1, value.comment);
    raw->set_boolean(2, value.is_union);
    raw->set_integer(3, value.category_id);
    raw->set_integer(4, value.length);
    raw->set_integer(5, value.alignment);
    raw->set_integer(6, static_cast<std::int32_t>(value.components.size()));
    raw->set_integer(7, value.provenance.source_archive_id);
    raw->set_integer(8, value.provenance.universal_id);
    raw->set_integer(9, value.provenance.source_sync_time);
    raw->set_integer(10, value.provenance.last_change_time);
    raw->set_integer(11, value.packing);
    raw->set_integer(12, value.minimum_alignment);
    value.id = raw->key().as_integer();
    put(DataTypeTable::composites, *raw);

    std::int32_t expected_ordinal = 0;
    for (auto &component : value.components) {
        require_data_type(component.data_type_id);
        if (component.length < 0 || component.offset < 0 ||
            component.ordinal != expected_ordinal++) {
            throw std::invalid_argument("composite component layout is invalid");
        }
        auto component_record = new_record(DataTypeTable::components);
        component_record->set_integer(0, value.id);
        component_record->set_integer(1, component.offset);
        component_record->set_integer(2, component.data_type_id);
        component_record->set_string(3, component.field_name);
        component_record->set_string(4, component.comment);
        component_record->set_integer(5, component.length);
        component_record->set_integer(6, component.ordinal);
        component.id = component_record->key().as_integer();
        put(DataTypeTable::components, *component_record);
        add_dependency(value.id, component.data_type_id);
    }
    const DataType changed = value;
    record_manager_change(&changed, false);
    return value;
}

FunctionDefinitionDataType DataTypeManager::create_function_definition(
    FunctionDefinitionDataType value) {
    require_mutation();
    value.id = 0;
    if (value.provenance.universal_id == 0) {
        value.provenance.universal_id = next_local_universal_id();
    }
    validate_data_type(DataType{value}, std::nullopt);
    require_category(value.category_id);
    require_data_type(value.return_type_id);
    require_unique_name(value.category_id, value.name);
    if (value.calling_convention_id > 1 &&
        !calling_convention_name(value.calling_convention_id)) {
        throw std::out_of_range("calling convention does not exist");
    }
    const auto timestamp = value.provenance.last_change_time == 0
                               ? now_millis()
                               : value.provenance.last_change_time;
    value.provenance.last_change_time = timestamp;
    value.provenance.source_sync_time = timestamp;
    auto raw = new_record(DataTypeTable::function_definitions);
    raw->set_string(0, value.name);
    raw->set_string(1, value.comment);
    raw->set_integer(2, value.category_id);
    raw->set_integer(3, value.return_type_id);
    raw->set_integer(4, (value.variadic ? 1 : 0) | (value.no_return ? 2 : 0));
    raw->set_integer(5, value.calling_convention_id);
    raw->set_integer(6, value.provenance.source_archive_id);
    raw->set_integer(7, value.provenance.universal_id);
    raw->set_integer(8, value.provenance.source_sync_time);
    raw->set_integer(9, value.provenance.last_change_time);
    value.id = raw->key().as_integer();
    put(DataTypeTable::function_definitions, *raw);
    add_dependency(value.id, value.return_type_id);

    std::int32_t expected_ordinal = 0;
    for (auto &parameter : value.parameters) {
        require_data_type(parameter.data_type_id);
        if (parameter.ordinal != expected_ordinal++ || parameter.data_type_length < 0) {
            throw std::invalid_argument("function-definition parameter layout is invalid");
        }
        auto parameter_record = new_record(DataTypeTable::function_parameters);
        parameter_record->set_integer(0, value.id);
        parameter_record->set_integer(1, parameter.data_type_id);
        parameter_record->set_string(2, parameter.name);
        parameter_record->set_string(3, parameter.comment);
        parameter_record->set_integer(4, parameter.ordinal);
        parameter_record->set_integer(5, parameter.data_type_length);
        parameter.id = parameter_record->key().as_integer();
        put(DataTypeTable::function_parameters, *parameter_record);
        add_dependency(value.id, parameter.data_type_id);
    }
    const DataType changed = value;
    record_manager_change(&changed, false);
    return value;
}

BitFieldDataType DataTypeManager::create_bitfield(BitFieldDataType value) const {
    require_data_type(value.base_type_id);
    if (value.bit_offset > 7) {
        throw std::invalid_argument("bitfield offset must be between 0 and 7");
    }
    if (value.base_type_id <= 0) {
        throw std::invalid_argument("bitfield requires a resolved integer, typedef, or enum base");
    }
    const auto base_data_type_kind = kind(value.base_type_id);
    if (value.base_kind == BitFieldBaseKind::none) {
        if (base_data_type_kind == DataTypeKind::typedef_type) {
            value.base_kind = BitFieldBaseKind::typedef_type;
        }
        else if (base_data_type_kind == DataTypeKind::enumeration) {
            value.base_kind = BitFieldBaseKind::enumeration;
        }
        else if (base_data_type_kind == DataTypeKind::builtin) {
            value.base_kind = BitFieldBaseKind::integer;
        }
        else {
            throw std::invalid_argument("unsupported bitfield base data type");
        }
    }
    const bool kind_matches =
        (value.base_kind == BitFieldBaseKind::typedef_type &&
         base_data_type_kind == DataTypeKind::typedef_type) ||
        (value.base_kind == BitFieldBaseKind::enumeration &&
         base_data_type_kind == DataTypeKind::enumeration) ||
        (value.base_kind == BitFieldBaseKind::integer &&
         base_data_type_kind == DataTypeKind::builtin);
    if (!kind_matches) throw std::invalid_argument("bitfield base kind does not match its ID");
    const auto index = table_key(value.base_type_id);
    if (index > 0xffffffffULL) {
        throw std::overflow_error("bitfield base data-type index exceeds 32 bits");
    }
    const std::uint64_t base_info =
        (static_cast<std::uint64_t>(value.base_kind) << 5U) |
        (value.extra_storage ? 0x10ULL : 0ULL);
    const std::uint64_t encoded =
        (index << 24U) | (base_info << 16U) |
        (static_cast<std::uint64_t>(value.bit_offset) << 8U) |
        value.declared_bit_size;
    value.id = make_id(DataTypeKind::bitfield,
                       std::bit_cast<std::int64_t>(encoded));
    return value;
}

DataType DataTypeManager::create_data_type(DataType value) {
    return std::visit(
        [this](auto item) -> DataType {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, BuiltinDataType>) {
                return create_builtin(std::move(item));
            }
            else if constexpr (std::is_same_v<T, ArrayDataType>) {
                return create_array(std::move(item));
            }
            else if constexpr (std::is_same_v<T, PointerDataType>) {
                return create_pointer(std::move(item));
            }
            else if constexpr (std::is_same_v<T, TypedefDataType>) {
                return create_typedef(std::move(item));
            }
            else if constexpr (std::is_same_v<T, EnumDataType>) {
                return create_enum(std::move(item));
            }
            else if constexpr (std::is_same_v<T, CompositeDataType>) {
                return create_composite(std::move(item));
            }
            else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                return create_function_definition(std::move(item));
            }
            else {
                return create_bitfield(std::move(item));
            }
        },
        std::move(value));
}

DataType DataTypeManager::update_data_type(DataType value,
                                           DataTypeUpdateMode mode) {
    require_mutation();
    const auto id = data_type_id(value);
    if (id <= 0 || kind(id) == DataTypeKind::bitfield) {
        throw std::invalid_argument("only stored data types can be updated");
    }
    apply_update_timestamp(value, mode);
    validate_data_type(value, id);

    // Child row IDs are stable object identities in ProgramDataTypeManager. A
    // caller may retain an existing row or request a new row with ID 0, but may
    // not steal a row owned by another parent.
    std::visit(
        [&](const auto &item) {
            using T = std::decay_t<decltype(item)>;
            DataTypeTable child_table{};
            std::size_t parent_column = 0;
            std::vector<std::int64_t> requested;
            if constexpr (std::is_same_v<T, EnumDataType>) {
                child_table = DataTypeTable::enumeration_values;
                parent_column = 2;
                for (const auto &entry : item.values) requested.push_back(entry.record_id);
            }
            else if constexpr (std::is_same_v<T, CompositeDataType>) {
                child_table = DataTypeTable::components;
                for (const auto &entry : item.components) requested.push_back(entry.id);
            }
            else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                child_table = DataTypeTable::function_parameters;
                for (const auto &entry : item.parameters) requested.push_back(entry.id);
            }
            else {
                return;
            }
            std::set<std::int64_t> seen;
            for (const auto child_id : requested) {
                if (child_id == 0) continue;
                if (child_id < 0 || !seen.insert(child_id).second) {
                    throw std::invalid_argument("duplicate or invalid child record ID");
                }
                const auto child = record(child_table, child_id);
                if (!child || child->field(parent_column).as_integer() != id) {
                    throw std::invalid_argument(
                        "child record is not owned by the updated data type");
                }
            }
        },
        value);

    std::visit(
        [&](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, BuiltinDataType>) {
                auto raw = slot(DataTypeTable::builtins).expected_schema->create_record(id);
                raw->set_string(0, item.name);
                raw->set_string(1, item.class_name);
                raw->set_integer(2, item.category_id);
                put(DataTypeTable::builtins, *raw);
            }
            else if constexpr (std::is_same_v<T, ArrayDataType>) {
                auto raw = slot(DataTypeTable::arrays).expected_schema->create_record(id);
                raw->set_integer(0, item.element_type_id);
                raw->set_integer(1, item.element_count);
                raw->set_integer(2, item.element_length);
                raw->set_integer(3, item.category_id);
                put(DataTypeTable::arrays, *raw);
            }
            else if constexpr (std::is_same_v<T, PointerDataType>) {
                auto raw = slot(DataTypeTable::pointers).expected_schema->create_record(id);
                raw->set_integer(0, item.referenced_type_id);
                raw->set_integer(1, item.category_id);
                raw->set_integer(2, item.length);
                put(DataTypeTable::pointers, *raw);
            }
            else if constexpr (std::is_same_v<T, TypedefDataType>) {
                auto raw = slot(DataTypeTable::typedefs).expected_schema->create_record(id);
                raw->set_integer(0, item.referenced_type_id);
                raw->set_integer(1, item.flags);
                raw->set_string(2, item.name);
                raw->set_integer(3, item.category_id);
                raw->set_integer(4, item.provenance.source_archive_id);
                raw->set_integer(5, item.provenance.universal_id);
                raw->set_integer(6, item.provenance.source_sync_time);
                raw->set_integer(7, item.provenance.last_change_time);
                put(DataTypeTable::typedefs, *raw);
            }
            else if constexpr (std::is_same_v<T, EnumDataType>) {
                auto raw = slot(DataTypeTable::enumerations).expected_schema->create_record(id);
                raw->set_string(0, item.name);
                raw->set_string(1, item.comment);
                raw->set_integer(2, item.category_id);
                raw->set_integer(3, item.size);
                raw->set_integer(4, item.provenance.source_archive_id);
                raw->set_integer(5, item.provenance.universal_id);
                raw->set_integer(6, item.provenance.source_sync_time);
                raw->set_integer(7, item.provenance.last_change_time);
                put(DataTypeTable::enumerations, *raw);

                db::IntegerField parent(db::FieldType::int64, id);
                std::set<std::int64_t> retained;
                for (auto &entry : item.values) {
                    std::unique_ptr<db::Record> child;
                    if (entry.record_id == 0) {
                        child = new_record(DataTypeTable::enumeration_values);
                        entry.record_id = child->key().as_integer();
                    }
                    else {
                        child = slot(DataTypeTable::enumeration_values)
                                    .expected_schema->create_record(entry.record_id);
                    }
                    child->set_string(0, entry.name);
                    child->set_integer(1, entry.value);
                    child->set_integer(2, id);
                    child->set_string(3, entry.comment);
                    put(DataTypeTable::enumeration_values, *child);
                    retained.insert(entry.record_id);
                }
                for (const auto old_child : record_ids_by_index(
                         DataTypeTable::enumeration_values, 2, parent)) {
                    if (!retained.contains(old_child)) {
                        (void)erase(DataTypeTable::enumeration_values, old_child);
                    }
                }
            }
            else if constexpr (std::is_same_v<T, CompositeDataType>) {
                auto raw = slot(DataTypeTable::composites).expected_schema->create_record(id);
                raw->set_string(0, item.name);
                raw->set_string(1, item.comment);
                raw->set_boolean(2, item.is_union);
                raw->set_integer(3, item.category_id);
                raw->set_integer(4, item.length);
                raw->set_integer(5, item.alignment);
                raw->set_integer(6, static_cast<std::int32_t>(item.components.size()));
                raw->set_integer(7, item.provenance.source_archive_id);
                raw->set_integer(8, item.provenance.universal_id);
                raw->set_integer(9, item.provenance.source_sync_time);
                raw->set_integer(10, item.provenance.last_change_time);
                raw->set_integer(11, item.packing);
                raw->set_integer(12, item.minimum_alignment);
                put(DataTypeTable::composites, *raw);

                db::IntegerField parent(db::FieldType::int64, id);
                std::set<std::int64_t> retained;
                for (auto &entry : item.components) {
                    std::unique_ptr<db::Record> child;
                    if (entry.id == 0) {
                        child = new_record(DataTypeTable::components);
                        entry.id = child->key().as_integer();
                    }
                    else {
                        child = slot(DataTypeTable::components)
                                    .expected_schema->create_record(entry.id);
                    }
                    child->set_integer(0, id);
                    child->set_integer(1, entry.offset);
                    child->set_integer(2, entry.data_type_id);
                    child->set_string(3, entry.field_name);
                    child->set_string(4, entry.comment);
                    child->set_integer(5, entry.length);
                    child->set_integer(6, entry.ordinal);
                    put(DataTypeTable::components, *child);
                    retained.insert(entry.id);
                }
                for (const auto old_child :
                     record_ids_by_index(DataTypeTable::components, 0, parent)) {
                    if (!retained.contains(old_child)) {
                        (void)erase(DataTypeTable::components, old_child);
                    }
                }
            }
            else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                auto raw = slot(DataTypeTable::function_definitions)
                               .expected_schema->create_record(id);
                raw->set_string(0, item.name);
                raw->set_string(1, item.comment);
                raw->set_integer(2, item.category_id);
                raw->set_integer(3, item.return_type_id);
                raw->set_integer(4, (item.variadic ? 1 : 0) |
                                        (item.no_return ? 2 : 0));
                raw->set_integer(5, item.calling_convention_id);
                raw->set_integer(6, item.provenance.source_archive_id);
                raw->set_integer(7, item.provenance.universal_id);
                raw->set_integer(8, item.provenance.source_sync_time);
                raw->set_integer(9, item.provenance.last_change_time);
                put(DataTypeTable::function_definitions, *raw);

                db::IntegerField parent(db::FieldType::int64, id);
                std::set<std::int64_t> retained;
                for (auto &entry : item.parameters) {
                    std::unique_ptr<db::Record> child;
                    if (entry.id == 0) {
                        child = new_record(DataTypeTable::function_parameters);
                        entry.id = child->key().as_integer();
                    }
                    else {
                        child = slot(DataTypeTable::function_parameters)
                                    .expected_schema->create_record(entry.id);
                    }
                    child->set_integer(0, id);
                    child->set_integer(1, entry.data_type_id);
                    child->set_string(2, entry.name);
                    child->set_string(3, entry.comment);
                    child->set_integer(4, entry.ordinal);
                    child->set_integer(5, entry.data_type_length);
                    put(DataTypeTable::function_parameters, *child);
                    retained.insert(entry.id);
                }
                for (const auto old_child : record_ids_by_index(
                         DataTypeTable::function_parameters, 0, parent)) {
                    if (!retained.contains(old_child)) {
                        (void)erase(DataTypeTable::function_parameters, old_child);
                    }
                }
            }
            else {
                throw std::invalid_argument("virtual bitfields cannot be updated");
            }
        },
        value);

    remove_dependencies(id);
    std::visit(
        [&](const auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, ArrayDataType>) {
                add_dependency(id, item.element_type_id);
            }
            else if constexpr (std::is_same_v<T, PointerDataType>) {
                add_dependency(id, item.referenced_type_id);
            }
            else if constexpr (std::is_same_v<T, TypedefDataType>) {
                add_dependency(id, item.referenced_type_id);
            }
            else if constexpr (std::is_same_v<T, CompositeDataType>) {
                for (const auto &entry : item.components) {
                    add_dependency(id, entry.data_type_id);
                }
            }
            else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                add_dependency(id, item.return_type_id);
                for (const auto &entry : item.parameters) {
                    add_dependency(id, entry.data_type_id);
                }
            }
        },
        value);
    record_manager_change(&value, mode == DataTypeUpdateMode::local_change);
    return value;
}

std::optional<DataType> DataTypeManager::data_type(std::int64_t id) const {
    if (id <= 0) return std::nullopt;
    switch (kind(id)) {
    case DataTypeKind::builtin: {
        auto raw = record(DataTypeTable::builtins, id);
        if (!raw) return std::nullopt;
        return BuiltinDataType{id, raw->field(0).as_string().value_or(std::string{}),
                               raw->field(1).as_string().value_or(std::string{}),
                               raw->field(2).as_integer()};
    }
    case DataTypeKind::array: {
        auto raw = record(DataTypeTable::arrays, id);
        if (!raw) return std::nullopt;
        return ArrayDataType{id, raw->field(0).as_integer(),
                             static_cast<std::int32_t>(raw->field(1).as_integer()),
                             static_cast<std::int32_t>(raw->field(2).as_integer()),
                             raw->field(3).as_integer()};
    }
    case DataTypeKind::pointer: {
        auto raw = record(DataTypeTable::pointers, id);
        if (!raw) return std::nullopt;
        return PointerDataType{id, raw->field(0).as_integer(),
                               raw->field(1).as_integer(),
                               static_cast<std::int32_t>(raw->field(2).as_integer())};
    }
    case DataTypeKind::typedef_type: {
        auto raw = record(DataTypeTable::typedefs, id);
        if (!raw) return std::nullopt;
        return TypedefDataType{
            id, raw->field(0).as_integer(),
            static_cast<std::uint16_t>(raw->field(1).as_integer()),
            raw->field(2).as_string().value_or(std::string{}),
            raw->field(3).as_integer(),
            {raw->field(4).as_integer(), raw->field(5).as_integer(),
             raw->field(6).as_integer(), raw->field(7).as_integer()}};
    }
    case DataTypeKind::enumeration: {
        auto raw = record(DataTypeTable::enumerations, id);
        if (!raw) return std::nullopt;
        EnumDataType value;
        value.id = id;
        value.name = raw->field(0).as_string().value_or(std::string{});
        value.comment = raw->field(1).as_string();
        value.category_id = raw->field(2).as_integer();
        value.size = static_cast<std::uint8_t>(raw->field(3).as_integer());
        value.provenance = {raw->field(4).as_integer(), raw->field(5).as_integer(),
                            raw->field(6).as_integer(), raw->field(7).as_integer()};
        db::IntegerField enum_id(db::FieldType::int64, id);
        for (const auto value_id :
             record_ids_by_index(DataTypeTable::enumeration_values, 2, enum_id)) {
            auto item = record(DataTypeTable::enumeration_values, value_id);
            value.values.push_back({value_id,
                                    item->field(0).as_string().value_or(std::string{}),
                                    item->field(1).as_integer(), item->field(3).as_string()});
        }
        return value;
    }
    case DataTypeKind::composite: {
        auto raw = record(DataTypeTable::composites, id);
        if (!raw) return std::nullopt;
        CompositeDataType value;
        value.id = id;
        value.name = raw->field(0).as_string().value_or(std::string{});
        value.comment = raw->field(1).as_string();
        value.is_union = raw->field(2).as_boolean();
        value.category_id = raw->field(3).as_integer();
        value.length = static_cast<std::int32_t>(raw->field(4).as_integer());
        value.alignment = static_cast<std::int32_t>(raw->field(5).as_integer());
        value.provenance = {raw->field(7).as_integer(), raw->field(8).as_integer(),
                            raw->field(9).as_integer(), raw->field(10).as_integer()};
        value.packing = static_cast<std::int32_t>(raw->field(11).as_integer());
        value.minimum_alignment = static_cast<std::int32_t>(raw->field(12).as_integer());
        db::IntegerField parent(db::FieldType::int64, id);
        for (const auto component_id :
             record_ids_by_index(DataTypeTable::components, 0, parent)) {
            auto item = record(DataTypeTable::components, component_id);
            value.components.push_back(
                {component_id, item->field(2).as_integer(),
                 static_cast<std::int32_t>(item->field(1).as_integer()),
                 item->field(3).as_string(), item->field(4).as_string(),
                 static_cast<std::int32_t>(item->field(5).as_integer()),
                 static_cast<std::int32_t>(item->field(6).as_integer())});
        }
        std::ranges::sort(value.components, {}, &CompositeComponent::ordinal);
        return value;
    }
    case DataTypeKind::function_definition: {
        auto raw = record(DataTypeTable::function_definitions, id);
        if (!raw) return std::nullopt;
        FunctionDefinitionDataType value;
        value.id = id;
        value.name = raw->field(0).as_string().value_or(std::string{});
        value.comment = raw->field(1).as_string();
        value.category_id = raw->field(2).as_integer();
        value.return_type_id = raw->field(3).as_integer();
        const auto flags = static_cast<std::uint8_t>(raw->field(4).as_integer());
        value.variadic = (flags & 1) != 0;
        value.no_return = (flags & 2) != 0;
        value.calling_convention_id =
            static_cast<std::uint8_t>(raw->field(5).as_integer());
        value.provenance = {raw->field(6).as_integer(), raw->field(7).as_integer(),
                            raw->field(8).as_integer(), raw->field(9).as_integer()};
        db::IntegerField parent(db::FieldType::int64, id);
        for (const auto parameter_id :
             record_ids_by_index(DataTypeTable::function_parameters, 0, parent)) {
            auto item = record(DataTypeTable::function_parameters, parameter_id);
            value.parameters.push_back(
                {parameter_id, item->field(1).as_integer(),
                 item->field(2).as_string().value_or(std::string{}),
                 item->field(3).as_string(),
                 static_cast<std::int32_t>(item->field(4).as_integer()),
                 static_cast<std::int32_t>(item->field(5).as_integer())});
        }
        std::ranges::sort(value.parameters, {}, &FunctionDefinitionParameter::ordinal);
        return value;
    }
    case DataTypeKind::bitfield: {
        const auto encoded = table_key(id);
        BitFieldDataType value;
        value.id = id;
        value.declared_bit_size = static_cast<std::uint8_t>(encoded & 0xffU);
        value.bit_offset = static_cast<std::uint8_t>((encoded >> 8U) & 0xffU);
        const auto base_info = static_cast<std::uint8_t>((encoded >> 16U) & 0xffU);
        value.base_kind = static_cast<BitFieldBaseKind>((base_info >> 5U) & 0x03U);
        value.extra_storage = (base_info & 0x10U) != 0;
        const auto index = (encoded >> 24U) & 0xffffffffULL;
        switch (value.base_kind) {
        case BitFieldBaseKind::typedef_type:
            value.base_type_id = make_id(DataTypeKind::typedef_type,
                                         static_cast<std::int64_t>(index));
            break;
        case BitFieldBaseKind::enumeration:
            value.base_type_id = make_id(DataTypeKind::enumeration,
                                         static_cast<std::int64_t>(index));
            break;
        case BitFieldBaseKind::integer:
            value.base_type_id = make_id(DataTypeKind::builtin,
                                         static_cast<std::int64_t>(index));
            break;
        case BitFieldBaseKind::none:
            value.base_type_id = 0;
            break;
        }
        if (value.bit_offset > 7 || value.base_kind == BitFieldBaseKind::none ||
            !contains_data_type(value.base_type_id)) {
            return std::nullopt;
        }
        return value;
    }
    case DataTypeKind::component:
    case DataTypeKind::function_parameter:
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<DataType> DataTypeManager::data_type_named(
    std::int64_t category_id,
    const std::string &name) const {
    for (auto &value : all_data_types()) {
        const auto value_category = data_type_category(value);
        const auto value_name = data_type_name(value);
        if (value_category && value_name && *value_category == category_id &&
            *value_name == name) {
            return value;
        }
    }
    return std::nullopt;
}

std::optional<DataType> DataTypeManager::data_type_by_universal_id(
    std::int64_t source_archive_id,
    std::int64_t universal_id) const {
    if (universal_id == 0) return std::nullopt;
    struct IdentityTable {
        DataTypeTable table;
        std::size_t source_column;
        std::size_t universal_column;
    };
    constexpr IdentityTable identity_tables[] = {
        {DataTypeTable::typedefs, 4, 5},
        {DataTypeTable::composites, 7, 8},
        {DataTypeTable::function_definitions, 6, 7},
        {DataTypeTable::enumerations, 4, 5},
    };
    db::IntegerField universal(db::FieldType::int64, universal_id);
    for (const auto &entry : identity_tables) {
        for (const auto id :
             record_ids_by_index(entry.table, entry.universal_column, universal)) {
            auto raw = record(entry.table, id);
            if (raw && raw->field(entry.source_column).as_integer() ==
                           source_archive_id) {
                return data_type(id);
            }
        }
    }
    return std::nullopt;
}

std::vector<DataType> DataTypeManager::data_types_by_base_name(
    std::int64_t category_id,
    const std::string &name) const {
    const auto base = conflict_base_name(name);
    std::vector<DataType> result;
    for (auto &value : all_data_types()) {
        const auto value_category = data_type_category(value);
        const auto value_name = data_type_name(value);
        if (value_category && value_name && *value_category == category_id &&
            conflict_base_name(*value_name) == base) {
            result.push_back(std::move(value));
        }
    }
    return result;
}

std::string DataTypeManager::unused_conflict_name(
    std::int64_t category_id,
    const std::string &name) const {
    require_category(category_id);
    const auto base = conflict_base_name(name);
    std::string candidate = base;
    std::size_t suffix = 0;
    while (data_type_named(category_id, candidate)) {
        candidate = base + ".conflict";
        if (suffix != 0) candidate += std::to_string(suffix);
        ++suffix;
    }
    return candidate;
}

bool DataTypeManager::equivalent(const DataType &left,
                                 const DataType &right) const {
    std::vector<std::pair<std::int64_t, std::int64_t>> active;
    return equivalent_impl(left, right, active);
}

bool DataTypeManager::equivalent_impl(
    const DataType &left,
    const DataType &right,
    std::vector<std::pair<std::int64_t, std::int64_t>> &active) const {
    if (left.index() != right.index()) return false;
    const auto left_id = data_type_id(left);
    const auto right_id = data_type_id(right);
    if (left_id > 0 && left_id == right_id) return true;
    const auto pair = std::pair{left_id, right_id};
    if (left_id > 0 && right_id > 0 &&
        std::ranges::find(active, pair) != active.end()) {
        return true;
    }
    if (left_id > 0 && right_id > 0) active.push_back(pair);

    const auto referenced_types_equal = [&](std::int64_t left_reference,
                                            std::int64_t right_reference) {
        if (left_reference == right_reference) return true;
        const auto left_type = data_type(left_reference);
        const auto right_type = data_type(right_reference);
        return left_type && right_type &&
               equivalent_impl(*left_type, *right_type, active);
    };

    bool result = false;
    switch (left.index()) {
    case 0: {
        const auto &a = std::get<BuiltinDataType>(left);
        const auto &b = std::get<BuiltinDataType>(right);
        result = conflict_base_name(a.name) == conflict_base_name(b.name) &&
                 a.class_name == b.class_name;
        break;
    }
    case 1: {
        const auto &a = std::get<ArrayDataType>(left);
        const auto &b = std::get<ArrayDataType>(right);
        result = a.element_count == b.element_count &&
                 a.element_length == b.element_length &&
                 referenced_types_equal(a.element_type_id, b.element_type_id);
        break;
    }
    case 2: {
        const auto &a = std::get<PointerDataType>(left);
        const auto &b = std::get<PointerDataType>(right);
        result = a.length == b.length &&
                 referenced_types_equal(a.referenced_type_id,
                                        b.referenced_type_id);
        break;
    }
    case 3: {
        const auto &a = std::get<TypedefDataType>(left);
        const auto &b = std::get<TypedefDataType>(right);
        result = conflict_base_name(a.name) == conflict_base_name(b.name) &&
                 a.flags == b.flags &&
                 referenced_types_equal(a.referenced_type_id,
                                        b.referenced_type_id);
        break;
    }
    case 4: {
        const auto &a = std::get<EnumDataType>(left);
        const auto &b = std::get<EnumDataType>(right);
        if (conflict_base_name(a.name) == conflict_base_name(b.name) &&
            a.comment == b.comment && a.size == b.size &&
            a.values.size() == b.values.size()) {
            result = true;
            for (const auto &entry : a.values) {
                const auto match = std::ranges::find_if(
                    b.values, [&](const EnumValue &candidate) {
                        return candidate.name == entry.name;
                    });
                if (match == b.values.end() || match->value != entry.value ||
                    match->comment != entry.comment) {
                    result = false;
                    break;
                }
            }
        }
        break;
    }
    case 5: {
        const auto &a = std::get<CompositeDataType>(left);
        const auto &b = std::get<CompositeDataType>(right);
        result = conflict_base_name(a.name) == conflict_base_name(b.name) &&
                 a.comment == b.comment && a.is_union == b.is_union &&
                 a.length == b.length && a.alignment == b.alignment &&
                 a.packing == b.packing &&
                 a.minimum_alignment == b.minimum_alignment &&
                 a.components.size() == b.components.size();
        for (std::size_t i = 0; result && i < a.components.size(); ++i) {
            const auto &x = a.components[i];
            const auto &y = b.components[i];
            result = x.offset == y.offset && x.field_name == y.field_name &&
                     x.comment == y.comment && x.length == y.length &&
                     x.ordinal == y.ordinal &&
                     referenced_types_equal(x.data_type_id, y.data_type_id);
        }
        break;
    }
    case 6: {
        const auto &a = std::get<FunctionDefinitionDataType>(left);
        const auto &b = std::get<FunctionDefinitionDataType>(right);
        result = conflict_base_name(a.name) == conflict_base_name(b.name) &&
                 a.comment == b.comment && a.variadic == b.variadic &&
                 a.no_return == b.no_return &&
                 a.calling_convention_id == b.calling_convention_id &&
                 a.parameters.size() == b.parameters.size() &&
                 referenced_types_equal(a.return_type_id, b.return_type_id);
        for (std::size_t i = 0; result && i < a.parameters.size(); ++i) {
            const auto &x = a.parameters[i];
            const auto &y = b.parameters[i];
            result = x.name == y.name && x.comment == y.comment &&
                     x.ordinal == y.ordinal &&
                     x.data_type_length == y.data_type_length &&
                     referenced_types_equal(x.data_type_id, y.data_type_id);
        }
        break;
    }
    case 7: {
        const auto &a = std::get<BitFieldDataType>(left);
        const auto &b = std::get<BitFieldDataType>(right);
        result = a.base_kind == b.base_kind &&
                 a.declared_bit_size == b.declared_bit_size &&
                 a.bit_offset == b.bit_offset &&
                 a.extra_storage == b.extra_storage &&
                 referenced_types_equal(a.base_type_id, b.base_type_id);
        break;
    }
    default: break;
    }
    if (left_id > 0 && right_id > 0) active.pop_back();
    return result;
}

bool DataTypeManager::dependency_reaches(
    std::int64_t current_id,
    std::int64_t target_id,
    std::vector<std::int64_t> &active) const {
    if (current_id == target_id) return true;
    if (current_id <= 0 ||
        std::ranges::find(active, current_id) != active.end()) {
        return false;
    }
    active.push_back(current_id);
    if (kind(current_id) == DataTypeKind::bitfield) {
        const auto value = data_type(current_id);
        const bool result = value &&
                            dependency_reaches(
                                std::get<BitFieldDataType>(*value).base_type_id,
                                target_id, active);
        active.pop_back();
        return result;
    }
    for (const auto child : child_data_types(current_id)) {
        if (dependency_reaches(child, target_id, active)) {
            active.pop_back();
            return true;
        }
    }
    active.pop_back();
    return false;
}

bool DataTypeManager::depends_on(std::int64_t parent_id,
                                 std::int64_t candidate_ancestor_id) const {
    if (!contains_data_type(parent_id) ||
        !contains_data_type(candidate_ancestor_id)) {
        return false;
    }
    std::vector<std::int64_t> active;
    for (const auto child : child_data_types(parent_id)) {
        if (dependency_reaches(child, candidate_ancestor_id, active)) return true;
    }
    return false;
}

bool DataTypeManager::contains_data_type(std::int64_t id) const {
    return id == 0 || id == -1 || id == -2 || data_type(id).has_value();
}

std::vector<DataType> DataTypeManager::all_data_types() const {
    std::vector<DataType> result;
    for (const auto table_id : {DataTypeTable::builtins, DataTypeTable::arrays,
                                DataTypeTable::pointers, DataTypeTable::typedefs,
                                DataTypeTable::composites,
                                DataTypeTable::function_definitions,
                                DataTypeTable::enumerations}) {
        for (auto &raw : records(table_id)) {
            if (auto value = data_type(raw->key().as_integer())) {
                result.push_back(std::move(*value));
            }
        }
    }
    return result;
}

void DataTypeManager::rewrite_bitfield_base(
    DataType &parent,
    std::int64_t replaced_id,
    std::int64_t replacement_id) const {
    const auto remap = [&](std::int64_t id) {
        if (id == replaced_id) return replacement_id;
        if (id <= 0 || kind(id) != DataTypeKind::bitfield) return id;
        const auto decoded = data_type(id);
        if (!decoded) {
            throw std::runtime_error("parent references an invalid bitfield ID");
        }
        auto bitfield = std::get<BitFieldDataType>(*decoded);
        if (bitfield.base_type_id != replaced_id) return id;
        bitfield.base_type_id = replacement_id;
        bitfield.base_kind = BitFieldBaseKind::none;
        bitfield.id = 0;
        return create_bitfield(bitfield).id;
    };
    std::visit(
        [&](auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, ArrayDataType>) {
                value.element_type_id = remap(value.element_type_id);
            }
            else if constexpr (std::is_same_v<T, PointerDataType> ||
                               std::is_same_v<T, TypedefDataType>) {
                value.referenced_type_id = remap(value.referenced_type_id);
            }
            else if constexpr (std::is_same_v<T, CompositeDataType>) {
                for (auto &component : value.components) {
                    component.data_type_id = remap(component.data_type_id);
                }
            }
            else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                value.return_type_id = remap(value.return_type_id);
                for (auto &parameter : value.parameters) {
                    parameter.data_type_id = remap(parameter.data_type_id);
                }
            }
            else if constexpr (std::is_same_v<T, BitFieldDataType>) {
                value.base_type_id = remap(value.base_type_id);
            }
        },
        parent);
}

DataType DataTypeManager::replace_data_type(std::int64_t replaced_id,
                                            std::int64_t replacement_id) {
    require_mutation();
    if (replaced_id <= 0 || replacement_id <= 0 ||
        replaced_id == replacement_id) {
        throw std::invalid_argument("datatype replacement IDs are invalid");
    }
    const auto replaced = data_type(replaced_id);
    const auto replacement = data_type(replacement_id);
    if (!replaced || !replacement ||
        kind(replaced_id) == DataTypeKind::bitfield ||
        kind(replacement_id) == DataTypeKind::bitfield) {
        throw std::invalid_argument("replacement requires two stored data types");
    }
    if (depends_on(replacement_id, replaced_id)) {
        throw std::invalid_argument("replacement data type depends on replaced data type");
    }

    auto parents = parent_data_types(replaced_id);
    std::ranges::sort(parents);
    parents.erase(std::unique(parents.begin(), parents.end()), parents.end());
    std::vector<DataType> rewritten_parents;
    rewritten_parents.reserve(parents.size());
    for (const auto parent_id : parents) {
        if (parent_id == replacement_id) {
            throw std::invalid_argument("replacement would create a dependency cycle");
        }
        if (kind(replacement_id) != DataTypeKind::pointer &&
            depends_on(replacement_id, parent_id)) {
            throw std::invalid_argument("replacement would create a dependency cycle");
        }
        auto parent = data_type(parent_id);
        if (!parent) {
            throw std::runtime_error(
                "datatype dependency graph references a missing parent");
        }
        rewrite_bitfield_base(*parent, replaced_id, replacement_id);
        validate_data_type(*parent, parent_id);
        rewritten_parents.push_back(std::move(*parent));
    }
    for (auto &parent : rewritten_parents) {
        (void)update_data_type(std::move(parent),
                               DataTypeUpdateMode::local_change);
    }
    if (external_replacement_handler_) {
        external_replacement_handler_(replaced_id, replacement_id);
    }
    if (!remove_data_type(replaced_id)) {
        throw std::runtime_error("replaced data type disappeared during replacement");
    }
    if (!deduplicating_automatic_types_) {
        deduplicating_automatic_types_ = true;
        try {
            deduplicate_automatic_data_types(replacement_id);
            deduplicating_automatic_types_ = false;
        }
        catch (...) {
            deduplicating_automatic_types_ = false;
            throw;
        }
    }
    return *data_type(replacement_id);
}

void DataTypeManager::deduplicate_automatic_data_types(
    std::int64_t preferred_id) {
    // Array and Pointer names are derived from their children.  A child
    // replacement can therefore make two previously distinct rows identical.
    // Collapse one pair at a time and restart from the current graph because
    // replacing the duplicate may expose another equivalent parent.
    for (;;) {
        auto all = all_data_types();
        bool collapsed = false;
        for (std::size_t left = 0; left < all.size() && !collapsed; ++left) {
            const bool automatic = std::holds_alternative<ArrayDataType>(all[left]) ||
                                   std::holds_alternative<PointerDataType>(all[left]);
            if (!automatic) continue;
            for (std::size_t right = left + 1; right < all.size(); ++right) {
                if (all[left].index() != all[right].index() ||
                    data_type_category(all[left]) != data_type_category(all[right]) ||
                    !equivalent(all[left], all[right])) {
                    continue;
                }
                auto keep_id = data_type_id(all[left]);
                auto discard_id = data_type_id(all[right]);
                if (discard_id == preferred_id ||
                    (keep_id != preferred_id && table_key(discard_id) < table_key(keep_id))) {
                    std::swap(keep_id, discard_id);
                }
                (void)replace_data_type(discard_id, keep_id);
                collapsed = true;
                break;
            }
        }
        if (!collapsed) return;
    }
}

DataType DataTypeManager::resolve_data_type(DataType value,
                                            DataTypeConflictPolicy policy) {
    require_mutation();
    const auto supplied_id = data_type_id(value);
    if (supplied_id > 0 && contains_data_type(supplied_id)) {
        return *data_type(supplied_id);
    }
    set_data_type_id(value, 0);

    // Program and temporary archives do not transfer source identity into a
    // ProgramDataTypeManager. Local named types receive a fresh identity.
    std::visit(
        [&](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                if (item.provenance.source_archive_id != local_archive_id &&
                    item.provenance.source_archive_id != builtin_archive_id) {
                    const auto archive = source_archive(
                        item.provenance.source_archive_id);
                    if (!archive) {
                        throw std::out_of_range("source archive does not exist");
                    }
                    if (archive->type == SourceArchiveType::program ||
                        archive->type == SourceArchiveType::temporary) {
                        item.provenance.source_archive_id = local_archive_id;
                        item.provenance.universal_id = next_local_universal_id();
                        item.provenance.source_sync_time = 0;
                    }
                }
                if (item.provenance.universal_id == 0) {
                    item.provenance.universal_id = next_local_universal_id();
                }
            }
        },
        value);

    std::optional<DataTypeProvenance> provenance;
    std::visit(
        [&](const auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                provenance = item.provenance;
            }
        },
        value);
    if (provenance && provenance->universal_id != 0) {
        if (auto identified = data_type_by_universal_id(
                provenance->source_archive_id, provenance->universal_id)) {
            if (equivalent(*identified, value) ||
                policy == DataTypeConflictPolicy::use_existing) {
                return *identified;
            }
            if (identified->index() == value.index()) {
                set_data_type_id(value, data_type_id(*identified));
                return update_data_type(std::move(value),
                                        DataTypeUpdateMode::source_sync);
            }
        }
    }

    const auto category_id = data_type_category(value);
    const auto name = data_type_name(value);
    if (!category_id || !name) {
        // Pointer and array names are derived. Reuse an equivalent automatic
        // type rather than creating duplicate rows.
        for (const auto &existing : all_data_types()) {
            if (existing.index() == value.index() &&
                data_type_category(existing) == category_id &&
                equivalent(existing, value)) {
                return existing;
            }
        }
        return create_data_type(std::move(value));
    }

    for (const auto &candidate : data_types_by_base_name(*category_id, *name)) {
        if (equivalent(candidate, value)) return candidate;
    }
    auto existing = data_type_named(*category_id, *name);
    if (!existing) return create_data_type(std::move(value));

    if (policy == DataTypeConflictPolicy::use_existing) return *existing;
    if (policy ==
        DataTypeConflictPolicy::replace_empty_composites_or_rename_and_add) {
        if (std::holds_alternative<CompositeDataType>(*existing) &&
            std::holds_alternative<CompositeDataType>(value)) {
            const auto &old_composite = std::get<CompositeDataType>(*existing);
            const auto &new_composite = std::get<CompositeDataType>(value);
            if (old_composite.is_union == new_composite.is_union) {
                if (new_composite.components.empty()) return *existing;
                if (old_composite.components.empty()) {
                    set_data_type_id(value, old_composite.id);
                    return update_data_type(std::move(value),
                                            DataTypeUpdateMode::source_sync);
                }
            }
        }
        policy = DataTypeConflictPolicy::rename_and_add;
    }
    if (policy == DataTypeConflictPolicy::replace_existing) {
        if (existing->index() == value.index() &&
            !std::holds_alternative<BuiltinDataType>(value)) {
            set_data_type_id(value, data_type_id(*existing));
            return update_data_type(std::move(value),
                                    DataTypeUpdateMode::source_sync);
        }

        // Different persisted kinds cannot change their high-byte ID tag.
        // Move the old type aside, create the requested kind under the exact
        // name, then redirect all datatype and ProgramDB uses before deletion.
        auto renamed = *existing;
        set_data_type_name(
            renamed, unused_conflict_name(*category_id, *name));
        renamed = update_data_type(std::move(renamed),
                                   DataTypeUpdateMode::local_change);
        auto created = create_data_type(std::move(value));
        return replace_data_type(data_type_id(renamed), data_type_id(created));
    }

    set_data_type_name(value, unused_conflict_name(*category_id, *name));
    return create_data_type(std::move(value));
}

void DataTypeManager::set_external_replacement_handler(
    std::function<void(std::int64_t, std::int64_t)> handler) {
    external_replacement_handler_ = std::move(handler);
}

void DataTypeManager::set_external_deletion_handler(
    std::function<void(std::int64_t)> handler) {
    external_deletion_handler_ = std::move(handler);
}

void DataTypeManager::finish_legacy_source_archive_upgrade() {
    if (mode_ != ProgramOpenMode::upgrade) return;
    require_mutation();

    // Fixed SourceArchiveUpgradeMap replacements used by upstream ProgramDB.
    // The historical CLIB mapping is intentionally the final generic_clib
    // mapping installed by that class; Windows and NTDDK become local.
    constexpr std::int64_t old_clib_archive = 2585014296036210369LL;
    constexpr std::int64_t old_windows_archive = 2592694847825635591LL;
    constexpr std::int64_t old_ntddk_archive = 2585014353215059675LL;
    constexpr std::int64_t generic_clib_archive = 2644097909188870631LL;

    if (source_archive(old_clib_archive)) {
        replace_source_archive(
            old_clib_archive,
            SourceArchiveRecord{generic_clib_archive, std::nullopt,
                                std::string("generic_clib"),
                                SourceArchiveType::file, 0, false});
    }
    const auto local = source_archive(local_archive_id);
    if (!local) {
        throw std::runtime_error("local source archive is missing after upgrade");
    }
    for (const auto old_id : {old_windows_archive, old_ntddk_archive}) {
        if (source_archive(old_id)) {
            replace_source_archive(old_id, *local);
        }
    }

    // Upstream then replaces these obsolete root typedefs with their built-in
    // counterparts. Existing ProgramDBs normally already contain the built-in
    // rows; only perform a replacement when the exact counterpart is present,
    // avoiding fabrication of a Java class identity in the native manager.
    constexpr std::array<std::string_view, 6> obsolete_typedefs = {
        "short", "int", "long", "longlong", "wchar_t", "bool"};
    for (const auto name : obsolete_typedefs) {
        std::optional<std::int64_t> typedef_id;
        std::optional<std::int64_t> builtin_id;
        for (auto &record : records(DataTypeTable::typedefs)) {
            if (record->field(3).as_integer() == root_category_id &&
                record->field(2).as_string() ==
                    std::optional<std::string>(std::string(name))) {
                typedef_id = record->key().as_integer();
                break;
            }
        }
        for (auto &record : records(DataTypeTable::builtins)) {
            if (record->field(2).as_integer() == root_category_id &&
                record->field(0).as_string() ==
                    std::optional<std::string>(std::string(name))) {
                builtin_id = record->key().as_integer();
                break;
            }
        }
        if (typedef_id && builtin_id) {
            (void)replace_data_type(*typedef_id, *builtin_id);
        }
    }
}

void DataTypeManager::language_changed(
    const ProgramArchitecture &architecture) {
    require_mutation();
    architecture_ = &architecture;
    std::vector<std::int64_t> packed_composites;
    for (const auto &value : all_data_types()) {
        if (const auto *composite = std::get_if<CompositeDataType>(&value);
            composite && composite->packing != CompositeDataType::no_packing) {
            packed_composites.push_back(composite->id);
        }
    }
    std::ranges::sort(packed_composites);
    for (const auto id : packed_composites) {
        (void)repack_composite(
            id, architecture.data_organization, architecture.endian,
            DataTypeUpdateMode::preserve_timestamps);
    }
}

void DataTypeManager::rebind_architecture(
    const ProgramArchitecture *architecture) noexcept {
    architecture_ = architecture;
}

bool DataTypeManager::remove_data_type(std::int64_t id) {
    require_mutation();
    if (id <= 0) throw std::invalid_argument("reserved data type cannot be removed");
    if (!parent_data_types(id).empty()) {
        throw std::logic_error("data type is still referenced by parent data types");
    }
    const auto value = data_type(id);
    if (!value) return false;
    if (external_deletion_handler_) external_deletion_handler_(id);
    DataTypeTable primary_table;
    switch (kind(id)) {
    case DataTypeKind::builtin: primary_table = DataTypeTable::builtins; break;
    case DataTypeKind::array: primary_table = DataTypeTable::arrays; break;
    case DataTypeKind::pointer: primary_table = DataTypeTable::pointers; break;
    case DataTypeKind::typedef_type: primary_table = DataTypeTable::typedefs; break;
    case DataTypeKind::enumeration: {
        primary_table = DataTypeTable::enumerations;
        db::IntegerField enum_id(db::FieldType::int64, id);
        for (const auto child :
             record_ids_by_index(DataTypeTable::enumeration_values, 2, enum_id)) {
            (void)erase(DataTypeTable::enumeration_values, child);
        }
        break;
    }
    case DataTypeKind::composite: {
        primary_table = DataTypeTable::composites;
        db::IntegerField parent(db::FieldType::int64, id);
        for (const auto child : record_ids_by_index(DataTypeTable::components, 0, parent)) {
            (void)erase(DataTypeTable::components, child);
        }
        break;
    }
    case DataTypeKind::function_definition: {
        primary_table = DataTypeTable::function_definitions;
        db::IntegerField parent(db::FieldType::int64, id);
        for (const auto child :
             record_ids_by_index(DataTypeTable::function_parameters, 0, parent)) {
            (void)erase(DataTypeTable::function_parameters, child);
        }
        break;
    }
    case DataTypeKind::component:
    case DataTypeKind::function_parameter:
    case DataTypeKind::bitfield:
        throw std::invalid_argument("ID is not a standalone stored data type");
    }
    remove_dependencies(id);
    clear_settings(false, id);
    const bool removed = erase(primary_table, id);
    if (removed) record_manager_change(&*value, false);
    return removed;
}

StringMap &DataTypeManager::properties() noexcept { return *properties_; }
const StringMap &DataTypeManager::properties() const noexcept { return *properties_; }

void DataTypeManager::invalidate_caches() noexcept {
    // Current adapters decode records on demand. Name caches will be introduced
    // only with the semantic object graph, so no stale object survives reload.
}

} // namespace llmghidra::program
