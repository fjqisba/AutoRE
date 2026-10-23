#include "llmghidra/program/function_manager.hpp"

#include "llmghidra/program/data_type_manager.hpp"
#include "llmghidra/program/namespace_manager.hpp"
#include "llmghidra/program/variable_storage_manager.hpp"
#include "llmghidra/program/language_translator.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"

#include <set>
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr const char *function_table_name = "Function Data";
constexpr const char *thunk_table_name = "Thunk Functions";
constexpr const char *tag_table_name = "Function Tags";
constexpr const char *tag_mapping_table_name = "Function Tag Map";
constexpr std::size_t return_data_type_column = 0;
constexpr std::size_t stack_purge_column = 1;
constexpr std::size_t stack_return_offset_column = 2;
constexpr std::size_t stack_local_size_column = 3;
constexpr std::size_t flags_column = 4;
constexpr std::size_t calling_convention_column = 5;
constexpr std::size_t return_storage_column = 6;

constexpr std::uint8_t variadic_flag = 0x01;
constexpr std::uint8_t inline_flag = 0x02;
constexpr std::uint8_t no_return_flag = 0x04;
constexpr std::uint8_t custom_storage_flag = 0x08;
constexpr std::uint8_t signature_source_mask = 0x70;
constexpr unsigned signature_source_shift = 4;

[[nodiscard]] std::vector<std::unique_ptr<db::Field>> function_fields() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::StringField>());
    return fields;
}

} // namespace

std::shared_ptr<db::Schema> FunctionManager::current_schema() {
    return std::make_shared<db::Schema>(
        schema_version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "ID", function_fields(),
        std::vector<std::string>{"Return DataType ID", "StackPurge",
                                 "StackReturnOffset", "StackLocalSize", "Flags",
                                 "Calling Convention ID", "Return Storage"});
}

std::shared_ptr<db::Schema> FunctionManager::thunk_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "ID",
        std::move(fields), std::vector<std::string>{"Linked Function ID"});
}

std::shared_ptr<db::Schema> FunctionManager::tag_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "ID",
        std::move(fields), std::vector<std::string>{"Tag", "Comment"});
}

std::shared_ptr<db::Schema> FunctionManager::tag_mapping_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "ID",
        std::move(fields), std::vector<std::string>{"Function ID", "Tag ID"});
}

std::shared_ptr<db::Schema> FunctionManager::legacy_schema(int version) {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    std::vector<std::string> names{"Return DataType ID", "StackPurge",
                                   "StackParamOffset", "StackReturnOffset",
                                   "StackLocalSize"};
    if (version >= 1) {
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
        names.emplace_back("Flags");
    }
    if (version >= 2) {
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
        names.emplace_back("Calling Convention ID");
    }
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "ID", std::move(fields), std::move(names));
}

std::unique_ptr<db::Record> FunctionManager::translate_legacy_record(
    const db::Record &record) const {
    if (stored_schema_version_ < 0 || stored_schema_version_ >= schema_version) {
        throw std::logic_error("function record is not from a legacy schema");
    }
    auto translated = current_schema()->create_record(record.key().as_integer());
    translated->set_integer(return_data_type_column, record.field(0).as_integer());
    translated->set_integer(stack_purge_column, record.field(1).as_integer());
    translated->set_integer(stack_return_offset_column, record.field(3).as_integer());
    translated->set_integer(stack_local_size_column, record.field(4).as_integer());
    const auto old_flags = stored_schema_version_ == 0
                               ? std::uint8_t{}
                               : static_cast<std::uint8_t>(record.field(5).as_integer());
    translated->set_integer(flags_column,
                            static_cast<std::uint8_t>(old_flags |
                                                      custom_storage_flag));
    translated->set_integer(
        calling_convention_column,
        stored_schema_version_ >= 2 ? record.field(6).as_integer() : 0);
    translated->set_null(return_storage_column);
    return translated;
}

FunctionManager::FunctionManager(std::shared_ptr<db::DatabaseHandle> database,
                                 SymbolManager &symbols,
                                 DataTypeManager &data_types,
                                 VariableStorageManager &variable_storage,
                                 NamespaceManager &namespaces,
                                 ProgramOpenMode mode,
                                 bool create,
                                 bool create_missing_for_legacy_upgrade)
    : database_(std::move(database)), symbols_(&symbols),
      data_types_(&data_types), variable_storage_(&variable_storage),
      namespaces_(&namespaces), mode_(mode) {
    if (!database_) throw std::invalid_argument("function manager requires a database");
    if (create) {
        auto schema = current_schema();
        table_ = database_->create_table(function_table_name, schema);
        schema_ = std::move(schema);
        thunk_table_ = database_->create_table(
            thunk_table_name, thunk_schema(), {0});
    }
    else {
        table_ = database_->get_table(function_table_name);
        if (!table_ && create_missing_for_legacy_upgrade &&
            mode_ == ProgramOpenMode::upgrade) {
            auto schema = current_schema();
            table_ = database_->create_table(function_table_name, schema);
            schema_ = std::move(schema);
            stored_schema_version_ = schema_version;
            thunk_table_ = database_->get_table(thunk_table_name);
            if (!thunk_table_) {
                thunk_table_ = database_->create_table(
                    thunk_table_name, thunk_schema(), {0});
            }
            else if (!thunk_table_->schema().equals(*thunk_schema()) ||
                     thunk_table_->indexed_columns() !=
                         std::vector<std::size_t>{0}) {
                throw std::runtime_error(
                    "unsupported Ghidra Thunk Functions table");
            }
            return;
        }
        if (!table_) throw std::runtime_error("missing Ghidra Function Data table");
        stored_schema_version_ = table_->schema().version();
        schema_ = current_schema();
        const bool current = stored_schema_version_ == schema_version &&
                             table_->schema().equals(*schema_);
        const bool legacy = stored_schema_version_ >= 0 &&
                            stored_schema_version_ < schema_version &&
                            table_->schema().equals(
                                *legacy_schema(stored_schema_version_));
        if (!current && !legacy) {
            throw std::runtime_error("unsupported Ghidra Function Data schema");
        }
        if (legacy && mode_ == ProgramOpenMode::update) {
            throw std::runtime_error("Ghidra Function Data table requires upgrade");
        }
        if (legacy && mode_ == ProgramOpenMode::upgrade) {
            std::vector<std::unique_ptr<db::Record>> translated;
            auto iterator = table_->iterator();
            while (iterator->has_next()) {
                if (const auto row = iterator->next()) {
                    translated.push_back(translate_legacy_record(*row));
                }
            }
            if (!database_->delete_table(function_table_name)) {
                throw std::runtime_error("failed to replace legacy Function Data table");
            }
            table_ = database_->create_table(function_table_name, schema_);
            for (auto &row : translated) table_->put_record(*row);
            stored_schema_version_ = schema_version;
        }
        thunk_table_ = database_->get_table(thunk_table_name);
        if (!thunk_table_) {
            if (mode_ == ProgramOpenMode::upgrade) {
                thunk_table_ = database_->create_table(
                    thunk_table_name, thunk_schema(), {0});
            }
            else if (mode_ != ProgramOpenMode::read_only) {
                throw std::runtime_error("missing Ghidra Thunk Functions table");
            }
        }
        if (thunk_table_) {
            if (!thunk_table_->schema().equals(*thunk_schema())) {
                throw std::runtime_error("unsupported Ghidra Thunk Functions table");
            }
            if (const auto indexed = thunk_table_->indexed_columns();
                indexed.size() != 1 || indexed.front() != 0) {
                throw std::runtime_error("Ghidra Thunk Functions index contract mismatch");
            }
        }
        tag_table_ = database_->get_table(tag_table_name);
        if (tag_table_ && !tag_table_->schema().equals(*tag_schema())) {
            throw std::runtime_error("unsupported Ghidra Function Tags table");
        }
        tag_mapping_table_ = database_->get_table(tag_mapping_table_name);
        if (tag_mapping_table_ &&
            !tag_mapping_table_->schema().equals(*tag_mapping_schema())) {
            throw std::runtime_error("unsupported Ghidra Function Tag Map table");
        }
        if (tag_mapping_table_) {
            const auto indexed = tag_mapping_table_->indexed_columns();
            if (indexed.size() != 1 || indexed.front() != 0) {
                throw std::runtime_error(
                    "Ghidra Function Tag Map index contract mismatch");
            }
        }
    }
}

void FunctionManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

void FunctionManager::validate(const Function &function) const {
    if (function.symbol_id <= 0 || function.symbol.id != function.symbol_id ||
        function.symbol.type != SymbolType::function) {
        throw std::invalid_argument("function record must reference its function symbol");
    }
    if (static_cast<std::uint8_t>(function.signature_source) > 4) {
        throw std::invalid_argument("unsupported signature source storage id");
    }
    if (!data_types_->contains_data_type(function.return_data_type_id)) {
        throw std::invalid_argument("function return data type does not exist");
    }
    if (function.symbol.address.is_external_address()) {
        if (!function.body.empty()) {
            throw std::invalid_argument("external function may not have a memory body");
        }
        return;
    }
    if (function.body.empty() || !function.body.contains(function.symbol.address)) {
        throw std::invalid_argument("function body must contain its entry point");
    }
    for (const auto &range : function.body.ranges()) {
        if (!range.min_address().is_memory_address() ||
            !range.min_address().same_space(function.symbol.address)) {
            throw std::invalid_argument(
                "function body must use its entry point address space");
        }
    }
}

std::unique_ptr<db::Record> FunctionManager::encode(const Function &function) const {
    auto record = schema_->create_record(function.symbol_id);
    record->set_integer(return_data_type_column, function.return_data_type_id);
    record->set_integer(stack_purge_column, function.stack_purge);
    record->set_integer(stack_return_offset_column, function.stack_return_offset);
    record->set_integer(stack_local_size_column, function.stack_local_size);
    std::uint8_t flags = static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(function.signature_source) << signature_source_shift);
    if (function.variadic) flags |= variadic_flag;
    if (function.inline_hint) flags |= inline_flag;
    if (function.no_return) flags |= no_return_flag;
    if (function.custom_parameter_storage) flags |= custom_storage_flag;
    record->set_integer(flags_column, flags);
    record->set_integer(calling_convention_column, function.calling_convention_id);
    record->set_string(return_storage_column, function.return_storage);
    return record;
}

Function FunctionManager::decode(const db::Record &record) const {
    std::unique_ptr<db::Record> legacy_record;
    const db::Record *source = &record;
    if (stored_schema_version_ < schema_version) {
        legacy_record = translate_legacy_record(record);
        source = legacy_record.get();
    }
    Function function;
    function.symbol_id = source->key().as_integer();
    const auto symbol = symbols_->get(function.symbol_id);
    if (!symbol || symbol->type != SymbolType::function) {
        throw std::runtime_error("orphaned Function Data record");
    }
    function.symbol = *symbol;
    function.return_data_type_id = source->field(return_data_type_column).as_integer();
    function.stack_purge = static_cast<std::int32_t>(source->field(stack_purge_column).as_integer());
    function.stack_return_offset = static_cast<std::int32_t>(
        source->field(stack_return_offset_column).as_integer());
    function.stack_local_size = static_cast<std::int32_t>(
        source->field(stack_local_size_column).as_integer());
    const auto flags = static_cast<std::uint8_t>(source->field(flags_column).as_integer());
    function.variadic = (flags & variadic_flag) != 0;
    function.inline_hint = (flags & inline_flag) != 0;
    function.no_return = (flags & no_return_flag) != 0;
    function.custom_parameter_storage = (flags & custom_storage_flag) != 0;
    function.signature_source = static_cast<SignatureSource>(
        (flags & signature_source_mask) >> signature_source_shift);
    function.calling_convention_id = static_cast<std::uint8_t>(
        source->field(calling_convention_column).as_integer());
    function.return_storage = source->field(return_storage_column).as_string();
    function.body = namespaces_->body(function.symbol_id, false);
    validate(function);
    return function;
}

Function FunctionManager::create(FunctionSpec spec) {
    require_mutation();
    if (!spec.entry.is_memory_address() && !spec.entry.is_external_address()) {
        throw std::invalid_argument("function entry must be a memory or external address");
    }
    if (spec.external != spec.entry.is_external_address()) {
        throw std::invalid_argument("function external flag does not match its entry space");
    }
    if (!spec.external && spec.body.empty()) spec.body.add(spec.entry);
    if (spec.external && !spec.body.empty()) {
        throw std::invalid_argument("external function may not have a memory body");
    }
    SymbolSpec symbol_spec;
    symbol_spec.name = std::move(spec.name);
    symbol_spec.address = spec.entry;
    symbol_spec.parent_id = spec.parent_namespace_id;
    symbol_spec.type = SymbolType::function;
    symbol_spec.source = spec.symbol_source;
    symbol_spec.primary = true;
    symbol_spec.original_imported_name = std::move(spec.original_imported_name);
    symbol_spec.external_program_address = std::move(spec.external_program_address);
    auto symbol = symbols_->create(std::move(symbol_spec));

    Function function;
    function.symbol_id = symbol.id;
    function.symbol = std::move(symbol);
    function.return_data_type_id = spec.return_data_type_id;
    function.stack_purge = unknown_stack_depth_change;
    function.signature_source = spec.signature_source;
    function.calling_convention_id = spec.calling_convention_id;
    function.body = std::move(spec.body);
    validate(function);
    auto record = encode(function);
    table_->put_record(*record);
    if (!function.body.empty()) namespaces_->set_body(function.symbol_id, function.body);
    return function;
}

Function FunctionManager::promote_external_symbol(
    std::int64_t symbol_id,
    std::int64_t return_data_type_id,
    SignatureSource signature_source,
    std::uint8_t calling_convention_id) {
    require_mutation();
    if (table_->has_record(symbol_id)) {
        auto existing = get(symbol_id);
        if (!existing) {
            throw std::runtime_error(
                "external function record cannot be decoded");
        }
        return *existing;
    }
    auto symbol = symbols_->get(symbol_id);
    if (!symbol || symbol->type != SymbolType::label ||
        !symbol->address.is_external_address()) {
        throw std::invalid_argument(
            "only an external label can be promoted to a function");
    }
    if (!data_types_->contains_data_type(return_data_type_id)) {
        throw std::invalid_argument(
            "external function return data type does not exist");
    }
    symbol->type = SymbolType::function;
    symbol->primary = true;
    symbol->data_type_id.reset();
    symbol->variable_offset.reset();
    symbols_->update(*symbol);

    Function function;
    function.symbol_id = symbol_id;
    function.symbol = *symbol;
    function.return_data_type_id = return_data_type_id;
    function.stack_purge = unknown_stack_depth_change;
    function.signature_source = signature_source;
    function.calling_convention_id = calling_convention_id;
    validate(function);
    auto record = encode(function);
    table_->put_record(*record);
    return function;
}

std::optional<Function> FunctionManager::get(std::int64_t symbol_id) const {
    auto record = table_->record(symbol_id);
    return record ? std::optional<Function>(decode(*record)) : std::nullopt;
}

std::optional<Function> FunctionManager::at(const Address &entry) const {
    for (const auto &symbol : symbols_->at(entry)) {
        if (symbol.type != SymbolType::function) continue;
        if (auto function = get(symbol.id)) return function;
    }
    return std::nullopt;
}

std::vector<Function> FunctionManager::all() const {
    std::vector<Function> result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        if (auto record = iterator->next()) result.push_back(decode(*record));
    }
    return result;
}

std::size_t FunctionManager::size() const {
    return static_cast<std::size_t>(table_->record_count());
}

std::optional<std::int64_t> FunctionManager::thunk_target(
    std::int64_t function_id) const {
    if (!thunk_table_) return std::nullopt;
    const auto record = thunk_table_->record(function_id);
    return record ? std::optional<std::int64_t>(record->field(0).as_integer())
                  : std::nullopt;
}

std::vector<std::int64_t> FunctionManager::thunks_to(
    std::int64_t referenced_function_id) const {
    std::vector<std::int64_t> result;
    if (!thunk_table_) return result;
    auto iterator = thunk_table_->iterator();
    while (iterator->has_next()) {
        if (auto record = iterator->next();
            record && record->field(0).as_integer() == referenced_function_id) {
            result.push_back(record->key().as_integer());
        }
    }
    return result;
}

void FunctionManager::set_thunk(
    std::int64_t function_id,
    std::optional<std::int64_t> referenced_function_id) {
    require_mutation();
    if (!get(function_id)) throw std::out_of_range("thunk function does not exist");
    if (!referenced_function_id) {
        if (thunk_table_) (void)thunk_table_->delete_record(function_id);
        return;
    }
    if (*referenced_function_id == function_id || !get(*referenced_function_id)) {
        throw std::invalid_argument("referenced thunk function is invalid");
    }
    std::set<std::int64_t> visited{function_id};
    auto current = *referenced_function_id;
    for (;;) {
        if (!visited.insert(current).second) {
            throw std::invalid_argument("thunk relation would create a cycle");
        }
        const auto next = thunk_target(current);
        if (!next) break;
        current = *next;
    }
    if (!thunk_table_) {
        thunk_table_ = database_->create_table(
            thunk_table_name, thunk_schema(), {0});
    }
    auto record = thunk_schema()->create_record(function_id);
    record->set_integer(0, *referenced_function_id);
    thunk_table_->put_record(*record);
}

std::shared_ptr<db::Table> FunctionManager::require_tag_table() {
    if (!tag_table_) tag_table_ = database_->create_table(tag_table_name, tag_schema());
    return tag_table_;
}

std::shared_ptr<db::Table> FunctionManager::require_tag_mapping_table() {
    if (!tag_mapping_table_) {
        tag_mapping_table_ = database_->create_table(
            tag_mapping_table_name, tag_mapping_schema(), {0});
    }
    return tag_mapping_table_;
}

std::optional<FunctionTag> FunctionManager::tag(std::int64_t id) const {
    if (!tag_table_) return std::nullopt;
    const auto record = tag_table_->record(id);
    if (!record) return std::nullopt;
    return FunctionTag{id, record->field(0).as_string().value_or(std::string{}),
                       record->field(1).as_string()};
}

std::optional<FunctionTag> FunctionManager::tag(const std::string &name) const {
    if (!tag_table_) return std::nullopt;
    auto iterator = tag_table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (record && record->field(0).as_string() == name) {
            return FunctionTag{record->key().as_integer(), name,
                               record->field(1).as_string()};
        }
    }
    return std::nullopt;
}

FunctionTag FunctionManager::create_tag(
    std::string name,
    std::optional<std::string> comment) {
    require_mutation();
    if (name.empty()) throw std::invalid_argument("function tag name is empty");
    if (auto existing = tag(name)) return *existing;
    auto table = require_tag_table();
    auto record = tag_schema()->create_record(table->next_long_key());
    record->set_string(0, name);
    record->set_string(1, comment);
    table->put_record(*record);
    return {record->key().as_integer(), std::move(name), std::move(comment)};
}

std::vector<FunctionTag> FunctionManager::tags() const {
    std::vector<FunctionTag> result;
    if (!tag_table_) return result;
    auto iterator = tag_table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (record) {
            result.push_back({record->key().as_integer(),
                              record->field(0).as_string().value_or(std::string{}),
                              record->field(1).as_string()});
        }
    }
    return result;
}

void FunctionManager::update_tag(FunctionTag value) {
    require_mutation();
    if (value.id < 0 || value.name.empty() || !tag(value.id)) {
        throw std::invalid_argument("function tag is invalid");
    }
    if (const auto duplicate = tag(value.name);
        duplicate && duplicate->id != value.id) {
        throw std::invalid_argument("function tag name already exists");
    }
    auto record = tag_schema()->create_record(value.id);
    record->set_string(0, value.name);
    record->set_string(1, value.comment);
    tag_table_->put_record(*record);
}

bool FunctionManager::apply_tag(std::int64_t function_id,
                                std::int64_t tag_id) {
    require_mutation();
    if (!get(function_id) || !tag(tag_id)) {
        throw std::out_of_range("function or function tag does not exist");
    }
    if (tag_mapping_table_) {
        auto iterator = tag_mapping_table_->iterator();
        while (iterator->has_next()) {
            const auto record = iterator->next();
            if (record && record->field(0).as_integer() == function_id &&
                record->field(1).as_integer() == tag_id) {
                return false;
            }
        }
    }
    auto table = require_tag_mapping_table();
    auto record = tag_mapping_schema()->create_record(table->next_long_key());
    record->set_integer(0, function_id);
    record->set_integer(1, tag_id);
    table->put_record(*record);
    return true;
}

bool FunctionManager::unapply_tag(std::int64_t function_id,
                                  std::int64_t tag_id) {
    require_mutation();
    if (!tag_mapping_table_) return false;
    auto iterator = tag_mapping_table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (record && record->field(0).as_integer() == function_id &&
            record->field(1).as_integer() == tag_id) {
            return tag_mapping_table_->delete_record(record->key());
        }
    }
    return false;
}

std::vector<FunctionTag> FunctionManager::function_tags(
    std::int64_t function_id) const {
    if (!get(function_id)) throw std::out_of_range("function does not exist");
    std::vector<FunctionTag> result;
    if (!tag_mapping_table_) return result;
    auto iterator = tag_mapping_table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record || record->field(0).as_integer() != function_id) continue;
        if (auto value = tag(record->field(1).as_integer())) {
            result.push_back(std::move(*value));
        }
    }
    return result;
}

std::int64_t FunctionManager::effective_function_id(
    std::int64_t function_id) const {
    if (!get(function_id)) throw std::out_of_range("function does not exist");
    std::set<std::int64_t> visited;
    auto current = function_id;
    while (visited.insert(current).second) {
        const auto target = thunk_target(current);
        if (!target) return current;
        if (!get(*target)) {
            throw std::runtime_error("thunk references a missing function");
        }
        current = *target;
    }
    throw std::runtime_error("persisted thunk relation contains a cycle");
}

FunctionVariable FunctionManager::decode_variable(const Symbol &symbol) const {
    if (symbol.type != SymbolType::parameter &&
        symbol.type != SymbolType::local_variable) {
        throw std::invalid_argument("symbol is not a function variable");
    }
    auto storage = variable_storage_->storage(symbol.address);
    if (!storage) {
        storage = symbol.type == SymbolType::parameter
                      ? VariableStorage::unassigned()
                      : VariableStorage::bad();
    }
    return FunctionVariable{symbol, std::move(*storage)};
}

std::optional<FunctionVariable> FunctionManager::variable(
    std::int64_t symbol_id) const {
    const auto symbol = symbols_->get(symbol_id);
    if (!symbol || (symbol->type != SymbolType::parameter &&
                    symbol->type != SymbolType::local_variable)) {
        return std::nullopt;
    }
    return decode_variable(*symbol);
}

std::vector<FunctionVariable> FunctionManager::parameters(
    std::int64_t function_id) const {
    const auto target_id = effective_function_id(function_id);
    std::vector<FunctionVariable> result;
    for (const auto &symbol : symbols_->in_namespace(target_id)) {
        if (symbol.type == SymbolType::parameter) {
            result.push_back(decode_variable(symbol));
        }
    }
    std::ranges::sort(result, [](const auto &left, const auto &right) {
        const auto left_ordinal = left.symbol.variable_offset.value_or(0);
        const auto right_ordinal = right.symbol.variable_offset.value_or(0);
        return left_ordinal != right_ordinal
                   ? left_ordinal < right_ordinal
                   : left.symbol.id < right.symbol.id;
    });
    return result;
}

std::vector<FunctionVariable> FunctionManager::local_variables(
    std::int64_t function_id) const {
    // Ghidra exposes a thunk's target parameters, but a thunk itself has no
    // local-variable view. Mutating through add_local_variable still delegates
    // to the effective target, matching FunctionDB.
    if (thunk_target(function_id)) return {};
    const auto target_id = function_id;
    std::vector<FunctionVariable> result;
    for (const auto &symbol : symbols_->in_namespace(target_id)) {
        if (symbol.type == SymbolType::local_variable) {
            result.push_back(decode_variable(symbol));
        }
    }
    std::ranges::sort(result, [](const auto &left, const auto &right) {
        const auto left_offset = left.symbol.variable_offset.value_or(0);
        const auto right_offset = right.symbol.variable_offset.value_or(0);
        if (left_offset != right_offset) return left_offset < right_offset;
        if (left.storage.serialization() != right.storage.serialization()) {
            return left.storage.serialization() < right.storage.serialization();
        }
        return left.symbol.id < right.symbol.id;
    });
    return result;
}

void FunctionManager::require_unique_variable_name(
    std::int64_t function_id,
    const std::string &name,
    std::int64_t except_symbol_id) const {
    if (name.empty()) return;
    for (const auto &candidate : symbols_->named_in_namespace(name, function_id)) {
        if (candidate.id != except_symbol_id &&
            (candidate.type == SymbolType::parameter ||
             candidate.type == SymbolType::local_variable)) {
            throw std::invalid_argument("function variable name already exists");
        }
    }
}

void FunctionManager::normalize_parameter_ordinals(
    std::int64_t function_id,
    std::optional<std::int64_t> moved_symbol_id,
    std::optional<std::int32_t> requested_ordinal) {
    std::vector<Symbol> values;
    for (const auto &candidate : symbols_->in_namespace(function_id)) {
        if (candidate.type == SymbolType::parameter) values.push_back(candidate);
    }
    std::ranges::sort(values, [](const Symbol &left, const Symbol &right) {
        const auto left_ordinal = left.variable_offset.value_or(0);
        const auto right_ordinal = right.variable_offset.value_or(0);
        return left_ordinal != right_ordinal ? left_ordinal < right_ordinal
                                             : left.id < right.id;
    });
    if (moved_symbol_id) {
        const auto moved = std::ranges::find_if(values, [&](const Symbol &value) {
            return value.id == *moved_symbol_id;
        });
        if (moved == values.end()) {
            throw std::out_of_range("parameter symbol does not exist");
        }
        auto value = std::move(*moved);
        values.erase(moved);
        const auto bounded = std::min<std::size_t>(
            static_cast<std::size_t>(std::max<std::int32_t>(0, *requested_ordinal)),
            values.size());
        values.insert(values.begin() + static_cast<std::ptrdiff_t>(bounded),
                      std::move(value));
    }
    for (std::size_t ordinal = 0; ordinal < values.size(); ++ordinal) {
        const auto desired = static_cast<std::int32_t>(ordinal);
        if (values[ordinal].variable_offset.value_or(0) == desired) continue;
        values[ordinal].variable_offset = desired;
        symbols_->update(values[ordinal]);
    }
}

FunctionVariable FunctionManager::add_parameter(
    std::int64_t function_id,
    std::int32_t ordinal,
    FunctionVariableSpec spec) {
    require_mutation();
    const auto target_id = effective_function_id(function_id);
    const auto function = get(target_id);
    if (!function) throw std::out_of_range("function does not exist");
    if (!data_types_->contains_data_type(spec.data_type_id)) {
        throw std::invalid_argument("parameter data type does not exist");
    }
    if (spec.name.empty()) spec.name = "param";
    VariableStorage storage = function->custom_parameter_storage
                                  ? std::move(spec.storage)
                                  : VariableStorage::unassigned();

    std::optional<FunctionVariable> overlap;
    if (!storage.is_unassigned()) {
        for (auto &candidate : parameters(target_id)) {
            if (candidate.storage.intersects(storage)) {
                overlap = std::move(candidate);
                break;
            }
        }
    }
    require_unique_variable_name(target_id, spec.name,
                                 overlap ? overlap->symbol.id : 0);
    if (overlap) {
        overlap->symbol.name = std::move(spec.name);
        overlap->symbol.source = spec.source;
        overlap->symbol.data_type_id = spec.data_type_id;
        overlap->symbol.comment = std::move(spec.comment);
        overlap->storage = std::move(storage);
        update_variable(*overlap);
        normalize_parameter_ordinals(target_id, overlap->symbol.id, ordinal);
        return *variable(overlap->symbol.id);
    }

    const auto variable_address = variable_storage_->address_for(storage, true);
    if (!variable_address) {
        throw std::runtime_error("failed to allocate parameter storage address");
    }
    const auto existing_count = parameters(target_id).size();
    const auto bounded_ordinal = static_cast<std::int32_t>(std::min<std::size_t>(
        static_cast<std::size_t>(std::max<std::int32_t>(0, ordinal)),
        existing_count));
    SymbolSpec symbol_spec;
    symbol_spec.name = std::move(spec.name);
    symbol_spec.address = *variable_address;
    symbol_spec.parent_id = target_id;
    symbol_spec.type = SymbolType::parameter;
    symbol_spec.source = spec.source;
    symbol_spec.data_type_id = spec.data_type_id;
    symbol_spec.variable_offset = bounded_ordinal;
    symbol_spec.comment = std::move(spec.comment);
    auto symbol = symbols_->create(std::move(symbol_spec));
    normalize_parameter_ordinals(target_id, symbol.id, bounded_ordinal);
    return decode_variable(*symbols_->get(symbol.id));
}

FunctionVariable FunctionManager::add_local_variable(
    std::int64_t function_id,
    std::int32_t first_use_offset,
    FunctionVariableSpec spec) {
    require_mutation();
    const auto target_id = effective_function_id(function_id);
    if (!data_types_->contains_data_type(spec.data_type_id)) {
        throw std::invalid_argument("local-variable data type does not exist");
    }
    if (spec.name.empty()) spec.name = "local";
    if (spec.storage.has_stack_storage()) first_use_offset = 0;

    std::optional<FunctionVariable> overlap;
    for (auto &candidate : local_variables(target_id)) {
        if (candidate.symbol.variable_offset.value_or(0) == first_use_offset &&
            candidate.storage.intersects(spec.storage)) {
            overlap = std::move(candidate);
            break;
        }
    }
    require_unique_variable_name(target_id, spec.name,
                                 overlap ? overlap->symbol.id : 0);
    if (overlap) {
        overlap->symbol.name = std::move(spec.name);
        overlap->symbol.source = spec.source;
        overlap->symbol.data_type_id = spec.data_type_id;
        overlap->symbol.variable_offset = first_use_offset;
        overlap->symbol.comment = std::move(spec.comment);
        overlap->storage = std::move(spec.storage);
        update_variable(*overlap);
        return *variable(overlap->symbol.id);
    }

    const auto variable_address = variable_storage_->address_for(spec.storage, true);
    if (!variable_address) {
        throw std::runtime_error("failed to allocate local-variable storage address");
    }
    SymbolSpec symbol_spec;
    symbol_spec.name = std::move(spec.name);
    symbol_spec.address = *variable_address;
    symbol_spec.parent_id = target_id;
    symbol_spec.type = SymbolType::local_variable;
    symbol_spec.source = spec.source;
    symbol_spec.data_type_id = spec.data_type_id;
    symbol_spec.variable_offset = first_use_offset;
    symbol_spec.comment = std::move(spec.comment);
    return decode_variable(symbols_->create(std::move(symbol_spec)));
}

void FunctionManager::update_variable(FunctionVariable value) {
    require_mutation();
    const auto existing = symbols_->get(value.symbol.id);
    if (!existing || (existing->type != SymbolType::parameter &&
                      existing->type != SymbolType::local_variable)) {
        throw std::out_of_range("function variable does not exist");
    }
    if (value.symbol.type != existing->type ||
        value.symbol.parent_id != existing->parent_id) {
        throw std::invalid_argument("function variable ownership and kind are immutable");
    }
    if (value.symbol.type == SymbolType::parameter &&
        value.symbol.variable_offset != existing->variable_offset) {
        throw std::invalid_argument(
            "use reorder_parameter to change a parameter ordinal");
    }
    if (!value.symbol.data_type_id ||
        !data_types_->contains_data_type(*value.symbol.data_type_id)) {
        throw std::invalid_argument("function variable data type does not exist");
    }
    require_unique_variable_name(value.symbol.parent_id, value.symbol.name,
                                 value.symbol.id);
    if (value.symbol.type == SymbolType::parameter) {
        const auto function = get(value.symbol.parent_id);
        if (!function) throw std::runtime_error("variable parent function is missing");
        if (!function->custom_parameter_storage) {
            value.storage = VariableStorage::unassigned();
        }
    }
    else if (value.storage.has_stack_storage()) {
        value.symbol.variable_offset = 0;
    }
    for (const auto &candidate_symbol :
         symbols_->in_namespace(value.symbol.parent_id)) {
        if (candidate_symbol.id == value.symbol.id ||
            (candidate_symbol.type != SymbolType::parameter &&
             candidate_symbol.type != SymbolType::local_variable)) {
            continue;
        }
        const auto candidate = decode_variable(candidate_symbol);
        if (!candidate.storage.intersects(value.storage)) continue;
        const bool separate_local_lifetimes =
            value.symbol.type == SymbolType::local_variable &&
            candidate.symbol.type == SymbolType::local_variable &&
            value.symbol.variable_offset.value_or(0) !=
                candidate.symbol.variable_offset.value_or(0);
        if (!separate_local_lifetimes) {
            throw std::invalid_argument(
                "function variable storage overlaps an existing variable");
        }
    }
    const auto variable_address = variable_storage_->address_for(value.storage, true);
    if (!variable_address) {
        throw std::runtime_error("failed to allocate variable storage address");
    }
    value.symbol.address = *variable_address;
    symbols_->update(value.symbol);
}

void FunctionManager::reorder_parameter(std::int64_t symbol_id,
                                        std::int32_t ordinal) {
    require_mutation();
    const auto value = symbols_->get(symbol_id);
    if (!value || value->type != SymbolType::parameter) {
        throw std::out_of_range("parameter symbol does not exist");
    }
    normalize_parameter_ordinals(value->parent_id, symbol_id, ordinal);
}

bool FunctionManager::remove_variable(std::int64_t symbol_id) {
    require_mutation();
    const auto value = symbols_->get(symbol_id);
    if (!value || (value->type != SymbolType::parameter &&
                   value->type != SymbolType::local_variable)) {
        return false;
    }
    const auto function_id = value->parent_id;
    const auto parameter = value->type == SymbolType::parameter;
    if (!symbols_->remove(symbol_id)) {
        throw std::runtime_error("function variable disappeared during removal");
    }
    if (parameter) normalize_parameter_ordinals(function_id, std::nullopt, std::nullopt);
    return true;
}

bool FunctionManager::remove_tag(std::int64_t id) {
    require_mutation();
    if (!tag(id)) return false;
    if (tag_mapping_table_) {
        std::vector<std::unique_ptr<db::Field>> keys;
        auto iterator = tag_mapping_table_->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (record && record->field(1).as_integer() == id) {
                keys.push_back(record->key().clone());
            }
        }
        for (const auto &key : keys) (void)tag_mapping_table_->delete_record(*key);
    }
    return tag_table_->delete_record(id);
}

void FunctionManager::remove_function_tag_mappings(std::int64_t function_id) {
    if (!tag_mapping_table_) return;
    std::vector<std::unique_ptr<db::Field>> keys;
    auto iterator = tag_mapping_table_->iterator();
    while (iterator->has_next()) {
        if (auto record = iterator->next();
            record && record->field(0).as_integer() == function_id) {
            keys.push_back(record->key().clone());
        }
    }
    for (const auto &key : keys) (void)tag_mapping_table_->delete_record(*key);
}

void FunctionManager::update(const Function &function) {
    require_mutation();
    validate(function);
    if (!table_->has_record(function.symbol_id)) {
        throw std::out_of_range("function does not exist");
    }
    symbols_->update(function.symbol);
    auto record = encode(function);
    table_->put_record(*record);
    namespaces_->set_body(function.symbol_id, function.body);
}

void FunctionManager::set_body(std::int64_t function_id, AddressSet body) {
    auto function = get(effective_function_id(function_id));
    if (!function) throw std::out_of_range("function does not exist");
    function->body = std::move(body);
    update(*function);
}

bool FunctionManager::remove(std::int64_t symbol_id) {
    require_mutation();
    if (!table_->has_record(symbol_id)) return false;
    const auto direct_thunks = thunks_to(symbol_id);
    for (const auto thunk_id : direct_thunks) {
        if (!remove(thunk_id)) {
            throw std::runtime_error("referencing thunk disappeared during removal");
        }
    }
    (void)namespaces_->remove_body(symbol_id);
    if (thunk_table_) (void)thunk_table_->delete_record(symbol_id);
    remove_function_tag_mappings(symbol_id);
    for (const auto &child : symbols_->in_namespace(symbol_id)) {
        if (!symbols_->remove(child.id)) {
            throw std::runtime_error("function child symbol disappeared during removal");
        }
    }
    if (!table_->delete_record(symbol_id)) {
        throw std::runtime_error("function record disappeared during removal");
    }
    if (!symbols_->remove(symbol_id)) {
        throw std::runtime_error("function symbol disappeared during removal");
    }
    return true;
}

std::size_t FunctionManager::remove_overlapping_range(
    const Address &start, const Address &end) {
    require_mutation();
    if (!start.is_valid() || !end.is_valid() || !start.same_space(end) ||
        end < start) {
        throw std::invalid_argument("function removal range is invalid");
    }
    std::vector<std::int64_t> ids;
    for (const auto &function : all()) {
        if (function.body.intersects(start, end)) {
            ids.push_back(function.symbol_id);
        }
    }
    std::size_t removed = 0;
    for (const auto id : ids) removed += remove(id) ? 1U : 0U;
    return removed;
}

std::size_t FunctionManager::replace_data_type(std::int64_t replaced_id,
                                               std::int64_t replacement_id) {
    require_mutation();
    if (replaced_id == replacement_id) return 0;
    if (!data_types_->contains_data_type(replacement_id)) {
        throw std::invalid_argument("replacement return data type does not exist");
    }
    std::size_t changed = 0;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (!record || record->field(return_data_type_column).as_integer() !=
                           replaced_id) {
            continue;
        }
        record->set_integer(return_data_type_column, replacement_id);
        table_->put_record(*record);
        ++changed;
    }
    return changed;
}

void FunctionManager::set_language(
    const AddressFactory &new_address_factory,
    const LanguageTranslator &translator) {
    require_mutation();
    std::vector<Function> replacements;
    for (auto function : all()) {
        if (!function.return_storage) continue;
        function.return_storage = VariableStorage::translate_serialization(
            new_address_factory, translator, *function.return_storage);
        replacements.push_back(std::move(function));
    }
    for (const auto &function : replacements) update(function);
}

void FunctionManager::invalidate_cache() {
    table_ = database_->get_table(function_table_name);
    if (!table_) {
        throw std::runtime_error("unsupported or missing Ghidra Function Data table");
    }
    stored_schema_version_ = table_->schema().version();
    schema_ = current_schema();
    const bool current = stored_schema_version_ == schema_version &&
                         table_->schema().equals(*schema_);
    const bool legacy = mode_ == ProgramOpenMode::read_only &&
                        stored_schema_version_ >= 0 &&
                        stored_schema_version_ < schema_version &&
                        table_->schema().equals(*legacy_schema(stored_schema_version_));
    if (!current && !legacy) {
        throw std::runtime_error("unsupported Ghidra Function Data table");
    }
    thunk_table_ = database_->get_table(thunk_table_name);
    if (!thunk_table_) {
        if (mode_ != ProgramOpenMode::read_only) {
            throw std::runtime_error("missing Ghidra Thunk Functions table");
        }
    }
    else {
        if (!thunk_table_->schema().equals(*thunk_schema())) {
            throw std::runtime_error("unsupported Ghidra Thunk Functions table");
        }
        if (const auto indexed = thunk_table_->indexed_columns();
            indexed.size() != 1 || indexed.front() != 0) {
            throw std::runtime_error("Ghidra Thunk Functions index contract mismatch");
        }
    }
    tag_table_ = database_->get_table(tag_table_name);
    if (tag_table_ && !tag_table_->schema().equals(*tag_schema())) {
        throw std::runtime_error("unsupported Ghidra Function Tags table");
    }
    tag_mapping_table_ = database_->get_table(tag_mapping_table_name);
    if (tag_mapping_table_ &&
        !tag_mapping_table_->schema().equals(*tag_mapping_schema())) {
        throw std::runtime_error("unsupported Ghidra Function Tag Map table");
    }
    if (tag_mapping_table_) {
        const auto indexed = tag_mapping_table_->indexed_columns();
        if (indexed.size() != 1 || indexed.front() != 0) {
            throw std::runtime_error(
                "Ghidra Function Tag Map index contract mismatch");
        }
    }
}

} // namespace llmghidra::program
