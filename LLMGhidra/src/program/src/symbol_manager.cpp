#include "llmghidra/program/symbol_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/namespace_manager.hpp"
#include "llmghidra/program/language_translator.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr const char *symbol_table_name = "Symbols";
constexpr std::size_t name_column = 0;
constexpr std::size_t address_column = 1;
constexpr std::size_t parent_column = 2;
constexpr std::size_t type_column = 3;
constexpr std::size_t flags_column = 4;
constexpr std::size_t locator_hash_column = 5;
constexpr std::size_t primary_column = 6;
constexpr std::size_t data_type_column = 7;
constexpr std::size_t variable_offset_column = 8;
constexpr std::size_t original_imported_name_column = 9;
constexpr std::size_t external_program_address_column = 10;
constexpr std::size_t comment_column = 11;
constexpr std::size_t library_path_column = 12;

constexpr std::uint8_t source_low_bits = 0x03;
constexpr std::uint8_t pinned_flag = 0x04;
constexpr std::uint8_t source_high_bit = 0x08;

[[nodiscard]] std::int32_t java_string_hash(const std::string &text) noexcept {
    // Java String.hashCode operates on UTF-16 code units. Decode UTF-8 here so
    // the persisted locator hash remains compatible for non-ASCII names.
    std::uint32_t hash = 0;
    for (std::size_t index = 0; index < text.size();) {
        const auto lead = static_cast<std::uint8_t>(text[index]);
        std::uint32_t code_point = 0xfffd;
        std::size_t length = 1;
        if (lead < 0x80) {
            code_point = lead;
        }
        else if ((lead & 0xe0) == 0xc0 && index + 1 < text.size()) {
            code_point = lead & 0x1f;
            length = 2;
        }
        else if ((lead & 0xf0) == 0xe0 && index + 2 < text.size()) {
            code_point = lead & 0x0f;
            length = 3;
        }
        else if ((lead & 0xf8) == 0xf0 && index + 3 < text.size()) {
            code_point = lead & 0x07;
            length = 4;
        }
        bool valid = length > 1;
        for (std::size_t part = 1; part < length; ++part) {
            const auto continuation = static_cast<std::uint8_t>(text[index + part]);
            if ((continuation & 0xc0) != 0x80) {
                valid = false;
                length = 1;
                code_point = 0xfffd;
                break;
            }
            code_point = (code_point << 6) | (continuation & 0x3f);
        }
        if (lead < 0x80) {
            valid = true;
        }
        if (!valid || code_point > 0x10ffff ||
            (code_point >= 0xd800 && code_point <= 0xdfff) ||
            (length == 2 && code_point < 0x80) ||
            (length == 3 && code_point < 0x800) ||
            (length == 4 && code_point < 0x10000)) {
            code_point = 0xfffd;
            length = 1;
        }
        index += length;
        if (code_point <= 0xffff) {
            hash = hash * 31U + code_point;
        }
        else {
            code_point -= 0x10000;
            hash = hash * 31U + (0xd800U + (code_point >> 10));
            hash = hash * 31U + (0xdc00U + (code_point & 0x3ff));
        }
    }
    return std::bit_cast<std::int32_t>(hash);
}

[[nodiscard]] std::int32_t java_long_hash(std::int64_t value) noexcept {
    const auto bits = std::bit_cast<std::uint64_t>(value);
    return std::bit_cast<std::int32_t>(
        static_cast<std::uint32_t>(bits ^ (bits >> 32)));
}

[[nodiscard]] std::uint8_t encode_flags(SourceType source, bool pinned) {
    const auto id = static_cast<std::uint8_t>(source);
    if (id > 4) {
        throw std::invalid_argument("unsupported symbol source storage id");
    }
    return static_cast<std::uint8_t>((id & source_low_bits) |
                                     ((id & 0x04U) << 1U) |
                                     (pinned ? pinned_flag : 0U));
}

[[nodiscard]] SourceType decode_source(std::uint8_t flags) {
    const auto id = static_cast<std::uint8_t>((flags & source_low_bits) |
                                              ((flags & source_high_bit) >> 1U));
    if (id > 4) {
        throw std::runtime_error("symbol record has an unknown source storage id");
    }
    return static_cast<SourceType>(id);
}

[[nodiscard]] bool is_namespace_type(SymbolType type) noexcept {
    return type == SymbolType::library || type == SymbolType::name_space ||
           type == SymbolType::class_type;
}

[[nodiscard]] bool java_is_whitespace(std::uint32_t code_point) noexcept {
    return (code_point >= 0x09 && code_point <= 0x0d) ||
           (code_point >= 0x1c && code_point <= 0x20) ||
           code_point == 0x1680 ||
           (code_point >= 0x2000 && code_point <= 0x2006) ||
           (code_point >= 0x2008 && code_point <= 0x200a) ||
           code_point == 0x2028 || code_point == 0x2029 ||
           code_point == 0x205f || code_point == 0x3000;
}

[[nodiscard]] bool java_string_is_blank(const std::string &text) noexcept {
    if (text.empty()) return true;
    for (std::size_t index = 0; index < text.size();) {
        const auto lead = static_cast<std::uint8_t>(text[index]);
        std::uint32_t code_point{};
        std::size_t length{};
        if (lead < 0x80) {
            code_point = lead;
            length = 1;
        }
        else if ((lead & 0xe0) == 0xc0) {
            code_point = lead & 0x1f;
            length = 2;
        }
        else if ((lead & 0xf0) == 0xe0) {
            code_point = lead & 0x0f;
            length = 3;
        }
        else if ((lead & 0xf8) == 0xf0) {
            code_point = lead & 0x07;
            length = 4;
        }
        else {
            return false;
        }
        if (index + length > text.size()) return false;
        for (std::size_t part = 1; part < length; ++part) {
            const auto continuation = static_cast<std::uint8_t>(text[index + part]);
            if ((continuation & 0xc0) != 0x80) return false;
            code_point = (code_point << 6) | (continuation & 0x3f);
        }
        if ((length == 2 && code_point < 0x80) ||
            (length == 3 && code_point < 0x800) ||
            (length == 4 && code_point < 0x10000) ||
            code_point > 0x10ffff ||
            (code_point >= 0xd800 && code_point <= 0xdfff) ||
            !java_is_whitespace(code_point)) {
            return false;
        }
        index += length;
    }
    return true;
}

void convert_legacy_string_data(std::uint8_t symbol_type,
                                db::Record &record,
                                const std::optional<std::string> &value) {
    if (!value || java_string_is_blank(*value)) return;
    const auto type = static_cast<SymbolType>(symbol_type);
    if (type == SymbolType::label || type == SymbolType::function) {
        const auto comma = value->find(',');
        record.set_string(external_program_address_column,
                          value->substr(0, comma));
        if (comma != std::string::npos) {
            record.set_string(original_imported_name_column,
                              value->substr(comma + 1));
        }
    }
    else if (type == SymbolType::parameter ||
             type == SymbolType::local_variable) {
        record.set_string(comment_column, value);
    }
    else if (type == SymbolType::library) {
        record.set_string(library_path_column, value);
    }
}

[[nodiscard]] std::string default_function_name(const Address &address) {
    std::string address_text = address.to_string();
    std::replace(address_text.begin(), address_text.end(), ':', '_');
    return "FUN_" + address_text;
}

[[nodiscard]] bool starts_with_default_dynamic_prefix(
    const std::string &name) noexcept {
    constexpr const char *prefixes[]{"UNK_", "DAT_", "LAB_", "SUB_",
                                     "EXT_", "FUN_"};
    return std::ranges::any_of(prefixes, [&](const char *prefix) {
        return name.starts_with(prefix);
    });
}

[[nodiscard]] std::vector<std::unique_ptr<db::Field>> symbol_fields() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    return fields;
}

} // namespace

std::shared_ptr<db::Schema> SymbolManager::current_schema() {
    return std::make_shared<db::Schema>(
        schema_version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Key", symbol_fields(),
        std::vector<std::string>{"Name", "Address", "Namespace", "Symbol Type",
                                 "Flags", "Locator Hash", "Primary", "Datatype",
                                 "Variable Offset", "ExtOrigImportName", "ExtProgAddr",
                                 "Comment", "LibPath"},
        std::set<std::size_t>{locator_hash_column, primary_column, data_type_column,
                              variable_offset_column, original_imported_name_column,
                              external_program_address_column, comment_column,
                              library_path_column});
}

std::shared_ptr<db::Schema> SymbolManager::legacy_schema(int version) {
    std::vector<std::unique_ptr<db::Field>> fields;
    std::vector<std::string> names;
    if (version == 0) {
        fields.push_back(std::make_unique<db::StringField>());
        fields.push_back(std::make_unique<db::BooleanField>());
        fields.push_back(std::make_unique<db::BooleanField>());
        fields.push_back(std::make_unique<db::BooleanField>());
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        return std::make_shared<db::Schema>(
            version, std::make_unique<db::IntegerField>(db::FieldType::int64),
            "Key", std::move(fields),
            std::vector<std::string>{"Name", "Is Dynamic", "Is Local",
                                     "Is Primary", "Address"});
    }
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    names = {"Name", "Address", version >= 3 ? "Namespace" : "Parent",
             "Symbol Type"};
    if (version == 1) {
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        fields.push_back(std::make_unique<db::StringField>());
        names.insert(names.end(), {"SymbolData1", "SymbolData2", "Comment"});
    }
    else if (version == 2) {
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        fields.push_back(std::make_unique<db::StringField>());
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
        names.insert(names.end(), {"SymbolData1", "SymbolData2", "SymbolData3",
                                   "Flags"});
    }
    else if (version == 3) {
        fields.push_back(std::make_unique<db::StringField>());
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        names.insert(names.end(), {"String Data", "Flags", "Locator Hash",
                                   "Primary", "Datatype", "Variable Offset"});
        return std::make_shared<db::Schema>(
            version, std::make_unique<db::IntegerField>(db::FieldType::int64),
            "Key", std::move(fields), std::move(names),
            std::set<std::size_t>{6, 7, 8, 9});
    }
    else {
        throw std::invalid_argument("unsupported legacy Symbols schema version");
    }
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Key", std::move(fields), std::move(names));
}

std::unique_ptr<db::Record> SymbolManager::translate_v0_global_record(
    const db::Record &record,
    std::int64_t destination_id) const {
    if (record.field(1).as_boolean() || record.field(2).as_boolean()) {
        throw std::logic_error(
            "dynamic/local Symbols V0 rows require deferred migration");
    }
    const auto name = record.field(0).as_string().value_or(std::string{});
    const auto old_address_key = std::bit_cast<std::uint64_t>(
        record.field(4).as_integer());
    const Address address = address_map_->decode(old_address_key);
    if (old_address_key != PersistentAddressMap::invalid_key &&
        !address.is_valid()) {
        throw std::runtime_error(
            "Symbols V0 record contains an undecodable address");
    }
    const auto address_key = address_map_->key(address, true);
    auto translated = current_schema()->create_record(destination_id);
    translated->set_string(name_column, name);
    translated->set_integer(address_column,
                            std::bit_cast<std::int64_t>(address_key));
    translated->set_integer(parent_column, global_namespace_id);
    translated->set_integer(type_column,
                            static_cast<std::uint8_t>(SymbolType::label));
    // Preserve the fixed V0 adapter's SourceType.USER_DEFINED.ordinal().
    translated->set_integer(flags_column, 4);
    if (const auto hash = locator_hash(name, global_namespace_id, address_key)) {
        translated->set_integer(locator_hash_column, *hash);
    }
    if (record.field(3).as_boolean()) {
        translated->set_integer(primary_column,
                                std::bit_cast<std::int64_t>(address_key));
    }
    return translated;
}

std::unique_ptr<db::Record> SymbolManager::translate_legacy_record(
    const db::Record &record) const {
    if (stored_schema_version_ < 1 || stored_schema_version_ >= schema_version) {
        throw std::logic_error("symbol record is not from a supported legacy schema");
    }
    auto translated = current_schema()->create_record(record.key().as_integer());
    const auto name = record.field(0).as_string().value_or(std::string{});
    const auto old_address_key = std::bit_cast<std::uint64_t>(
        record.field(1).as_integer());
    std::uint64_t address_key = old_address_key;
    if (mode_ == ProgramOpenMode::upgrade) {
        const Address address = address_map_->decode(old_address_key);
        if (old_address_key != PersistentAddressMap::invalid_key &&
            !address.is_valid()) {
            throw std::runtime_error(
                "legacy Symbols record contains an undecodable address");
        }
        address_key = address_map_->key(address, true);
    }
    const auto namespace_id = record.field(2).as_integer();
    const auto symbol_type = static_cast<std::uint8_t>(
        record.field(3).as_integer());
    translated->set_string(name_column, name);
    translated->set_integer(address_column,
                            std::bit_cast<std::int64_t>(address_key));
    translated->set_integer(parent_column, namespace_id);
    translated->set_integer(type_column, symbol_type);

    if (stored_schema_version_ == 3) {
        translated->set_integer(flags_column, record.field(5).as_integer());
        convert_legacy_string_data(symbol_type, *translated,
                                   record.field(4).as_string());
        if (!record.field(6).is_null()) {
            translated->set_field(locator_hash_column, record.field_copy(6));
        }
        if (!record.field(7).is_null()) {
            translated->set_integer(primary_column,
                                    std::bit_cast<std::int64_t>(address_key));
        }
        if (!record.field(8).is_null()) {
            translated->set_field(data_type_column, record.field_copy(8));
        }
        if (!record.field(9).is_null()) {
            translated->set_field(variable_offset_column, record.field_copy(9));
        }
        return translated;
    }

    convert_legacy_string_data(symbol_type, *translated,
                               record.field(6).as_string());
    if (stored_schema_version_ == 1) {
        // The fixed Ghidra baseline writes SourceType.ordinal(), not the
        // persistent storage ID, in its V1 adapter.  Preserve that observable
        // conversion exactly: DEFAULT is ordinal 0 and USER_DEFINED is 4 in
        // the baseline enum declaration.
        const bool default_function =
            static_cast<SymbolType>(symbol_type) == SymbolType::function &&
            name == default_function_name(address_map_->decode(old_address_key));
        translated->set_integer(flags_column, default_function ? 0 : 4);
    }
    else {
        translated->set_integer(flags_column, record.field(7).as_integer());
    }
    if (const auto hash = locator_hash(name, namespace_id, address_key)) {
        translated->set_integer(locator_hash_column, *hash);
    }
    const auto data_type_id = record.field(4).as_integer();
    if (data_type_id != -1) {
        translated->set_integer(data_type_column, data_type_id);
    }
    const auto type = static_cast<SymbolType>(symbol_type);
    const auto data2 = static_cast<std::int32_t>(record.field(5).as_integer());
    if (type == SymbolType::label && data2 == 1) {
        translated->set_integer(primary_column,
                                std::bit_cast<std::int64_t>(address_key));
    }
    else if (type == SymbolType::parameter ||
             type == SymbolType::local_variable) {
        translated->set_integer(variable_offset_column, data2);
    }
    if (type == SymbolType::function) {
        translated->set_integer(primary_column,
                                std::bit_cast<std::int64_t>(address_key));
    }
    return translated;
}

SymbolManager::SymbolManager(std::shared_ptr<db::DatabaseHandle> database,
                             PersistentAddressMap &address_map,
                             ProgramOpenMode mode,
                             bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) {
        throw std::invalid_argument("symbol manager requires a database");
    }
    if (create) {
        auto schema = current_schema();
        table_ = database_->create_table(
            symbol_table_name, schema,
            {address_column, name_column, parent_column, locator_hash_column,
             primary_column, original_imported_name_column,
             external_program_address_column});
        schema_ = std::move(schema);
        stored_schema_version_ = schema_version;
    }
    else {
        table_ = database_->get_table(symbol_table_name);
        if (!table_) {
            throw std::runtime_error("missing Ghidra Symbols table");
        }
        stored_schema_version_ = table_->schema().version();
        schema_ = current_schema();
        const bool current = stored_schema_version_ == schema_version &&
                             table_->schema().equals(*schema_);
        const bool legacy_v0 = stored_schema_version_ == 0 &&
                               table_->schema().equals(*legacy_schema(0));
        const bool legacy = stored_schema_version_ >= 1 &&
                            stored_schema_version_ < schema_version &&
                            table_->schema().equals(
                                *legacy_schema(stored_schema_version_));
        if (!current && !legacy && !legacy_v0) {
            throw std::runtime_error("unsupported Ghidra Symbols schema");
        }
        if (legacy_v0 && mode_ != ProgramOpenMode::upgrade) {
            throw std::runtime_error(
                "Ghidra Symbols V0 requires coordinated upgrade and cannot be opened directly");
        }
        if (legacy && mode_ == ProgramOpenMode::update) {
            throw std::runtime_error("Ghidra Symbols table requires upgrade");
        }
        if ((legacy || legacy_v0) && mode_ == ProgramOpenMode::upgrade) {
            std::vector<std::unique_ptr<db::Record>> translated;
            const auto zero_id_remap = table_->next_long_key();
            auto iterator = table_->iterator();
            while (iterator->has_next()) {
                if (const auto row = iterator->next()) {
                    if (legacy_v0) {
                        const auto old_address_key = std::bit_cast<std::uint64_t>(
                            row->field(4).as_integer());
                        if (row->field(2).as_boolean()) {
                            deferred_legacy_local_symbols_.push_back(
                                {row->key().as_integer(), old_address_key,
                                 row->field(0).as_string().value_or(std::string{}),
                                 row->field(3).as_boolean()});
                        }
                        if (row->field(1).as_boolean() ||
                            row->field(2).as_boolean()) {
                            continue;
                        }
                        const auto destination_id =
                            row->key().as_integer() == global_namespace_id
                                ? zero_id_remap
                                : row->key().as_integer();
                        translated.push_back(
                            translate_v0_global_record(*row, destination_id));
                    }
                    else {
                        translated.push_back(translate_legacy_record(*row));
                    }
                }
            }
            if (!database_->delete_table(symbol_table_name)) {
                throw std::runtime_error("failed to replace legacy Symbols table");
            }
            table_ = database_->create_table(
                symbol_table_name, schema_,
                {address_column, name_column, parent_column, locator_hash_column,
                 primary_column, original_imported_name_column,
                 external_program_address_column});
            for (auto &row : translated) table_->put_record(*row);
            stored_schema_version_ = schema_version;
        }
    }
}

std::uint64_t SymbolManager::encoded_address(const Address &address, bool create) const {
    return address_map_->key(address, create);
}

std::optional<std::int64_t> SymbolManager::locator_hash(
    const std::string &name,
    std::int64_t namespace_id,
    std::uint64_t address_key) {
    if (name.empty()) {
        return std::nullopt;
    }
    // java.util.Objects.hash(name, namespaceID) is Arrays.hashCode(Object[]).
    std::uint32_t hash = 1;
    hash = hash * 31U + std::bit_cast<std::uint32_t>(java_string_hash(name));
    hash = hash * 31U + std::bit_cast<std::uint32_t>(java_long_hash(namespace_id));
    const std::uint64_t combined = (static_cast<std::uint64_t>(hash) << 32U) |
                                   (address_key & 0xffffffffULL);
    return std::bit_cast<std::int64_t>(combined);
}

std::int64_t SymbolManager::allocate_id() const {
    auto id = table_->next_long_key();
    if (id == global_namespace_id) ++id;
    while (std::ranges::any_of(
        deferred_legacy_local_symbols_, [id](const auto &symbol) {
            return symbol.id == id;
        })) {
        if (id == std::numeric_limits<std::int64_t>::max()) {
            throw std::overflow_error("Symbols key space exhausted");
        }
        ++id;
    }
    return id;
}

void SymbolManager::validate(const Symbol &symbol) {
    if (symbol.id == global_namespace_id) {
        throw std::invalid_argument("symbol id zero is reserved for the global namespace");
    }
    if (symbol.parent_id < global_namespace_id) {
        throw std::invalid_argument("symbol namespace id must be non-negative");
    }
    if (is_namespace_type(symbol.type)) {
        if (symbol.address.is_valid()) {
            throw std::invalid_argument("namespace, class, and library symbols use NO_ADDRESS");
        }
        if (symbol.source == SourceType::default_source) {
            throw std::invalid_argument("namespace, class, and library symbols require an explicit source");
        }
    }
    else if (symbol.type == SymbolType::label || symbol.type == SymbolType::function) {
        if (!symbol.address.is_memory_address() && !symbol.address.is_external_address()) {
            throw std::invalid_argument("label and function symbols require memory or external addresses");
        }
        if (symbol.type == SymbolType::label && symbol.source == SourceType::default_source &&
            !symbol.address.is_external_address()) {
            throw std::invalid_argument("default label source is only valid for external labels");
        }
    }
    else if (symbol.type == SymbolType::parameter ||
             symbol.type == SymbolType::local_variable) {
        if (!symbol.address.is_variable_address()) {
            throw std::invalid_argument("parameter and local-variable symbols require variable addresses");
        }
        if (symbol.parent_id == global_namespace_id) {
            throw std::invalid_argument("parameter and local-variable symbols require a function parent");
        }
    }
    else if (symbol.type == SymbolType::global_variable) {
        if (!symbol.address.is_variable_address() ||
            symbol.parent_id != global_namespace_id) {
            throw std::invalid_argument("global-variable symbols require a variable address and global parent");
        }
    }
    if (symbol.primary && symbol.type != SymbolType::label &&
        symbol.type != SymbolType::function) {
        throw std::invalid_argument("only label and function symbols can be primary");
    }
}

void SymbolManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

std::unique_ptr<db::Record> SymbolManager::encode(const Symbol &symbol) const {
    const auto address_key = encoded_address(symbol.address, true);
    auto record = schema_->create_record(symbol.id);
    record->set_string(name_column, symbol.name);
    record->set_integer(address_column, std::bit_cast<std::int64_t>(address_key));
    record->set_integer(parent_column, symbol.parent_id);
    record->set_integer(type_column, static_cast<std::uint8_t>(symbol.type));
    record->set_integer(flags_column, encode_flags(symbol.source, symbol.pinned));
    if (const auto hash = locator_hash(symbol.name, symbol.parent_id, address_key)) {
        record->set_integer(locator_hash_column, *hash);
    }
    if (symbol.primary) {
        record->set_integer(primary_column, std::bit_cast<std::int64_t>(address_key));
    }
    if (symbol.data_type_id) record->set_integer(data_type_column, *symbol.data_type_id);
    if (symbol.variable_offset) record->set_integer(variable_offset_column, *symbol.variable_offset);
    record->set_string(original_imported_name_column, symbol.original_imported_name);
    record->set_string(external_program_address_column, symbol.external_program_address);
    record->set_string(comment_column, symbol.comment);
    record->set_string(library_path_column, symbol.library_path);
    return record;
}

Symbol SymbolManager::decode(const db::Record &record) const {
    std::unique_ptr<db::Record> legacy_record;
    const db::Record *source = &record;
    if (stored_schema_version_ < schema_version) {
        legacy_record = translate_legacy_record(record);
        source = legacy_record.get();
    }
    Symbol symbol;
    symbol.id = source->key().as_integer();
    symbol.name = source->field(name_column).as_string().value_or(std::string{});
    symbol.address = address_map_->decode(std::bit_cast<std::uint64_t>(
        source->field(address_column).as_integer()));
    symbol.parent_id = source->field(parent_column).as_integer();
    symbol.type = static_cast<SymbolType>(source->field(type_column).as_integer());
    const auto flags = static_cast<std::uint8_t>(source->field(flags_column).as_integer());
    symbol.source = decode_source(flags);
    symbol.pinned = (flags & pinned_flag) != 0;
    symbol.primary = !source->field(primary_column).is_null();
    if (!source->field(data_type_column).is_null()) {
        symbol.data_type_id = source->field(data_type_column).as_integer();
    }
    if (!source->field(variable_offset_column).is_null()) {
        symbol.variable_offset = static_cast<std::int32_t>(
            source->field(variable_offset_column).as_integer());
    }
    symbol.original_imported_name = source->field(original_imported_name_column).as_string();
    symbol.external_program_address = source->field(external_program_address_column).as_string();
    symbol.comment = source->field(comment_column).as_string();
    symbol.library_path = source->field(library_path_column).as_string();
    return symbol;
}

Symbol SymbolManager::create(SymbolSpec spec) {
    require_mutation();
    Symbol symbol{allocate_id(), std::move(spec.name), spec.address, spec.parent_id,
                  spec.type, spec.source, spec.primary, spec.pinned,
                  spec.data_type_id, spec.variable_offset,
                  std::move(spec.original_imported_name),
                  std::move(spec.external_program_address),
                  std::move(spec.comment), std::move(spec.library_path)};
    validate(symbol);
    if (symbol.primary) {
        clear_primary(symbol.address, symbol.id);
    }
    auto record = encode(symbol);
    table_->put_record(*record);
    return symbol;
}

std::optional<Symbol> SymbolManager::get(std::int64_t id) const {
    auto record = table_->record(id);
    return record ? std::optional<Symbol>(decode(*record)) : std::nullopt;
}

std::vector<Symbol> SymbolManager::all() const {
    std::vector<Symbol> result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        if (auto record = iterator->next()) result.push_back(decode(*record));
    }
    return result;
}

std::vector<Symbol> SymbolManager::at(const Address &address) const {
    std::vector<Symbol> result;
    if (stored_schema_version_ < schema_version) {
        for (const auto &symbol : all()) {
            if (symbol.address == address) result.push_back(symbol);
        }
        return result;
    }
    const auto key = encoded_address(address, false);
    db::IntegerField value(db::FieldType::int64, std::bit_cast<std::int64_t>(key));
    const auto index = database_->get_index(symbol_table_name, address_column);
    if (!index) return result;
    for (auto &primary_key : index->find_primary_keys(value)) {
        if (auto record = table_->record(*primary_key)) result.push_back(decode(*record));
    }
    return result;
}

std::vector<Symbol> SymbolManager::named(const std::string &name) const {
    std::vector<Symbol> result;
    if (stored_schema_version_ < schema_version) {
        for (const auto &symbol : all()) {
            if (symbol.name == name) result.push_back(symbol);
        }
        return result;
    }
    db::StringField value{std::optional<std::string>(name)};
    const auto index = database_->get_index(symbol_table_name, name_column);
    if (!index) return result;
    for (auto &primary_key : index->find_primary_keys(value)) {
        if (auto record = table_->record(*primary_key)) result.push_back(decode(*record));
    }
    return result;
}

std::vector<Symbol> SymbolManager::in_namespace(std::int64_t parent_id) const {
    std::vector<Symbol> result;
    if (stored_schema_version_ < schema_version) {
        for (const auto &symbol : all()) {
            if (symbol.parent_id == parent_id) result.push_back(symbol);
        }
        return result;
    }
    db::IntegerField value(db::FieldType::int64, parent_id);
    const auto index = database_->get_index(symbol_table_name, parent_column);
    if (!index) return result;
    for (auto &primary_key : index->find_primary_keys(value)) {
        if (auto record = table_->record(*primary_key)) result.push_back(decode(*record));
    }
    return result;
}

std::vector<Symbol> SymbolManager::named_in_namespace(
    const std::string &name,
    std::int64_t parent_id) const {
    auto result = named(name);
    std::erase_if(result, [parent_id](const Symbol &symbol) {
        return symbol.parent_id != parent_id;
    });
    return result;
}

std::optional<Symbol> SymbolManager::primary_at(const Address &address) const {
    if (stored_schema_version_ < schema_version) {
        for (const auto &symbol : all()) {
            if (symbol.primary && symbol.address == address) return symbol;
        }
        return std::nullopt;
    }
    const auto key = encoded_address(address, false);
    db::IntegerField value(db::FieldType::int64, std::bit_cast<std::int64_t>(key));
    const auto index = database_->get_index(symbol_table_name, primary_column);
    if (!index) return std::nullopt;
    auto keys = index->find_primary_keys(value);
    if (keys.empty()) return std::nullopt;
    auto record = table_->record(*keys.front());
    return record ? std::optional<Symbol>(decode(*record)) : std::nullopt;
}

std::size_t SymbolManager::size() const {
    return static_cast<std::size_t>(table_->record_count());
}

void SymbolManager::clear_primary(const Address &address, std::int64_t except_id) {
    for (const auto &candidate : at(address)) {
        if (candidate.id == except_id || !candidate.primary) continue;
        auto record = table_->record(candidate.id);
        record->set_null(primary_column);
        table_->put_record(*record);
    }
}

void SymbolManager::update(const Symbol &symbol) {
    require_mutation();
    validate(symbol);
    if (!table_->has_record(symbol.id)) {
        throw std::out_of_range("symbol does not exist");
    }
    if (symbol.primary) clear_primary(symbol.address, symbol.id);
    auto record = encode(symbol);
    table_->put_record(*record);
}

void SymbolManager::rename(std::int64_t id, std::string name, SourceType source) {
    auto symbol = get(id);
    if (!symbol) throw std::out_of_range("symbol does not exist");
    symbol->name = std::move(name);
    symbol->source = source;
    update(*symbol);
}

void SymbolManager::set_namespace(std::int64_t id, std::int64_t parent_id) {
    auto symbol = get(id);
    if (!symbol) throw std::out_of_range("symbol does not exist");
    if (parent_id == id) throw std::invalid_argument("symbol cannot contain itself");
    for (auto cursor = get(parent_id); cursor; cursor = get(cursor->parent_id)) {
        if (cursor->id == id) throw std::invalid_argument("namespace cycle");
        if (cursor->parent_id == global_namespace_id) break;
    }
    symbol->parent_id = parent_id;
    update(*symbol);
}

void SymbolManager::set_primary(std::int64_t id) {
    auto symbol = get(id);
    if (!symbol) throw std::out_of_range("symbol does not exist");
    symbol->primary = true;
    update(*symbol);
}

void SymbolManager::move(std::int64_t id, Address address) {
    auto symbol = get(id);
    if (!symbol) throw std::out_of_range("symbol does not exist");
    symbol->address = std::move(address);
    update(*symbol);
}

bool SymbolManager::remove(std::int64_t id) {
    require_mutation();
    if (!in_namespace(id).empty()) {
        throw std::logic_error("cannot remove a namespace that still contains symbols");
    }
    if (!table_->has_record(id)) return false;
    if (external_removal_handler_) external_removal_handler_(id);
    return table_->delete_record(id);
}

std::size_t SymbolManager::remove_range(const Address &start,
                                        const Address &end,
                                        bool preserve_pinned) {
    require_mutation();
    if (!start.same_space(end) || end < start) {
        throw std::invalid_argument("symbol removal range is invalid");
    }
    std::vector<std::int64_t> ids;
    for (const auto &symbol : all()) {
        if (!symbol.address.is_valid() || !symbol.address.same_space(start) ||
            symbol.address < start || symbol.address > end ||
            (preserve_pinned && symbol.pinned)) {
            continue;
        }
        ids.push_back(symbol.id);
    }
    std::size_t removed = 0;
    for (const auto id : ids) {
        if (external_removal_handler_) external_removal_handler_(id);
        removed += table_->delete_record(id) ? 1U : 0U;
    }
    return removed;
}

void SymbolManager::move_address_range(const Address &from,
                                       const Address &to,
                                       std::uint64_t length) {
    require_mutation();
    if (!from.is_memory_address() || !to.is_memory_address() || length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("symbol move range is invalid");
    }
    const auto end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    std::vector<Symbol> moved;
    std::vector<SymbolSpec> pinned_function_replacements;
    for (auto symbol : all()) {
        if (!symbol.address.same_space(from) || symbol.address < from ||
            symbol.address > end) {
            continue;
        }
        if (symbol.pinned && symbol.type != SymbolType::function) continue;
        const auto old_address = symbol.address;
        symbol.address = to.add_no_wrap(old_address.subtract(from));
        if (symbol.pinned && symbol.type == SymbolType::function) {
            pinned_function_replacements.push_back(SymbolSpec{
                symbol.name, old_address, symbol.parent_id, SymbolType::label,
                symbol.source, symbol.primary, true});
            symbol.pinned = false;
        }
        moved.push_back(std::move(symbol));
    }
    for (const auto &symbol : moved) update(symbol);
    for (auto &replacement : pinned_function_replacements) {
        (void)create(std::move(replacement));
    }
}

std::size_t SymbolManager::replace_data_type(std::int64_t replaced_id,
                                             std::int64_t replacement_id) {
    require_mutation();
    if (replaced_id == replacement_id) return 0;
    std::size_t changed = 0;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (!record || record->field(data_type_column).is_null() ||
            record->field(data_type_column).as_integer() != replaced_id) {
            continue;
        }
        record->set_integer(data_type_column, replacement_id);
        table_->put_record(*record);
        ++changed;
    }
    return changed;
}

void SymbolManager::set_external_removal_handler(
    std::function<void(std::int64_t)> handler) {
    external_removal_handler_ = std::move(handler);
}

void SymbolManager::set_language(const LanguageTranslator &translator) {
    require_mutation();
    std::vector<Symbol> replacements;
    for (auto symbol : all()) {
        if (!symbol.external_program_address) continue;
        const auto old_address = translator.old_address_factory().parse_address(
            *symbol.external_program_address);
        if (!old_address) {
            // Upstream treats an unparseable value as a possible overlay or
            // non-address payload and leaves it unchanged.
            continue;
        }
        const auto translated = translator.new_address(*old_address);
        if (!translated || !translated->is_loaded_memory_address()) {
            throw std::runtime_error(
                "language translation cannot preserve external symbol address: " +
                *symbol.external_program_address);
        }
        symbol.external_program_address = translated->to_string();
        replacements.push_back(std::move(symbol));
    }
    for (const auto &symbol : replacements) update(symbol);
}

bool SymbolManager::has_deferred_legacy_local_symbols() const noexcept {
    return !deferred_legacy_local_symbols_.empty();
}

void SymbolManager::finalize_legacy_local_symbols(
    NamespaceManager &namespaces) {
    if (deferred_legacy_local_symbols_.empty()) return;
    require_mutation();
    std::uint64_t sequence{};
    for (const auto &legacy : deferred_legacy_local_symbols_) {
        const Address address = address_map_->decode(legacy.old_address_key);
        if (!address.is_valid()) {
            throw std::runtime_error(
                "deferred Symbols V0 local contains an undecodable address");
        }
        const auto namespace_id = namespaces.namespace_containing(address);
        if (namespace_id == global_namespace_id) {
            ++sequence;
            continue;
        }
        if (table_->has_record(legacy.id)) {
            throw std::runtime_error(
                "deferred Symbols V0 local ID collides with an upgraded symbol");
        }
        std::string name = legacy.name;
        if (starts_with_default_dynamic_prefix(name)) name.insert(name.begin(), '_');
        while (std::ranges::any_of(
            named_in_namespace(name, namespace_id), [&](const Symbol &candidate) {
                return candidate.address == address;
            })) {
            name = legacy.name + std::to_string(++sequence);
        }
        const auto address_key = address_map_->key(address, true);
        auto record = schema_->create_record(legacy.id);
        record->set_string(name_column, name);
        record->set_integer(address_column,
                            std::bit_cast<std::int64_t>(address_key));
        record->set_integer(parent_column, namespace_id);
        record->set_integer(type_column,
                            static_cast<std::uint8_t>(SymbolType::label));
        // SymbolManager.saveLocalSymbol/addSymbolRecord also persisted the
        // fixed baseline USER_DEFINED ordinal rather than its storage ID.
        record->set_integer(flags_column, 4);
        if (const auto hash = locator_hash(name, namespace_id, address_key)) {
            record->set_integer(locator_hash_column, *hash);
        }
        if (legacy.primary) {
            record->set_integer(primary_column,
                                std::bit_cast<std::int64_t>(address_key));
        }
        table_->put_record(*record);
        ++sequence;
    }
    deferred_legacy_local_symbols_.clear();
}

void SymbolManager::invalidate_cache() {
    table_ = database_->get_table(symbol_table_name);
    if (!table_) {
        throw std::runtime_error("unsupported or missing Ghidra Symbols table");
    }
    stored_schema_version_ = table_->schema().version();
    schema_ = current_schema();
    const bool current = stored_schema_version_ == schema_version &&
                         table_->schema().equals(*schema_);
    const bool legacy = mode_ == ProgramOpenMode::read_only &&
                        stored_schema_version_ >= 1 &&
                        stored_schema_version_ < schema_version &&
                        table_->schema().equals(
                            *legacy_schema(stored_schema_version_));
    if (!current && !legacy) {
        throw std::runtime_error("unsupported Ghidra Symbols table");
    }
}

} // namespace llmghidra::program
