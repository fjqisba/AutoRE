#include "llmghidra/program/property_map_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr std::size_t property_type_column = 0;
constexpr std::size_t object_class_column = 1;
constexpr std::size_t object_version_column = 2;

[[nodiscard]] db::FieldType value_field_type(PropertyMapKind kind) {
    switch (kind) {
    case PropertyMapKind::int32: return db::FieldType::int32;
    case PropertyMapKind::int64: return db::FieldType::int64;
    case PropertyMapKind::string: return db::FieldType::string;
    default:
        throw std::invalid_argument("property kind has no primitive value field");
    }
}

} // namespace

std::shared_ptr<db::Schema> PropertyMapManager::registry_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::StringField>(), "Name", std::move(fields),
        std::vector<std::string>{"Type", "Object Class", "Version"});
}

std::shared_ptr<db::Schema> PropertyMapManager::primitive_schema(
    PropertyMapKind kind) {
    std::vector<std::unique_ptr<db::Field>> fields;
    std::vector<std::string> names;
    if (kind != PropertyMapKind::marker) {
        fields.push_back(db::make_field(value_field_type(kind)));
        names.emplace_back("Value");
    }
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Address", std::move(fields), std::move(names));
}

std::string PropertyMapManager::map_table_name(const std::string &name) {
    return std::string(map_table_prefix) + name;
}

PropertyMapManager::PropertyMapManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    ProgramOpenMode mode,
    bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) {
        throw std::invalid_argument("property manager requires a database");
    }
    registry_ = database_->get_table(registry_table_name);
    if (create) {
        if (registry_) throw std::runtime_error("Properties table already exists");
        registry_ = database_->create_table(registry_table_name,
                                             registry_schema());
    }
    else if (!registry_) {
        throw std::runtime_error("Ghidra Properties table is missing");
    }
    validate_registry();
    for (const auto &entry : definitions()) validate_map(entry);
}

void PropertyMapManager::validate_name(const std::string &name) {
    if (name.empty() || std::ranges::any_of(name, [](unsigned char value) {
            return value == 0 || value == '/' || value == '\\';
        })) {
        throw std::invalid_argument("property map name is invalid");
    }
}

void PropertyMapManager::validate_registry() const {
    if (registry_ && !registry_->schema().equals(*registry_schema())) {
        throw std::runtime_error("unsupported Ghidra Properties schema");
    }
}

std::vector<PropertyMapDefinition> PropertyMapManager::definitions() const {
    std::vector<PropertyMapDefinition> result;
    if (!registry_) return result;
    auto iterator = registry_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record) continue;
        PropertyMapDefinition definition;
        definition.name = record->key().as_string().value_or(std::string{});
        const auto raw_kind = record->field(property_type_column).as_integer();
        if (raw_kind < 0 || raw_kind > 4) {
            throw std::runtime_error(
                "Properties registry contains an unsupported type");
        }
        definition.kind = static_cast<PropertyMapKind>(raw_kind);
        definition.object_class =
            record->field(object_class_column).as_string();
        definition.object_schema_version = static_cast<std::int32_t>(
            record->field(object_version_column).as_integer());
        if (definition.name.empty() ||
            (definition.kind == PropertyMapKind::object &&
             !definition.object_class)) {
            throw std::runtime_error(
                "Properties registry contains an invalid definition");
        }
        result.push_back(std::move(definition));
    }
    std::ranges::sort(result, {}, &PropertyMapDefinition::name);
    return result;
}

std::optional<PropertyMapDefinition> PropertyMapManager::definition(
    const std::string &name) const {
    for (auto value : definitions()) {
        if (value.name == name) return value;
    }
    return std::nullopt;
}

void PropertyMapManager::validate_map(
    const PropertyMapDefinition &definition_value) const {
    const auto table = database_->get_table(map_table_name(definition_value.name));
    if (!table) return;
    if (definition_value.kind == PropertyMapKind::object) {
        if (table->schema().key_type().type() != db::FieldType::int64 ||
            table->schema().version() != definition_value.object_schema_version) {
            throw std::runtime_error(
                "Ghidra object property map schema does not match its registry");
        }
        return;
    }
    if (!table->schema().equals(*primitive_schema(definition_value.kind))) {
        throw std::runtime_error(
            "Ghidra primitive property map schema mismatch");
    }
}

void PropertyMapManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

PropertyMapDefinition PropertyMapManager::create(
    std::string name,
    PropertyMapKind kind) {
    require_mutation();
    validate_name(name);
    if (kind == PropertyMapKind::object) {
        throw std::invalid_argument("use create_object for object property maps");
    }
    if (definition(name)) {
        throw std::invalid_argument("property map already exists");
    }
    auto record = registry_schema()->create_record(
        std::make_unique<db::StringField>(name));
    record->set_integer(property_type_column, static_cast<std::uint8_t>(kind));
    registry_->put_record(*record);
    (void)database_->create_table(map_table_name(name), primitive_schema(kind));
    return {std::move(name), kind, std::nullopt, 0};
}

PropertyMapDefinition PropertyMapManager::create_object(
    std::string name,
    std::string object_class,
    std::shared_ptr<const db::Schema> schema) {
    require_mutation();
    validate_name(name);
    if (object_class.empty() || !schema ||
        schema->key_type().type() != db::FieldType::int64) {
        throw std::invalid_argument(
            "object property map requires a class and long-key schema");
    }
    if (definition(name)) {
        throw std::invalid_argument("property map already exists");
    }
    auto record = registry_schema()->create_record(
        std::make_unique<db::StringField>(name));
    record->set_integer(property_type_column,
                        static_cast<std::uint8_t>(PropertyMapKind::object));
    record->set_string(object_class_column, object_class);
    record->set_integer(object_version_column, schema->version());
    registry_->put_record(*record);
    (void)database_->create_table(map_table_name(name), std::move(schema));
    return {std::move(name), PropertyMapKind::object,
            std::move(object_class), static_cast<std::int32_t>(
                record->field(object_version_column).as_integer())};
}

std::shared_ptr<db::Table> PropertyMapManager::map_table(
    const PropertyMapDefinition &definition_value) const {
    auto table = database_->get_table(map_table_name(definition_value.name));
    if (!table) {
        throw std::runtime_error(
            "Properties registry points to a missing property table");
    }
    return table;
}

void PropertyMapManager::validate_value(PropertyMapKind kind,
                                        const PropertyValue &value) {
    const bool valid =
        (kind == PropertyMapKind::marker &&
         std::holds_alternative<std::monostate>(value)) ||
        (kind == PropertyMapKind::int32 &&
         std::holds_alternative<std::int32_t>(value)) ||
        (kind == PropertyMapKind::int64 &&
         std::holds_alternative<std::int64_t>(value)) ||
        (kind == PropertyMapKind::string &&
         std::holds_alternative<std::string>(value));
    if (!valid) throw std::invalid_argument("property value type mismatch");
}

void PropertyMapManager::set(const std::string &name,
                             const Address &address,
                             PropertyValue value) {
    require_mutation();
    const auto definition_value = definition(name);
    if (!definition_value) throw std::out_of_range("property map does not exist");
    if (definition_value->kind == PropertyMapKind::object) {
        throw std::invalid_argument(
            "object properties must use their schema-specific table adapter");
    }
    validate_value(definition_value->kind, value);
    const auto key = std::bit_cast<std::int64_t>(
        address_map_->key(address, true));
    auto record = primitive_schema(definition_value->kind)->create_record(key);
    if (const auto item = std::get_if<std::int32_t>(&value)) {
        record->set_integer(0, *item);
    }
    else if (const auto item = std::get_if<std::int64_t>(&value)) {
        record->set_integer(0, *item);
    }
    else if (const auto item = std::get_if<std::string>(&value)) {
        record->set_string(0, *item);
    }
    map_table(*definition_value)->put_record(*record);
}

PropertyValue PropertyMapManager::decode_value(
    const PropertyMapDefinition &definition_value,
    const db::Table &table,
    const db::Field &key) const {
    const auto record = table.record(key);
    if (!record) throw std::out_of_range("property record does not exist");
    switch (definition_value.kind) {
    case PropertyMapKind::marker: return std::monostate{};
    case PropertyMapKind::int32:
        return static_cast<std::int32_t>(record->field(0).as_integer());
    case PropertyMapKind::int64: return record->field(0).as_integer();
    case PropertyMapKind::string:
        return record->field(0).as_string().value_or(std::string{});
    case PropertyMapKind::object:
        throw std::invalid_argument(
            "object property value requires a schema-specific adapter");
    }
    throw std::runtime_error("unknown property map kind");
}

std::optional<PropertyValue> PropertyMapManager::get(
    const std::string &name,
    const Address &address) const {
    const auto definition_value = definition(name);
    if (!definition_value) return std::nullopt;
    const auto table = map_table(*definition_value);
    db::IntegerField key(db::FieldType::int64, std::bit_cast<std::int64_t>(
        address_map_->key(address, false)));
    if (!table->has_record(key)) return std::nullopt;
    return decode_value(*definition_value, *table, key);
}

bool PropertyMapManager::contains(const std::string &name,
                                  const Address &address) const {
    const auto definition_value = definition(name);
    if (!definition_value) return false;
    db::IntegerField key(db::FieldType::int64, std::bit_cast<std::int64_t>(
        address_map_->key(address, false)));
    return map_table(*definition_value)->has_record(key);
}

bool PropertyMapManager::remove(const std::string &name,
                                const Address &address) {
    require_mutation();
    const auto definition_value = definition(name);
    if (!definition_value) return false;
    db::IntegerField key(db::FieldType::int64, std::bit_cast<std::int64_t>(
        address_map_->key(address, false)));
    return map_table(*definition_value)->delete_record(key);
}

std::vector<AddressProperty> PropertyMapManager::entries(
    const std::string &name) const {
    const auto definition_value = definition(name);
    if (!definition_value) return {};
    if (definition_value->kind == PropertyMapKind::object) {
        throw std::invalid_argument(
            "object property entries require a schema-specific adapter");
    }
    const auto table = map_table(*definition_value);
    std::vector<AddressProperty> result;
    auto iterator = table->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record) continue;
        const auto address = address_map_->decode(std::bit_cast<std::uint64_t>(
            record->key().as_integer()));
        if (!address.is_valid()) {
            throw std::runtime_error("property map contains an invalid address");
        }
        result.push_back({address,
                          decode_value(*definition_value, *table,
                                       record->key())});
    }
    std::ranges::sort(result, {}, &AddressProperty::address);
    return result;
}

void PropertyMapManager::clear(const std::string &name) {
    require_mutation();
    const auto definition_value = definition(name);
    if (!definition_value) return;
    map_table(*definition_value)->delete_all();
}

bool PropertyMapManager::remove_map(const std::string &name) {
    require_mutation();
    const auto definition_value = definition(name);
    if (!definition_value) return false;
    if (!database_->delete_table(map_table_name(name))) {
        throw std::runtime_error("failed to delete property map table");
    }
    db::StringField key(name);
    if (!registry_->delete_record(key)) {
        throw std::runtime_error("failed to delete property map definition");
    }
    return true;
}

void PropertyMapManager::remove_all(const Address &address) {
    require_mutation();
    for (const auto &definition_value : definitions()) {
        db::IntegerField key(db::FieldType::int64, std::bit_cast<std::int64_t>(
            address_map_->key(address, false)));
        (void)map_table(definition_value)->delete_record(key);
    }
}

void PropertyMapManager::delete_address_range(const Address &start,
                                              const Address &end) {
    require_mutation();
    if (!start.same_space(end) || end < start) {
        throw std::invalid_argument("property delete range is invalid");
    }
    for (const auto &definition_value : definitions()) {
        auto table = map_table(definition_value);
        std::vector<std::unique_ptr<db::Field>> keys;
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (!record) continue;
            const auto address = address_map_->decode(
                std::bit_cast<std::uint64_t>(record->key().as_integer()));
            if (address.same_space(start) && address >= start && address <= end) {
                keys.push_back(record->key().clone());
            }
        }
        for (const auto &key : keys) (void)table->delete_record(*key);
    }
}

void PropertyMapManager::move_address_range(
    const Address &from,
    const Address &to,
    std::uint64_t length) {
    require_mutation();
    if (length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("property move length is invalid");
    }
    const auto end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    (void)to.add_no_wrap(static_cast<std::int64_t>(length - 1));
    for (const auto &definition_value : definitions()) {
        auto table = map_table(definition_value);
        std::vector<std::pair<std::unique_ptr<db::Record>, Address>> moved;
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (!record) continue;
            const auto address = address_map_->decode(
                std::bit_cast<std::uint64_t>(record->key().as_integer()));
            if (address.same_space(from) && address >= from && address <= end) {
                moved.emplace_back(std::move(record), address);
            }
        }
        for (const auto &entry : moved) {
            (void)table->delete_record(entry.first->key());
        }
        for (auto &entry : moved) {
            const auto destination = to.add_no_wrap(entry.second.subtract(from));
            entry.first->set_key(std::make_unique<db::IntegerField>(
                db::FieldType::int64, std::bit_cast<std::int64_t>(
                    address_map_->key(destination, true))));
            table->put_record(*entry.first);
        }
    }
}

std::shared_ptr<db::Table> PropertyMapManager::object_table(
    const std::string &name) const {
    const auto definition_value = definition(name);
    if (!definition_value ||
        definition_value->kind != PropertyMapKind::object) {
        return {};
    }
    return map_table(*definition_value);
}

void PropertyMapManager::invalidate_cache() {
    registry_ = database_->get_table(registry_table_name);
    validate_registry();
    for (const auto &entry : definitions()) validate_map(entry);
}

} // namespace llmghidra::program
