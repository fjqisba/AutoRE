#pragma once

#include "llmghidra/program/persistent_address_map.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Field;
class Schema;
class Table;
}

namespace llmghidra::program {

enum class PropertyMapKind : std::uint8_t {
    int32 = 0,
    int64 = 1,
    string = 2,
    marker = 3,
    object = 4,
};

using PropertyValue =
    std::variant<std::monostate, std::int32_t, std::int64_t, std::string>;

struct PropertyMapDefinition {
    std::string name;
    PropertyMapKind kind{PropertyMapKind::marker};
    std::optional<std::string> object_class;
    std::int32_t object_schema_version{};
};

struct AddressProperty {
    Address address;
    PropertyValue value;
};

// Native DBPropertyMapManager for Ghidra's Properties V0 registry and
// primitive "Property Map - <name>" tables. Object maps remain schema-driven:
// their exact table is exposed to the C++ type adapter that owns the Saveable
// layout instead of requiring Java reflection.
class PropertyMapManager final {
public:
    static constexpr const char *registry_table_name = "Properties";
    static constexpr const char *map_table_prefix = "Property Map - ";

    PropertyMapManager(std::shared_ptr<db::DatabaseHandle> database,
                       PersistentAddressMap &address_map,
                       ProgramOpenMode mode,
                       bool create);

    [[nodiscard]] PropertyMapDefinition create(
        std::string name,
        PropertyMapKind kind);
    [[nodiscard]] PropertyMapDefinition create_object(
        std::string name,
        std::string object_class,
        std::shared_ptr<const db::Schema> schema);
    [[nodiscard]] std::optional<PropertyMapDefinition> definition(
        const std::string &name) const;
    [[nodiscard]] std::vector<PropertyMapDefinition> definitions() const;
    [[nodiscard]] bool remove_map(const std::string &name);

    void set(const std::string &name,
             const Address &address,
             PropertyValue value = std::monostate{});
    [[nodiscard]] std::optional<PropertyValue> get(
        const std::string &name,
        const Address &address) const;
    [[nodiscard]] bool contains(const std::string &name,
                                const Address &address) const;
    [[nodiscard]] bool remove(const std::string &name,
                              const Address &address);
    [[nodiscard]] std::vector<AddressProperty> entries(
        const std::string &name) const;
    void clear(const std::string &name);
    void remove_all(const Address &address);
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);

    [[nodiscard]] std::shared_ptr<db::Table> object_table(
        const std::string &name) const;
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> registry_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> primitive_schema(
        PropertyMapKind kind);
    [[nodiscard]] std::shared_ptr<db::Table> map_table(
        const PropertyMapDefinition &definition) const;
    [[nodiscard]] static std::string map_table_name(const std::string &name);
    [[nodiscard]] PropertyValue decode_value(
        const PropertyMapDefinition &definition,
        const db::Table &table,
        const db::Field &key) const;
    static void validate_name(const std::string &name);
    static void validate_value(PropertyMapKind kind,
                               const PropertyValue &value);
    void validate_registry() const;
    void validate_map(const PropertyMapDefinition &definition) const;
    void require_mutation() const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    ProgramOpenMode mode_{};
    std::shared_ptr<db::Table> registry_;
};

} // namespace llmghidra::program
