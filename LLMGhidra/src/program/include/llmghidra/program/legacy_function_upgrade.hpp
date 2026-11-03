#pragma once

#include "llmghidra/program/address_set.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Schema;
class Table;
}

namespace llmghidra::program {

class PersistentAddressMap;

struct LegacyStackVariableRecord {
    std::int64_t record_id{};
    std::int32_t offset{};
    std::int64_t data_type_id{};
    std::int32_t data_type_length{};
    std::string name;
    std::optional<std::string> comment;
};

struct LegacyRegisterParameterRecord {
    std::int64_t record_id{};
    std::string register_name;
    std::int64_t data_type_id{};
    std::string name;
    std::optional<std::string> comment;
};

struct LegacyFunctionRecord {
    std::uint64_t old_entry_key{};
    Address entry;
    std::int64_t return_data_type_id{};
    std::int32_t stack_depth{};
    std::int32_t stack_parameter_offset{};
    std::int32_t stack_return_offset{};
    std::int32_t stack_local_size{};
    std::optional<std::string> repeatable_comment;
    AddressSet body;
    std::vector<LegacyStackVariableRecord> stack_variables;
    std::vector<LegacyRegisterParameterRecord> register_parameters;
};

// Read-only native adapter for the pre-Function-Data layout used by Ghidra
// 2.1 and earlier.  Mutation is deliberately separated from extraction so a
// coordinated Program upgrade can validate every source table before deleting
// any historical data.
class LegacyFunctionUpgrade final {
public:
    static constexpr const char *function_table_name = "Functions";

    [[nodiscard]] static bool present(
        const std::shared_ptr<db::DatabaseHandle> &database);

    LegacyFunctionUpgrade(std::shared_ptr<db::DatabaseHandle> database,
                          PersistentAddressMap &address_map);

    [[nodiscard]] std::vector<LegacyFunctionRecord> records() const;
    void delete_source_tables();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> function_schema(int version);
    [[nodiscard]] static std::shared_ptr<db::Schema> stack_schema(int version);
    [[nodiscard]] static std::shared_ptr<db::Schema> register_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> shared_range_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> shared_map_schema();

    [[nodiscard]] AddressSet body(std::int64_t function_key) const;
    [[nodiscard]] std::vector<LegacyStackVariableRecord> stack_variables(
        std::int64_t function_key) const;
    [[nodiscard]] std::vector<LegacyRegisterParameterRecord> register_parameters(
        std::int64_t function_key) const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    std::shared_ptr<db::Table> functions_;
    std::shared_ptr<db::Table> stack_variables_;
    std::shared_ptr<db::Table> register_parameters_;
    std::shared_ptr<db::Table> shared_ranges_;
    std::shared_ptr<db::Table> shared_map_;
    int function_version_{};
    int stack_version_{};
};

} // namespace llmghidra::program
