#pragma once

#include "llmghidra/program/address.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Record;
class Schema;
class Table;
}

namespace llmghidra::program {

class PersistentAddressMap;

struct LegacyVariableStorageRecord {
    std::int64_t variable_id{};
    std::uint64_t old_storage_address_key{};
    Address storage_address;
    std::int64_t namespace_id{};
    std::int32_t symbol_count{};
};

// Native source adapter for the namespace-specific VariableStorage V0/V1
// table (without a space in its name).  Conversion to current compound
// storage is coordinated with Symbols and DataType sizes at Program level.
class LegacyVariableStorageUpgrade final {
public:
    static constexpr const char *table_name = "VariableStorage";

    [[nodiscard]] static bool present(
        const std::shared_ptr<db::DatabaseHandle> &database);

    LegacyVariableStorageUpgrade(std::shared_ptr<db::DatabaseHandle> database,
                                 PersistentAddressMap &address_map);

    [[nodiscard]] std::vector<LegacyVariableStorageRecord> records() const;
    [[nodiscard]] std::optional<LegacyVariableStorageRecord> record(
        std::int64_t variable_id) const;
    [[nodiscard]] std::vector<LegacyVariableStorageRecord> in_namespace(
        std::int64_t namespace_id) const;
    void delete_source_table();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> schema(int version);
    [[nodiscard]] LegacyVariableStorageRecord decode(
        const db::Record &record) const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    std::shared_ptr<db::Table> table_;
};

} // namespace llmghidra::program
