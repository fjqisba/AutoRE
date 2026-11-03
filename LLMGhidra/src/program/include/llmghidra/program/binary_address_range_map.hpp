#pragma once

#include "llmghidra/program/address_range.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

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

struct BinaryAddressRangeValue {
    AddressRange range;
    std::vector<std::uint8_t> value;
};

// BinaryField specialization of AddressRangeMapDB. Register context uses this
// exact schema without a Value index.
class BinaryAddressRangeMap final {
public:
    static constexpr int schema_version = 0;

    BinaryAddressRangeMap(std::shared_ptr<db::DatabaseHandle> database,
                          PersistentAddressMap &address_map,
                          ProgramOpenMode mode,
                          std::string map_name);

    [[nodiscard]] bool has_table() const noexcept;
    [[nodiscard]] bool empty() const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> value_at(
        const Address &address) const;
    [[nodiscard]] std::vector<BinaryAddressRangeValue> entries() const;
    [[nodiscard]] std::optional<AddressRange> range_containing(
        const Address &address) const;

    void paint(const Address &start,
               const Address &end,
               std::vector<std::uint8_t> value);
    void clear(const Address &start, const Address &end);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);
    void dispose();
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> current_schema();
    [[nodiscard]] std::vector<BinaryAddressRangeValue> load_entries() const;
    static void normalize(std::vector<BinaryAddressRangeValue> &values);
    void store_entries(std::vector<BinaryAddressRangeValue> values);
    [[nodiscard]] std::shared_ptr<db::Table> require_table();
    void require_mutation() const;
    void validate_table() const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    std::shared_ptr<db::Table> table_;
    ProgramOpenMode mode_{};
    std::string table_name_;
};

} // namespace llmghidra::program
