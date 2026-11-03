#pragma once

#include "llmghidra/program/address_set.hpp"
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

struct AddressRangeValue {
    AddressRange range;
    std::int64_t value{};
};

// Long-valued specialization of Ghidra AddressRangeMapDB.  It preserves the
// Range Map schema, AddressMapDB keys, split/merge painting semantics and the
// wrapping-record representation used at an address-space boundary.
class AddressRangeMap final {
public:
    static constexpr int schema_version = 0;

    AddressRangeMap(std::shared_ptr<db::DatabaseHandle> database,
                    PersistentAddressMap &address_map,
                    ProgramOpenMode mode,
                    std::string map_name,
                    bool indexed = true);

    [[nodiscard]] bool has_table() const noexcept;
    [[nodiscard]] std::optional<std::int64_t> value_at(
        const Address &address) const;
    [[nodiscard]] std::vector<AddressRangeValue> entries() const;
    [[nodiscard]] std::vector<AddressRange> ranges(
        const Address &start,
        const Address &end) const;
    [[nodiscard]] AddressSet address_set(std::int64_t value) const;

    void paint(const Address &start, const Address &end, std::int64_t value);
    void clear(const Address &start, const Address &end);
    void clear_all();
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> current_schema();
    [[nodiscard]] std::vector<AddressRangeValue> load_entries() const;
    static void normalize(std::vector<AddressRangeValue> &values);
    void store_entries(std::vector<AddressRangeValue> values);
    [[nodiscard]] std::shared_ptr<db::Table> require_table();
    void require_mutation() const;
    void validate_table() const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    std::shared_ptr<db::Table> table_;
    ProgramOpenMode mode_{};
    std::string table_name_;
    bool indexed_{true};
};

} // namespace llmghidra::program
