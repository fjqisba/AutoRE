#pragma once

#include "llmghidra/program/address_range_map.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
}

namespace llmghidra::program {

class SymbolManager;

class NamespaceManager final {
public:
    static constexpr std::int64_t global_namespace_id = 0;

    NamespaceManager(std::shared_ptr<db::DatabaseHandle> database,
                     PersistentAddressMap &address_map,
                     SymbolManager &symbols,
                     ProgramOpenMode mode);

    [[nodiscard]] AddressSet body(std::int64_t namespace_id,
                                  bool include_children = true) const;
    void set_body(std::int64_t namespace_id, const AddressSet &body);
    [[nodiscard]] AddressSet remove_body(std::int64_t namespace_id);
    [[nodiscard]] std::int64_t namespace_containing(
        const Address &address) const;
    [[nodiscard]] std::optional<AddressRange> first_overlap(
        const AddressSet &body,
        std::optional<std::int64_t> except_namespace = std::nullopt) const;
    [[nodiscard]] std::vector<std::int64_t> overlapping_namespaces(
        const AddressSet &body) const;
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);
    void invalidate_cache();

private:
    [[nodiscard]] bool valid_namespace(std::int64_t namespace_id) const;
    [[nodiscard]] AddressSet direct_body(std::int64_t namespace_id) const;
    void append_body(std::int64_t namespace_id,
                     AddressSet &result,
                     std::vector<std::int64_t> &active) const;

    SymbolManager *symbols_{};
    AddressRangeMap ranges_;
};

} // namespace llmghidra::program
