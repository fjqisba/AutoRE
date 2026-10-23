#pragma once

#include "llmghidra/program/address.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Record;
class Schema;
class Table;
}

namespace llmghidra::program {

struct Equate {
    std::int64_t id{};
    std::string name;
    std::int64_t value{};
};

struct EquateReference {
    std::int64_t id{};
    std::int64_t equate_id{};
    Address address;
    std::int16_t operand_index{};
    std::int64_t varnode_hash{};
};

// Native EquateDBAdapter V0 and EquateRefDBAdapter V0/V1 manager.
class EquateManager final {
public:
    EquateManager(std::shared_ptr<db::DatabaseHandle> database,
                  PersistentAddressMap &address_map,
                  ProgramOpenMode mode,
                  bool create);

    [[nodiscard]] Equate create(std::string name, std::int64_t value);
    [[nodiscard]] std::optional<Equate> by_id(std::int64_t id) const;
    [[nodiscard]] std::optional<Equate> by_name(const std::string &name) const;
    [[nodiscard]] std::vector<Equate> all() const;
    void rename(std::int64_t id, std::string name);
    [[nodiscard]] bool remove(std::int64_t id);

    [[nodiscard]] EquateReference add_reference(
        std::int64_t equate_id, const Address &address,
        std::int16_t operand_index, std::int64_t varnode_hash = 0);
    [[nodiscard]] std::vector<EquateReference> references(
        std::optional<std::int64_t> equate_id = std::nullopt) const;
    [[nodiscard]] std::vector<EquateReference> references_at(
        const Address &address) const;
    [[nodiscard]] bool remove_reference(std::int64_t reference_id,
                                        bool remove_orphan_equate = false);
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from, const Address &to,
                            std::uint64_t length);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> equate_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> reference_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_reference_schema();
    void create_tables();
    void open_tables();
    void require_mutation() const;
    [[nodiscard]] Equate decode_equate(const db::Record &record) const;
    [[nodiscard]] EquateReference decode_reference(const db::Record &record) const;
    [[nodiscard]] std::size_t reference_count(std::int64_t equate_id) const;
    void remove_orphan(std::int64_t equate_id);

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    ProgramOpenMode mode_{};
    std::shared_ptr<db::Table> equate_table_;
    std::shared_ptr<db::Table> reference_table_;
};

} // namespace llmghidra::program
