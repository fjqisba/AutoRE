#pragma once

#include "llmghidra/program/address.hpp"

#include <array>
#include <cstddef>
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
enum class ProgramOpenMode;

// Persisted ordinals match ghidra.program.model.listing.CommentType.
enum class CommentType : std::uint8_t {
    end_of_line = 0,
    pre = 1,
    post = 2,
    plate = 3,
    repeatable = 4,
};

struct CommentRecord {
    Address address;
    std::array<std::optional<std::string>, 5> comments;
};

// Native adapter for Ghidra's current Comments table.  Function plate and
// repeatable comments live here rather than in Function Data.
class CommentManager final {
public:
    static constexpr int schema_version = 1;
    static constexpr const char *table_name = "Comments";

    CommentManager(std::shared_ptr<db::DatabaseHandle> database,
                   PersistentAddressMap &address_map,
                   ProgramOpenMode mode,
                   bool create);

    [[nodiscard]] std::optional<std::string> get(
        const Address &address,
        CommentType type) const;
    [[nodiscard]] std::vector<CommentRecord> all() const;
    void set(const Address &address,
             CommentType type,
             std::optional<std::string> comment);
    [[nodiscard]] std::size_t size() const;
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> schema(int version);
    [[nodiscard]] std::uint64_t address_key(const Address &address,
                                            bool create) const;
    void upgrade_table(int stored_version);
    void validate_bound_table() const;
    void require_mutation() const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    std::shared_ptr<db::Table> table_;
    ProgramOpenMode mode_{};
    int stored_schema_version_{schema_version};
};

} // namespace llmghidra::program
