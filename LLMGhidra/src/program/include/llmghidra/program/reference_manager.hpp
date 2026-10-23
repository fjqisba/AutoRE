#pragma once

#include "llmghidra/program/address.hpp"
#include "llmghidra/program/persistent_address_map.hpp"
#include "llmghidra/program/symbol_manager.hpp"

#include <cstddef>
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

// Stable byte values from ghidra.program.model.symbol.RefType.  Unknown values
// remain round-trippable because Ghidra has historically retained every
// allocated RefType value for database compatibility.
struct ReferenceType final {
    static constexpr std::int8_t invalid = -2;
    static constexpr std::int8_t flow = -1;
    static constexpr std::int8_t fall_through = 0;
    static constexpr std::int8_t unconditional_jump = 1;
    static constexpr std::int8_t conditional_jump = 2;
    static constexpr std::int8_t unconditional_call = 3;
    static constexpr std::int8_t conditional_call = 4;
    static constexpr std::int8_t terminator = 5;
    static constexpr std::int8_t computed_jump = 6;
    static constexpr std::int8_t conditional_terminator = 7;
    static constexpr std::int8_t computed_call = 8;
    static constexpr std::int8_t indirection = 9;
    static constexpr std::int8_t call_terminator = 10;
    static constexpr std::int8_t jump_terminator = 11;
    static constexpr std::int8_t conditional_computed_jump = 12;
    static constexpr std::int8_t conditional_computed_call = 13;
    static constexpr std::int8_t conditional_call_terminator = 14;
    static constexpr std::int8_t computed_call_terminator = 15;
    static constexpr std::int8_t call_override_unconditional = 16;
    static constexpr std::int8_t jump_override_unconditional = 17;
    static constexpr std::int8_t callother_override_call = 18;
    static constexpr std::int8_t callother_override_jump = 19;
    static constexpr std::int8_t data = 100;
    static constexpr std::int8_t read = 101;
    static constexpr std::int8_t write = 102;
    static constexpr std::int8_t read_write = 103;
    static constexpr std::int8_t read_indirect = 104;
    static constexpr std::int8_t write_indirect = 105;
    static constexpr std::int8_t read_write_indirect = 106;
    static constexpr std::int8_t parameter = 107;
    static constexpr std::int8_t legacy_stack_read = 110;
    static constexpr std::int8_t legacy_stack_write = 111;
    static constexpr std::int8_t external = 113;
    static constexpr std::int8_t data_indirect = 114;
    static constexpr std::int8_t thunk = 127;

    [[nodiscard]] static bool is_call(std::int8_t value) noexcept;
    [[nodiscard]] static bool is_flow(std::int8_t value) noexcept;
    [[nodiscard]] static bool is_data(std::int8_t value) noexcept;
    [[nodiscard]] static bool is_indirect(std::int8_t value) noexcept;
    [[nodiscard]] static std::int8_t reference_level(std::int8_t value) noexcept;
};

struct Reference {
    Address from;
    Address to;
    std::int8_t type{ReferenceType::data};
    std::int32_t operand_index{-1};
    std::int64_t symbol_id{-1};
    bool primary{};
    SourceType source{SourceType::default_source};
    bool offset_reference{};
    bool shifted_reference{};
    std::int64_t offset_or_shift{};

    friend bool operator==(const Reference &, const Reference &) = default;
};

// Native storage manager for Ghidra's redundant FROM/TO reference tables.
// Mutations rewrite both directions inside the caller-owned DB transaction;
// stack/register destinations intentionally exist only in FROM REFS, matching
// ProgramDB version 12 and later.
class ReferenceManager final {
public:
    static constexpr const char *from_table_name = "FROM REFS";
    static constexpr const char *to_table_name = "TO REFS";
    static constexpr const char *legacy_shared_table_name = "Memory References";
    static constexpr const char *legacy_stack_table_name = "Stack References";
    static constexpr const char *legacy_external_entries_table_name = "External Entries";
    static constexpr std::size_t big_reference_threshold = 1700;

    ReferenceManager(std::shared_ptr<db::DatabaseHandle> database,
                     PersistentAddressMap &address_map,
                     ProgramOpenMode mode,
                     bool create);

    [[nodiscard]] std::vector<Reference> references_from(
        const Address &address) const;
    [[nodiscard]] std::vector<Reference> references_to(
        const Address &address) const;
    [[nodiscard]] std::optional<Reference> reference(
        const Address &from,
        const Address &to,
        std::int32_t operand_index) const;
    [[nodiscard]] std::vector<Address> from_addresses() const;
    [[nodiscard]] std::vector<Address> to_addresses() const;
    [[nodiscard]] std::size_t size() const;

    [[nodiscard]] Reference add(Reference reference);
    [[nodiscard]] bool remove(const Address &from,
                              const Address &to,
                              std::int32_t operand_index);
    [[nodiscard]] std::size_t remove_all_from(const Address &from);
    [[nodiscard]] std::size_t remove_all_to(const Address &to);
    [[nodiscard]] std::size_t remove_references_from_range(
        const Address &start,
        const Address &end);
    [[nodiscard]] bool set_primary(const Address &from,
                                   const Address &to,
                                   std::int32_t operand_index,
                                   bool primary);
    [[nodiscard]] bool set_symbol_id(const Address &from,
                                     const Address &to,
                                     std::int32_t operand_index,
                                     std::int64_t symbol_id);
    [[nodiscard]] std::size_t remove_symbol_associations(
        std::int64_t symbol_id);
    [[nodiscard]] bool update_type(const Address &from,
                                   const Address &to,
                                   std::int32_t operand_index,
                                   std::int8_t type);
    [[nodiscard]] std::size_t move_references_to(const Address &old_to,
                                                 const Address &new_to);
    [[nodiscard]] std::size_t move_references_from(const Address &old_from,
                                                   const Address &new_from);
    void normalize_address_encodings();
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);

    [[nodiscard]] bool is_external_entry_point(const Address &address) const;
    void add_external_entry_point(const Address &address);
    [[nodiscard]] bool remove_external_entry_point(const Address &address);
    [[nodiscard]] std::int8_t reference_level(const Address &address) const;

    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> from_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> to_schema(int version);
    [[nodiscard]] static std::shared_ptr<db::Schema> big_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> shared_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> stack_schema();

    void bind_existing_tables();
    void validate_current_tables();
    void upgrade_storage();
    void upgrade_legacy_stack_and_entries();
    void load_read_only_legacy_supplements();
    [[nodiscard]] bool contains_legacy_namespace_keys() const;
    [[nodiscard]] std::vector<Reference> all_from_records() const;
    [[nodiscard]] std::vector<Reference> shared_records() const;
    [[nodiscard]] std::vector<Reference> read_parent_list(
        const db::Record &parent,
        bool from_list,
        int parent_version) const;
    [[nodiscard]] std::vector<Reference> decode_inline(
        const Address &owner,
        const std::vector<std::uint8_t> &bytes,
        std::size_t expected_count,
        bool from_list) const;
    [[nodiscard]] std::vector<Reference> decode_big(
        std::uint64_t parent_key,
        const Address &owner,
        std::size_t expected_count,
        bool from_list) const;

    void replace_current_tables(const std::vector<Reference> &references);
    void rewrite_all(const std::vector<Reference> &references);
    void write_grouped(const std::vector<Reference> &references);
    void write_list(const Address &owner,
                    const std::vector<Reference> &references,
                    bool from_list);
    void remove_list_storage(const Address &owner, bool from_list);
    void delete_big_tables_for(const std::shared_ptr<db::Table> &parent,
                               bool from_list);
    [[nodiscard]] std::vector<std::uint8_t> encode_inline_reference(
        const Reference &reference,
        bool from_list) const;
    [[nodiscard]] static std::string big_table_name(std::uint64_t parent_key,
                                                    bool from_list);
    [[nodiscard]] std::uint64_t address_key(const Address &address,
                                            bool create) const;
    [[nodiscard]] static std::uint8_t encode_flags(const Reference &reference);
    [[nodiscard]] static SourceType decode_source(std::uint8_t flags);
    [[nodiscard]] static std::int8_t combine_type(std::int8_t incoming,
                                                  std::int8_t existing) noexcept;
    static void validate_reference(const Reference &reference);
    void require_mutation() const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    std::shared_ptr<db::Table> from_table_;
    std::shared_ptr<db::Table> to_table_;
    std::shared_ptr<db::Table> shared_table_;
    ProgramOpenMode mode_{};
    int to_schema_version_{1};
    bool current_storage_{};
    bool legacy_namespace_keys_{};
    std::vector<Reference> read_only_legacy_supplements_;
};

} // namespace llmghidra::program
