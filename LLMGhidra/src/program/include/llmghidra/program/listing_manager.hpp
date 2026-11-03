#pragma once

#include "llmghidra/program/address.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Record;
class Schema;
class Table;
}

namespace llmghidra::program {

struct InstructionPrototypeRecord {
    std::int32_t id{};
    std::vector<std::uint8_t> bytes;
    Address source_address;
    bool in_delay_slot{};
    std::optional<std::string> base_context_value;
};

struct InstructionRecord {
    Address address;
    std::int32_t prototype_id{};
    std::uint8_t flags{};
    std::uint32_t length{};
};

struct DefinedDataRecord {
    Address address;
    std::int64_t data_type_id{};
    std::uint64_t length{1};
};

// Native storage core of CodeManager: Data V0, Instructions V0/V1,
// Prototypes V0/V1 and ContextTable V0/V1. Semantic decoding remains bound
// to the native SLEIGH and DataType providers supplied by Program.
class ListingManager final {
public:
    using DataTypeLengthResolver =
        std::function<std::int64_t(std::int64_t, const Address &)>;
    using AvailableLengthResolver =
        std::function<std::uint64_t(const Address &)>;

    ListingManager(std::shared_ptr<db::DatabaseHandle> database,
                   PersistentAddressMap &address_map,
                   ProgramOpenMode mode,
                   bool create);

    void set_data_type_length_resolver(DataTypeLengthResolver resolver);
    void set_available_length_resolver(AvailableLengthResolver resolver);

    [[nodiscard]] InstructionPrototypeRecord create_prototype(
        std::span<const std::uint8_t> bytes, const Address &source_address,
        bool in_delay_slot,
        std::optional<std::string> base_context_value = std::nullopt);
    [[nodiscard]] std::optional<InstructionPrototypeRecord> prototype(
        std::int32_t id) const;
    [[nodiscard]] std::vector<InstructionPrototypeRecord> prototypes() const;
    void clear_prototypes();

    [[nodiscard]] InstructionRecord create_instruction(
        const Address &address, std::int32_t prototype_id,
        std::uint8_t flags = 0);
    [[nodiscard]] DefinedDataRecord create_data(
        const Address &address, std::int64_t data_type_id);
    [[nodiscard]] std::optional<InstructionRecord> instruction_at(
        const Address &address) const;
    [[nodiscard]] std::optional<DefinedDataRecord> data_at(
        const Address &address) const;
    [[nodiscard]] std::vector<InstructionRecord> instructions() const;
    [[nodiscard]] std::vector<DefinedDataRecord> defined_data() const;
    void set_instruction_flags(const Address &address, std::uint8_t flags);
    [[nodiscard]] bool remove_instruction(const Address &address);
    [[nodiscard]] bool remove_data(const Address &address);
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from, const Address &to,
                            std::uint64_t length);
    [[nodiscard]] std::size_t replace_data_type(
        std::int64_t replaced_id, std::int64_t replacement_id);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> data_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> instruction_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_instruction_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> prototype_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_prototype_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> context_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_context_schema();
    void create_tables();
    void open_tables();
    void open_code_unit_tables();
    void open_prototype_tables();
    void validate_tables() const;
    void require_mutation() const;
    [[nodiscard]] Address decode_address_key(std::int64_t key) const;
    [[nodiscard]] std::uint64_t data_length(
        std::int64_t data_type_id, const Address &address) const;
    [[nodiscard]] InstructionRecord decode_instruction(
        const db::Record &record) const;
    [[nodiscard]] DefinedDataRecord decode_data(const db::Record &record) const;
    [[nodiscard]] InstructionPrototypeRecord decode_prototype(
        const db::Record &record) const;
    void require_unoccupied(const Address &start, std::uint64_t length,
                            std::optional<Address> ignored_start = std::nullopt) const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    ProgramOpenMode mode_{};
    std::shared_ptr<db::Table> data_table_;
    std::shared_ptr<db::Table> instruction_table_;
    std::shared_ptr<db::Table> prototype_table_;
    std::shared_ptr<db::Table> context_table_;
    DataTypeLengthResolver data_type_length_resolver_;
    AvailableLengthResolver available_length_resolver_;
};

} // namespace llmghidra::program
