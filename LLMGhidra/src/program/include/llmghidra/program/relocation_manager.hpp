#pragma once

#include "llmghidra/program/address_set.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <cstdint>
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

class MemoryManager;

enum class RelocationStatus : std::uint8_t {
    unknown = 0,
    skipped = 1,
    unsupported = 2,
    failure = 3,
    partial = 4,
    applied = 5,
    applied_other = 6,
};

struct Relocation {
    std::int64_t id{};
    Address address;
    RelocationStatus status{RelocationStatus::unknown};
    std::int32_t type{};
    std::optional<std::vector<std::int64_t>> values;
    std::optional<std::vector<std::uint8_t>> original_bytes;
    std::optional<std::string> symbol_name;
    std::uint8_t deferred_byte_length{};
};

// Native Relocations V6 manager used by loaders and analyzers.
class RelocationManager final {
public:
    static constexpr int schema_version = 6;
    static constexpr const char *table_name = "Relocations";
    static constexpr std::uint8_t maximum_deferred_byte_length = 31;

    RelocationManager(std::shared_ptr<db::DatabaseHandle> database,
                      PersistentAddressMap &address_map,
                      MemoryManager &memory,
                      ProgramOpenMode mode,
                      bool create,
                      std::uint32_t default_pointer_size = 4);

    [[nodiscard]] Relocation add(
        const Address &address,
        RelocationStatus status,
        std::int32_t type,
        std::optional<std::vector<std::int64_t>> values,
        std::optional<std::vector<std::uint8_t>> original_bytes,
        std::optional<std::string> symbol_name = std::nullopt);
    [[nodiscard]] Relocation add_with_deferred_bytes(
        const Address &address,
        RelocationStatus status,
        std::int32_t type,
        std::optional<std::vector<std::int64_t>> values,
        std::uint8_t byte_length,
        std::optional<std::string> symbol_name = std::nullopt);
    [[nodiscard]] std::vector<Relocation> at(const Address &address) const;
    [[nodiscard]] std::vector<Relocation> all() const;
    [[nodiscard]] std::vector<Relocation> in(const AddressSet &set) const;
    [[nodiscard]] std::optional<Address> address_after(
        const Address &address) const;
    [[nodiscard]] bool has_relocation(const Address &address) const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] bool relocatable(
        std::optional<bool> program_property = std::nullopt) const;
    // ProgramDB V26 introduced relocation status and deferred byte length.
    // This second-stage migration intentionally runs only after Memory and the
    // compiler data organization are available.
    void refine_pre_v6_statuses(std::uint32_t default_pointer_size);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> current_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_schema(int version);
    [[nodiscard]] Relocation decode(const db::Record &record) const;
    [[nodiscard]] Relocation decode_legacy(const db::Record &record) const;
    [[nodiscard]] Address decode_source_address(
        const db::Record &record, int source_version) const;
    [[nodiscard]] std::unique_ptr<db::Record> translate_source_record(
        const db::Record &record, int source_version,
        db::Table &destination) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    resolve_original_bytes(const Relocation &relocation) const;
    [[nodiscard]] std::vector<std::uint8_t> original_file_bytes(
        const Address &address, std::size_t length) const;
    [[nodiscard]] std::size_t readable_current_bytes(
        const Address &address, std::span<std::uint8_t> destination) const;
    [[nodiscard]] std::uint8_t infer_pre_v6_byte_length(
        const std::vector<std::shared_ptr<db::Record>> &records,
        std::size_t index, std::uint32_t default_pointer_size) const;
    [[nodiscard]] static std::uint8_t encode_flags(
        RelocationStatus status,
        std::uint8_t byte_length);
    void open_or_upgrade_table();
    void stage_current_table(int source_version, bool rekey_current);
    void require_mutation() const;
    void validate_table() const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    MemoryManager *memory_{};
    ProgramOpenMode mode_{};
    std::shared_ptr<db::Table> table_;
    int source_schema_version_{schema_version};
    std::uint8_t default_original_byte_length_{4};
};

} // namespace llmghidra::program
