#pragma once

#include "llmghidra/program/binary_address_range_map.hpp"
#include "llmghidra/program/address_set.hpp"
#include "llmghidra/program/program_architecture.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
}

namespace llmghidra::program {

class LanguageTranslator;

struct RegisterValue {
    std::string register_name;
    // Big-endian bytes in register significance order. Mask and value have the
    // register's exact byte size; value bits outside mask are normalized away.
    std::vector<std::uint8_t> mask;
    std::vector<std::uint8_t> value;

    [[nodiscard]] bool has_any_value() const noexcept;
    [[nodiscard]] bool fully_defined() const noexcept;
};

struct RegisterValueRange {
    AddressRange range;
    RegisterValue value;
};

// Native current-schema counterpart of ProgramRegisterContextDB and
// DatabaseRangeMapAdapter. Each base register is persisted in the original
// "Range Map - Register_<name>" BinaryField table.
class RegisterContextManager final {
public:
    static constexpr const char *table_prefix = "Range Map - Register_";

    RegisterContextManager(
        std::shared_ptr<db::DatabaseHandle> database,
        PersistentAddressMap &address_map,
        ProgramOpenMode mode,
        std::shared_ptr<const ProgramArchitecture> architecture = {});

    [[nodiscard]] static bool old_context_present(
        const std::shared_ptr<db::DatabaseHandle> &database);

    [[nodiscard]] std::optional<RegisterValue> value_at(
        const std::string &register_name,
        const Address &address,
        bool include_default = true) const;
    [[nodiscard]] std::optional<AddressRange> value_range_containing(
        const std::string &register_name,
        const Address &address) const;
    [[nodiscard]] std::vector<RegisterValueRange> ranges(
        const std::string &register_name) const;
    [[nodiscard]] std::vector<RegisterValueRange> default_ranges(
        const std::string &register_name) const;
    [[nodiscard]] std::vector<std::string> registers_with_values() const;

    void set_value(const Address &start,
                   const Address &end,
                   RegisterValue value);
    void remove_value(const Address &start,
                      const Address &end,
                      const std::string &register_name);
    void set_default_value(const Address &start,
                           const Address &end,
                           RegisterValue value);
    // Apply pspec defaults first and cspec defaults second, matching
    // ProgramRegisterContextDB precedence. Tracked settings are consumed by
    // the decompiler ContextDatabase provider, not persisted register context.
    void initialize_default_values(const ProcessorSpec &processor_spec,
                                   const CompilerSpec &compiler_spec);
    void set_language(
        std::shared_ptr<const ProgramArchitecture> new_architecture,
        std::shared_ptr<AddressFactory> new_address_factory,
        const LanguageTranslator *translator,
        const ProcessorSpec &new_processor_spec,
        const CompilerSpec &new_compiler_spec,
        const AddressSet &program_memory);
    void rebind_language(
        std::shared_ptr<const ProgramArchitecture> architecture,
        const ProcessorSpec &processor_spec,
        const CompilerSpec &compiler_spec);
    void clear_default_values(const std::string &register_name);
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);
    void clear_register(const std::string &register_name);

    void set_context_write_validator(
        std::function<void(const Address &, const Address &)> validator);
    void invalidate_cache();

private:
    struct RegisterBinding {
        std::string requested_name;
        std::string base_name;
        RegisterDescription requested;
        RegisterDescription base;
        std::size_t base_byte_offset{};
    };

    [[nodiscard]] RegisterBinding binding(
        const std::string &register_name) const;
    [[nodiscard]] BinaryAddressRangeMap &map_for(
        const std::string &base_name) const;
    [[nodiscard]] std::vector<std::uint8_t> empty_base_value(
        const RegisterBinding &binding) const;
    [[nodiscard]] std::vector<std::uint8_t> encode_for_base(
        const RegisterBinding &binding,
        const RegisterValue &value) const;
    [[nodiscard]] RegisterValue decode_from_base(
        const RegisterBinding &binding,
        const std::vector<std::uint8_t> &bytes) const;
    static void combine(std::vector<std::uint8_t> &destination,
                        const std::vector<std::uint8_t> &overlay);
    static void clear_bits(std::vector<std::uint8_t> &destination,
                           const std::vector<std::uint8_t> &mask);
    static bool has_mask(const std::vector<std::uint8_t> &bytes) noexcept;
    void validate_write(const RegisterBinding &binding,
                        const Address &start,
                        const Address &end) const;
    void apply_overlay(BinaryAddressRangeMap &map,
                       const Address &start,
                       const Address &end,
                       const std::vector<std::uint8_t> &overlay);
    void reload_current_maps();

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    ProgramOpenMode mode_{};
    std::shared_ptr<const ProgramArchitecture> architecture_;
    // Owns the address encoding used only by a scratch-backed read-only view
    // of pre-ProgramRegisterContextDB tables.
    std::unique_ptr<PersistentAddressMap> legacy_view_address_map_;
    mutable std::unordered_map<
        std::string, std::unique_ptr<BinaryAddressRangeMap>> maps_;
    std::unordered_map<std::string, std::vector<BinaryAddressRangeValue>>
        defaults_;
    std::function<void(const Address &, const Address &)> write_validator_;
};

} // namespace llmghidra::program
