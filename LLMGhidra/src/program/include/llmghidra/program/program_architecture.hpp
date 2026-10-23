#pragma once

#include "llmghidra/program/address.hpp"
#include "llmghidra/program/language.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace ghidra {
class Translate;
}

namespace llmghidra::program {

class AddressFactory;

struct RegisterDescription {
    Address address;
    std::int32_t size{};
    // Bit metadata is required by legacy Program Context tables and SLEIGH
    // context fields. least_significant_bit is relative to the base register's
    // least-significant bit, matching Register::getLeastSignificantBit(). A
    // zero bit_length denotes the full byte storage.
    std::uint32_t least_significant_bit{};
    std::uint32_t bit_length{};
    std::optional<std::string> base_register;
    bool processor_context{};
};

struct ProcessorContextFieldDescription {
    std::string name;
    // SLEIGH absolute context-bit numbering: bit 0 is the most-significant
    // bit of the context blob and both endpoints are inclusive.
    std::uint32_t start_bit{};
    std::uint32_t end_bit{};

    friend bool operator==(
        const ProcessorContextFieldDescription &,
        const ProcessorContextFieldDescription &) = default;
};

// Language-dependent facts needed while opening and upgrading ProgramDB.
// The headless SLEIGH binding populates this from Translate::getAllRegisters()
// and the selected compiler specification; database code never guesses a host
// ABI or hard-codes a processor's register layout.
struct ProgramArchitecture {
    DataOrganization data_organization;
    Endian endian{Endian::little};
    std::unordered_map<std::string, RegisterDescription> registers;
    std::optional<std::string> processor_context_register;
    std::vector<ProcessorContextFieldDescription> processor_context_fields;

    [[nodiscard]] std::optional<RegisterDescription> register_named(
        const std::string &name) const;
    [[nodiscard]] static ProgramArchitecture from_sleigh(
        const ghidra::Translate &translate,
        const AddressFactory &address_factory,
        DataOrganization data_organization,
        Endian endian,
        std::optional<std::string> processor_context_register = std::nullopt,
        std::span<const ProcessorContextFieldDescription>
            processor_context_fields = {});
};

} // namespace llmghidra::program
