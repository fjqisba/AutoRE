#include "llmghidra/program/program_architecture.hpp"

#include "llmghidra/program/address_factory.hpp"

#include "translate.hh"
#include "sleighbase.hh"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

[[nodiscard]] std::string folded(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

} // namespace

std::optional<RegisterDescription> ProgramArchitecture::register_named(
    const std::string &name) const {
    if (const auto exact = registers.find(name); exact != registers.end()) {
        return exact->second;
    }
    const auto wanted = folded(name);
    for (const auto &[candidate, description] : registers) {
        if (folded(candidate) == wanted) return description;
    }
    return std::nullopt;
}

ProgramArchitecture ProgramArchitecture::from_sleigh(
    const ghidra::Translate &translate,
    const AddressFactory &address_factory,
    DataOrganization data_organization,
    Endian endian,
    std::optional<std::string> processor_context_register,
    std::span<const ProcessorContextFieldDescription>
        processor_context_fields) {
    ProgramArchitecture result;
    result.data_organization = std::move(data_organization);
    result.endian = endian;
    const auto *sleigh = dynamic_cast<const ghidra::SleighBase *>(&translate);
    if (!processor_context_register && !processor_context_fields.empty()) {
        if (sleigh != nullptr && sleigh->getContextRegister() != nullptr) {
            processor_context_register = sleigh->getContextRegisterName();
        }
    }
    result.processor_context_register = std::move(processor_context_register);
    result.processor_context_fields.assign(
        processor_context_fields.begin(), processor_context_fields.end());
    std::map<ghidra::VarnodeData, std::string> native_registers;
    translate.getAllRegisters(native_registers);
    for (const auto &[storage, name] : native_registers) {
        if (!storage.space || storage.size <= 0 || name.empty()) continue;
        const auto space = address_factory.space(storage.space->getName());
        if (!space) {
            throw std::runtime_error(
                "SLEIGH register space is missing from Program AddressFactory: " +
                storage.space->getName());
        }
        result.registers.insert_or_assign(
            name, RegisterDescription{
                      space->address(static_cast<std::uint64_t>(storage.offset)),
                      static_cast<std::int32_t>(storage.size)});
    }
    if (result.processor_context_register) {
        if (!result.register_named(*result.processor_context_register) &&
            sleigh != nullptr && sleigh->getContextRegister() != nullptr &&
            folded(sleigh->getContextRegisterName()) ==
                folded(*result.processor_context_register)) {
            const auto &storage = *sleigh->getContextRegister();
            const auto space = address_factory.space(storage.space->getName());
            if (!space) {
                throw std::runtime_error(
                    "SLEIGH context register space is missing from Program AddressFactory: " +
                    storage.space->getName());
            }
            result.registers.insert_or_assign(
                *result.processor_context_register,
                RegisterDescription{
                    space->address(static_cast<std::uint64_t>(storage.offset)),
                    static_cast<std::int32_t>(storage.size)});
        }
    }

    // Translate exposes flat register storage.  Recover Ghidra's base-register
    // relationship from containment so current register-context tables always
    // bind to the largest storage and sub-register bytes use significance
    // order rather than host/address order.
    for (auto &[name, description] : result.registers) {
        if (result.processor_context_register &&
            folded(name) == folded(*result.processor_context_register)) {
            description.bit_length =
                static_cast<std::uint32_t>(description.size) * 8U;
            continue;
        }
        const std::pair<const std::string, RegisterDescription> *base = nullptr;
        for (const auto &candidate : result.registers) {
            if (candidate.first == name ||
                candidate.second.size <= description.size ||
                !candidate.second.address.same_space(description.address) ||
                candidate.second.address > description.address) {
                continue;
            }
            const auto byte_delta = description.address.offset() -
                                    candidate.second.address.offset();
            if (byte_delta > static_cast<std::uint64_t>(
                    candidate.second.size - description.size)) {
                continue;
            }
            if (base == nullptr ||
                candidate.second.size > base->second.size ||
                (candidate.second.size == base->second.size &&
                 candidate.first < base->first)) {
                base = &candidate;
            }
        }
        description.bit_length =
            static_cast<std::uint32_t>(description.size) * 8U;
        if (base == nullptr) continue;
        description.base_register = base->first;
        const auto byte_delta = description.address.offset() -
                                base->second.address.offset();
        description.least_significant_bit = result.endian == Endian::little
            ? static_cast<std::uint32_t>(byte_delta * 8U)
            : static_cast<std::uint32_t>(
                  (base->second.size - description.size - byte_delta) * 8U);
    }

    if (result.processor_context_register) {
        const auto wanted = folded(*result.processor_context_register);
        bool found = false;
        for (auto &[name, description] : result.registers) {
            if (folded(name) == wanted) {
                description.processor_context = true;
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(
                "SLEIGH processor-context register is missing from the register map: " +
                *result.processor_context_register);
        }
        const auto context_register = result.register_named(
            *result.processor_context_register);
        const auto context_bits = static_cast<std::uint64_t>(
            context_register->size) * 8U;
        std::set<std::string> context_field_names;
        for (const auto &field : result.processor_context_fields) {
            if (field.name.empty() || field.end_bit < field.start_bit ||
                field.end_bit >= context_bits) {
                throw std::runtime_error(
                    "SLEIGH processor-context field does not fit its base register");
            }
            if (!context_field_names.insert(folded(field.name)).second) {
                throw std::runtime_error(
                    "SLEIGH processor-context field name is duplicated: " +
                    field.name);
            }
        }
    }
    else if (!result.processor_context_fields.empty()) {
        throw std::runtime_error(
            "SLEIGH context fields require a processor-context base register");
    }
    return result;
}

} // namespace llmghidra::program
