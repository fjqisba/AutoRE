#pragma once

#include "llmghidra/program/language.hpp"
#include "llmghidra/program/program_architecture.hpp"

#include "globalcontext.hh"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace ghidra {
class AddrSpace;
class Translate;
}

namespace llmghidra::program {

class AddressFactory;
class RegisterContextManager;
struct RegisterValue;

// Native ContextDatabase binding used by SLEIGH and the decompiler for an
// opened ProgramDB.  Low-level context reads come from RegisterContextManager;
// writes made through the standard ContextDatabase helpers are mirrored back
// into the current Ghidra register-context tables.  The inherited
// ContextInternal partition is retained only for SLEIGH's mutation protocol
// and XML compatibility, never as the authoritative Program state.
class ProgramContextDatabase final : public ghidra::ContextInternal {
public:
    ProgramContextDatabase(RegisterContextManager &register_context,
                           const AddressFactory &address_factory,
                           const ProgramArchitecture &architecture,
                           const ghidra::Translate &translate);

    void registerVariable(const std::string &name,
                          ghidra::int4 start_bit,
                          ghidra::int4 end_bit) override;
    [[nodiscard]] const ghidra::uintm *getContext(
        const ghidra::Address &address) const override;
    [[nodiscard]] const ghidra::uintm *getContext(
        const ghidra::Address &address,
        ghidra::uintb &first,
        ghidra::uintb &last) const override;

    [[nodiscard]] ghidra::TrackedSet &getTrackedDefault() override;
    [[nodiscard]] const ghidra::TrackedSet &getTrackedSet(
        const ghidra::Address &address) const override;
    [[nodiscard]] ghidra::TrackedSet &createSet(
        const ghidra::Address &first,
        const ghidra::Address &end_open) override;
    void encode(ghidra::Encoder &encoder) const override;
    void decode(ghidra::Decoder &decoder) override;
    void decodeFromSpec(ghidra::Decoder &decoder) override;

    void initialize_tracked_values(const ProcessorSpec &processor_spec,
                                   const CompilerSpec &compiler_spec);
    void validate_registered_metadata() const;
    [[nodiscard]] const std::vector<ProcessorContextFieldDescription> &
    registered_fields() const noexcept;

protected:
    [[nodiscard]] ghidra::uintm *getDefaultValue() override;
    [[nodiscard]] const ghidra::uintm *getDefaultValue() const override;
    void contextChangePointChanged(const ghidra::Address &address,
                                   ghidra::int4 word,
                                   ghidra::uintm mask,
                                   ghidra::uintm value) override;
    void contextRegionChanged(const ghidra::Address &first,
                              const ghidra::Address &end_open,
                              ghidra::int4 word,
                              ghidra::uintm mask,
                              ghidra::uintm value) override;

private:
    struct TrackedSpaceState {
        std::map<ghidra::uintb, ghidra::TrackedSet> partitions;
    };

    [[nodiscard]] Address to_program_address(
        const ghidra::Address &address) const;
    [[nodiscard]] ghidra::Address to_sleigh_address(
        const Address &address) const;
    [[nodiscard]] RegisterValue context_word_value(
        ghidra::int4 word,
        ghidra::uintm mask,
        ghidra::uintm value) const;
    [[nodiscard]] Address change_point_end(
        const Address &start,
        ghidra::int4 word,
        ghidra::uintm mask) const;
    void overlay_context_value(const RegisterValue &value) const;
    void overlay_tracked_setting(
        const std::unordered_map<std::string, std::string> &setting);
    [[nodiscard]] ghidra::TrackedSet tracked_value_at(
        const TrackedSpaceState &state,
        ghidra::uintb offset) const;
    [[nodiscard]] static bool same_storage(
        const ghidra::VarnodeData &left,
        const ghidra::VarnodeData &right) noexcept;

    RegisterContextManager *register_context_{};
    const AddressFactory *address_factory_{};
    const ProgramArchitecture *architecture_{};
    const ghidra::Translate *translate_{};
    std::string context_register_;
    std::size_t context_register_size_{};
    std::vector<ProcessorContextFieldDescription> registered_fields_;
    std::vector<ghidra::uintm> default_context_;
    mutable std::vector<ghidra::uintm> query_context_;
    ghidra::TrackedSet tracked_default_;
    std::unordered_map<ghidra::AddrSpace *, TrackedSpaceState>
        tracked_spaces_;
};

} // namespace llmghidra::program
