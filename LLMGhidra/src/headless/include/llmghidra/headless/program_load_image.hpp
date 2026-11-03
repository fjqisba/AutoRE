#pragma once

#include "loadimage.hh"

#include <cstddef>
#include <vector>

namespace llmghidra::program {
class Address;
class Program;
}

namespace llmghidra::headless {

// Native LoadImage backed directly by an opened ProgramDB.  This is the byte,
// section, and imported-function provider used by the in-process SLEIGH and
// decompiler runtime; it deliberately has no Java callback/protocol fallback.
class ProgramLoadImage final : public ghidra::LoadImage {
public:
    explicit ProgramLoadImage(const program::Program &program);

    // Architecture address spaces do not exist when SleighArchitecture calls
    // buildLoader().  The owning runtime attaches its fully initialized
    // AddrSpaceManager from postSpecFile() before section/symbol iteration or
    // byte reads begin.
    void attach_address_spaces(const ghidra::AddrSpaceManager &spaces) noexcept;

    void loadFill(ghidra::uint1 *destination,
                  ghidra::int4 size,
                  const ghidra::Address &address) override;
    void openSymbols() const override;
    void closeSymbols() const override;
    [[nodiscard]] bool getNextSymbol(
        ghidra::LoadImageFunc &record) const override;
    void openSectionInfo() const override;
    void closeSectionInfo() const override;
    [[nodiscard]] bool getNextSection(
        ghidra::LoadImageSection &section) const override;
    void getReadonly(ghidra::RangeList &ranges) const override;
    [[nodiscard]] std::string getArchType() const override;
    void adjustVma(long adjustment) override;

private:
    [[nodiscard]] program::Address to_program_address(
        const ghidra::Address &address) const;
    [[nodiscard]] ghidra::Address to_decompiler_address(
        const program::Address &address) const;
    void require_attached() const;

    const program::Program *program_{};
    const ghidra::AddrSpaceManager *spaces_{};
    mutable std::vector<ghidra::LoadImageFunc> symbols_;
    mutable std::size_t symbol_index_{};
    mutable std::vector<ghidra::LoadImageSection> sections_;
    mutable std::size_t section_index_{};
};

} // namespace llmghidra::headless
