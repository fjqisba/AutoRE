#include "llmghidra/headless/program_load_image.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/function_manager.hpp"
#include "llmghidra/program/memory_manager.hpp"
#include "llmghidra/program/program.hpp"

#include "translate.hh"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::headless {
namespace {

[[nodiscard]] std::string load_image_name(const program::Program &program) {
    if (const auto path = program.executable_path(); path && !path->empty()) {
        return *path;
    }
    return program.name();
}

} // namespace

ProgramLoadImage::ProgramLoadImage(const program::Program &program)
    : ghidra::LoadImage(load_image_name(program)), program_(&program) {}

void ProgramLoadImage::attach_address_spaces(
    const ghidra::AddrSpaceManager &spaces) noexcept {
    spaces_ = &spaces;
}

void ProgramLoadImage::require_attached() const {
    if (spaces_ == nullptr) {
        throw ghidra::LowlevelError(
            "ProgramDB load image is not attached to decompiler address spaces");
    }
}

program::Address ProgramLoadImage::to_program_address(
    const ghidra::Address &address) const {
    if (address.isInvalid() || address.getSpace() == nullptr) {
        throw ghidra::DataUnavailError(
            "cannot read ProgramDB memory at an invalid address");
    }
    const auto space = program_->address_factory()->space(
        address.getSpace()->getName());
    if (!space || address.getOffset() > space->max_offset()) {
        throw ghidra::DataUnavailError(
            "decompiler address space is unavailable in ProgramDB: " +
            address.getSpace()->getName());
    }
    return space->address(
        static_cast<std::uint64_t>(address.getOffset()));
}

ghidra::Address ProgramLoadImage::to_decompiler_address(
    const program::Address &address) const {
    require_attached();
    if (!address.is_valid()) {
        throw ghidra::LowlevelError(
            "ProgramDB load image contains an invalid address");
    }
    auto *space = spaces_->getSpaceByName(address.space()->name());
    if (space == nullptr || address.offset() > space->getHighest()) {
        throw ghidra::LowlevelError(
            "ProgramDB address space is unavailable in the decompiler: " +
            address.space()->name());
    }
    return ghidra::Address(space, address.offset());
}

void ProgramLoadImage::loadFill(
    ghidra::uint1 *destination,
    ghidra::int4 size,
    const ghidra::Address &address) {
    require_attached();
    if (size < 0 || (size != 0 && destination == nullptr)) {
        throw ghidra::DataUnavailError(
            "invalid ProgramDB load-image read request");
    }
    if (size == 0) return;
    try {
        const auto bytes = program_->memory().read(
            to_program_address(address), static_cast<std::size_t>(size));
        std::copy(bytes.begin(), bytes.end(), destination);
    }
    catch (const program::MemoryAccessError &error) {
        throw ghidra::DataUnavailError(error.what());
    }
    catch (const std::out_of_range &error) {
        throw ghidra::DataUnavailError(error.what());
    }
    catch (const std::overflow_error &error) {
        throw ghidra::DataUnavailError(error.what());
    }
}

void ProgramLoadImage::openSymbols() const {
    require_attached();
    symbols_.clear();
    symbol_index_ = 0;
    for (const auto &function : program_->functions().all()) {
        const auto &entry = function.symbol.address;
        if (!entry.is_valid() ||
            !program_->memory().block_containing(entry)) {
            continue;
        }
        symbols_.push_back(
            {to_decompiler_address(entry), function.symbol.name});
    }
    std::ranges::sort(symbols_, [](const auto &left, const auto &right) {
        if (left.address != right.address) {
            return left.address < right.address;
        }
        return left.name < right.name;
    });
}

void ProgramLoadImage::closeSymbols() const {
    symbols_.clear();
    symbol_index_ = 0;
}

bool ProgramLoadImage::getNextSymbol(
    ghidra::LoadImageFunc &record) const {
    if (symbol_index_ >= symbols_.size()) return false;
    record = symbols_[symbol_index_++];
    return true;
}

void ProgramLoadImage::openSectionInfo() const {
    require_attached();
    sections_.clear();
    section_index_ = 0;
    for (const auto &block : program_->memory().blocks()) {
        ghidra::uint4 flags = 0;
        // Mapped blocks report !isInitialized() in Ghidra, but their bytes
        // remain loadable through the mapped source.  Only a genuinely
        // uninitialized, non-mapped block is a no-load section.
        if (!block.initialized() && !block.mapped()) {
            flags |= ghidra::LoadImageSection::noload;
        }
        if ((block.flags & program::MemoryBlock::execute) != 0) {
            flags |= ghidra::LoadImageSection::code;
        }
        else {
            flags |= ghidra::LoadImageSection::data;
        }
        if ((block.flags & program::MemoryBlock::write) == 0) {
            flags |= ghidra::LoadImageSection::readonly;
        }
        sections_.push_back(
            {to_decompiler_address(block.start), block.length, flags});
    }
    std::ranges::sort(sections_, [](const auto &left, const auto &right) {
        return left.address < right.address;
    });
}

void ProgramLoadImage::closeSectionInfo() const {
    sections_.clear();
    section_index_ = 0;
}

bool ProgramLoadImage::getNextSection(
    ghidra::LoadImageSection &section) const {
    if (section_index_ >= sections_.size()) return false;
    section = sections_[section_index_++];
    return true;
}

void ProgramLoadImage::getReadonly(ghidra::RangeList &ranges) const {
    require_attached();
    for (const auto &block : program_->memory().blocks()) {
        if ((block.flags & program::MemoryBlock::write) != 0) continue;
        const auto start = to_decompiler_address(block.start);
        if (block.length == 0 ||
            block.length - 1 > start.getSpace()->getHighest() -
                                   start.getOffset()) {
            throw ghidra::LowlevelError(
                "ProgramDB memory block exceeds its decompiler address space");
        }
        ranges.insertRange(
            start.getSpace(), start.getOffset(),
            start.getOffset() + block.length - 1);
    }
}

std::string ProgramLoadImage::getArchType() const {
    return program_->language_id() + ":" + program_->compiler_spec_id();
}

void ProgramLoadImage::adjustVma(long adjustment) {
    if (adjustment != 0) {
        throw ghidra::LowlevelError(
            "ProgramDB load addresses must be moved through MemoryManager");
    }
}

} // namespace llmghidra::headless
