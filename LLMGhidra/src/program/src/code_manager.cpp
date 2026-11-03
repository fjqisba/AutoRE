#include "llmghidra/program/code_manager.hpp"

#include "llmghidra/program/memory_manager.hpp"
#include "llmghidra/program/reference_manager.hpp"
#include "llmghidra/program/register_context_manager.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {

CodeManager::CodeManager(ListingManager &listing,
                         MemoryManager &memory,
                         CommentManager &comments,
                         ReferenceManager &references,
                         RegisterContextManager &register_context)
    : listing_(&listing), memory_(&memory), comments_(&comments),
      references_(&references), register_context_(&register_context) {
    register_context_->set_context_write_validator(
        [this](const Address &start, const Address &end) {
            check_context_write(start, end);
        });
}

CodeUnit CodeManager::from_instruction(InstructionRecord value) {
    return {CodeUnitKind::instruction, value.address, value.length,
            std::move(value), std::nullopt};
}

CodeUnit CodeManager::from_data(DefinedDataRecord value) {
    return {CodeUnitKind::defined_data, value.address, value.length,
            std::nullopt, std::move(value)};
}

std::vector<CodeUnit> CodeManager::sorted_units() const {
    std::vector<CodeUnit> result;
    for (auto value : listing_->instructions()) {
        result.push_back(from_instruction(std::move(value)));
    }
    for (auto value : listing_->defined_data()) {
        result.push_back(from_data(std::move(value)));
    }
    std::ranges::sort(result, [](const CodeUnit &left, const CodeUnit &right) {
        return left.address < right.address;
    });
    return result;
}

InstructionRecord CodeManager::create_instruction(
    const Address &address,
    std::span<const std::uint8_t> prototype_bytes,
    const Address &prototype_source,
    bool in_delay_slot,
    std::uint8_t flags,
    std::optional<std::string> base_context_value) {
    if (prototype_bytes.empty()) {
        throw std::invalid_argument("instruction prototype bytes are empty");
    }
    const auto memory_bytes = memory_->read(address, prototype_bytes.size());
    if (!std::ranges::equal(memory_bytes, prototype_bytes)) {
        throw std::invalid_argument(
            "instruction prototype bytes do not match program memory");
    }
    const auto prototype = listing_->create_prototype(
        prototype_bytes, prototype_source, in_delay_slot,
        std::move(base_context_value));
    return listing_->create_instruction(address, prototype.id, flags);
}

DefinedDataRecord CodeManager::create_data(const Address &address,
                                           std::int64_t data_type_id) {
    if (!memory_->block_containing(address)) {
        throw std::invalid_argument("defined data requires program memory");
    }
    return listing_->create_data(address, data_type_id);
}

std::optional<CodeUnit> CodeManager::at(const Address &address) const {
    if (auto value = listing_->instruction_at(address)) {
        return from_instruction(std::move(*value));
    }
    if (auto value = listing_->data_at(address)) {
        return from_data(std::move(*value));
    }
    return std::nullopt;
}

std::optional<CodeUnit> CodeManager::containing(
    const Address &address,
    bool use_prototype_length) const {
    for (auto unit : sorted_units()) {
        if (!unit.address.same_space(address) || unit.address > address) continue;
        std::uint64_t length = unit.length;
        if (use_prototype_length && unit.instruction) {
            const auto prototype = listing_->prototype(
                unit.instruction->prototype_id);
            if (prototype) length = prototype->bytes.size();
        }
        if (length == 0 ||
            length - 1 > static_cast<std::uint64_t>(
                             std::numeric_limits<std::int64_t>::max())) {
            throw std::runtime_error("persisted code unit has invalid length");
        }
        if (unit.address.add_no_wrap(static_cast<std::int64_t>(length - 1)) >=
            address) {
            return unit;
        }
    }
    return std::nullopt;
}

std::optional<CodeUnit> CodeManager::before(const Address &address) const {
    std::optional<CodeUnit> result;
    for (auto unit : sorted_units()) {
        if (!unit.address.same_space(address) || unit.address >= address) continue;
        if (!result || result->address < unit.address) result = std::move(unit);
    }
    return result;
}

std::optional<CodeUnit> CodeManager::after(const Address &address) const {
    for (auto unit : sorted_units()) {
        if (unit.address.same_space(address) && unit.address > address) return unit;
    }
    return std::nullopt;
}

std::vector<CodeUnit> CodeManager::code_units(bool forward) const {
    auto result = sorted_units();
    if (!forward) std::ranges::reverse(result);
    return result;
}

std::size_t CodeManager::instruction_count() const {
    return listing_->instructions().size();
}

std::size_t CodeManager::defined_data_count() const {
    return listing_->defined_data().size();
}

std::optional<std::string> CodeManager::comment(
    const Address &address,
    CommentType type) const {
    return comments_->get(address, type);
}

void CodeManager::set_comment(const Address &address,
                              CommentType type,
                              std::optional<std::string> value) {
    comments_->set(address, type, std::move(value));
}

std::optional<Address> CodeManager::fallthrough(
    const Address &instruction) const {
    for (const auto &reference : references_->references_from(instruction)) {
        if (reference.type == ReferenceType::fall_through &&
            reference.operand_index == -1) {
            return reference.to;
        }
    }
    return std::nullopt;
}

void CodeManager::set_fallthrough(
    const Address &instruction,
    std::optional<Address> destination) {
    if (!listing_->instruction_at(instruction)) {
        throw std::invalid_argument(
            "fallthrough source must be an instruction start");
    }
    for (const auto &reference : references_->references_from(instruction)) {
        if (reference.type == ReferenceType::fall_through &&
            reference.operand_index == -1) {
            (void)references_->remove(reference.from, reference.to,
                                      reference.operand_index);
        }
    }
    if (!destination) return;
    Reference reference;
    reference.from = instruction;
    reference.to = *destination;
    reference.type = ReferenceType::fall_through;
    reference.operand_index = -1;
    reference.source = SourceType::user_defined;
    reference.primary = true;
    (void)references_->add(std::move(reference));
}

bool CodeManager::is_initialized_memory(const Address &address) const {
    const auto block = memory_->block_containing(address);
    return block && block->initialized();
}

AddressSet CodeManager::undefined_ranges(
    const AddressSet &within,
    bool initialized_memory_only) const {
    AddressSet result;
    for (const auto &range : within.ranges()) {
        for (const auto &block : memory_->blocks()) {
            if (initialized_memory_only && !block.initialized()) continue;
            const AddressRange block_range(block.start, block.end());
            if (const auto intersection = range.intersection(block_range)) {
                result.add(*intersection);
            }
        }
    }
    for (const auto &unit : sorted_units()) {
        if (unit.length == 0 ||
            unit.length - 1 > static_cast<std::uint64_t>(
                                  std::numeric_limits<std::int64_t>::max())) {
            throw std::runtime_error("persisted code unit has invalid length");
        }
        result.erase(unit.address,
                     unit.address.add_no_wrap(
                         static_cast<std::int64_t>(unit.length - 1)));
    }
    return result;
}

std::optional<CodeUnit> CodeManager::undefined_at(
    const Address &address) const {
    if (!is_initialized_memory(address) || containing(address)) {
        return std::nullopt;
    }
    return CodeUnit{CodeUnitKind::undefined_data, address, 1,
                    std::nullopt, std::nullopt};
}

void CodeManager::clear_code_units(const Address &start,
                                   const Address &end,
                                   bool clear_context) {
    if (!start.same_space(end) || end < start) {
        throw std::invalid_argument("code-unit clear range is invalid");
    }
    std::vector<Address> instruction_starts;
    for (const auto &instruction : listing_->instructions()) {
        const auto instruction_end = instruction.address.add_no_wrap(
            static_cast<std::int64_t>(instruction.length - 1));
        if (instruction.address.same_space(start) &&
            !(instruction_end < start || end < instruction.address)) {
            instruction_starts.push_back(instruction.address);
        }
    }
    for (const auto &address : instruction_starts) {
        (void)references_->remove_all_from(address);
    }
    listing_->delete_address_range(start, end);
    if (clear_context) {
        register_context_->delete_address_range(start, end);
    }
}

void CodeManager::clear_comments(const Address &start, const Address &end) {
    comments_->delete_address_range(start, end);
}

void CodeManager::delete_address_range(const Address &start,
                                       const Address &end) {
    clear_code_units(start, end, true);
    clear_comments(start, end);
}

void CodeManager::move_address_range(const Address &from,
                                     const Address &to,
                                     std::uint64_t length) {
    listing_->move_address_range(from, to, length);
    comments_->move_address_range(from, to, length);
    register_context_->move_address_range(from, to, length);
}

void CodeManager::activate_context_locking() noexcept {
    context_locking_enabled_ = true;
}

void CodeManager::check_context_write(const Address &start,
                                      const Address &end) const {
    if (!context_locking_enabled_) return;
    const auto containing_unit = containing(start, false);
    if (containing_unit &&
        containing_unit->kind == CodeUnitKind::instruction) {
        throw std::logic_error(
            "processor-context change conflicts with an instruction");
    }
    for (const auto &instruction : listing_->instructions()) {
        if (instruction.address.same_space(start) &&
            instruction.address >= start && instruction.address <= end) {
            throw std::logic_error(
                "processor-context change conflicts with an instruction");
        }
    }
}

void CodeManager::memory_changed(const Address &, const Address &) noexcept {
    // Listing rows are persistent and are re-read by the current native
    // manager; there is no Java-style CodeUnit object cache to invalidate.
}

} // namespace llmghidra::program
