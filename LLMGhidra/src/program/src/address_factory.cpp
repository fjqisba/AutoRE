#include "llmghidra/program/address_factory.hpp"

#include "llmghidra/program/language.hpp"

#include "translate.hh"

#include <algorithm>
#include <bit>
#include <cctype>
#include <limits>
#include <stdexcept>

namespace llmghidra::program {
namespace {

[[nodiscard]] std::string folded_name(const std::string &name) {
    std::string result = name;
    std::ranges::transform(result, result.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return result;
}

} // namespace

std::shared_ptr<AddressFactory> AddressFactory::from_sleigh(
    const ghidra::Translate &translate,
    const ProcessorSpec &processor_spec,
    const CompilerSpec &compiler_spec) {
    std::vector<std::shared_ptr<AddressSpace>> spaces;
    spaces.reserve(static_cast<std::size_t>(translate.numSpaces()) + 5U);
    std::shared_ptr<AddressSpace> default_space;

    for (ghidra::int4 index = 0; index < translate.numSpaces(); ++index) {
        const auto *native = translate.getSpace(index);
        if (native == nullptr || native->isOtherSpace()) continue;
        if (native->getIndex() < 0 ||
            native->getIndex() > std::numeric_limits<std::int16_t>::max()) {
            throw std::runtime_error(
                "SLEIGH address-space index does not fit ProgramDB: " +
                native->getName());
        }

        AddressSpaceType type;
        switch (native->getType()) {
        case ghidra::IPTR_CONSTANT:
            type = AddressSpaceType::constant;
            break;
        case ghidra::IPTR_INTERNAL:
            if (native != translate.getUniqueSpace()) continue;
            type = AddressSpaceType::unique;
            break;
        case ghidra::IPTR_PROCESSOR:
            // Ghidra's SleighLanguage maps a decoded <space> with a
            // positive heritage delay to RAM; delay-zero processor spaces
            // are register storage. OTHER is injected separately below.
            type = native->getDelay() > 0
                ? AddressSpaceType::ram : AddressSpaceType::reg;
            break;
        default:
            // Compiler-created stack and decompiler-only fspec/iop/join
            // spaces are not language spaces and are handled explicitly.
            continue;
        }

        std::shared_ptr<AddressSpace> converted;
        if (processor_spec.segmented_address_space &&
            *processor_spec.segmented_address_space == native->getName()) {
            const auto &segment_type =
                processor_spec.segmented_address_type.value_or(std::string{});
            if (type != AddressSpaceType::ram) {
                throw std::runtime_error(
                    "segmented processor address space is not RAM: " +
                    native->getName());
            }
            if (segment_type == "protected") {
                converted = AddressSpace::create_protected_segmented(
                    native->getName(),
                    static_cast<std::uint32_t>(native->getIndex()));
            }
            else if (segment_type.empty() || segment_type == "real") {
                converted = AddressSpace::create_segmented(
                    native->getName(),
                    static_cast<std::uint32_t>(native->getIndex()));
            }
            else {
                throw std::runtime_error(
                    "unsupported segmented-address type: " + segment_type);
            }
        }
        else {
            if (native->getAddrSize() == 0 || native->getAddrSize() > 8) {
                throw std::runtime_error(
                    "SLEIGH address-space size is outside ProgramDB limits: " +
                    native->getName());
            }
            converted = AddressSpace::create(
                {native->getName(), native->getAddrSize() * 8U,
                 native->getWordSize(), type,
                 static_cast<std::uint32_t>(native->getIndex())});
        }
        if (native == translate.getDefaultCodeSpace()) {
            default_space = converted;
        }
        spaces.push_back(std::move(converted));
    }
    if (!default_space) {
        throw std::runtime_error(
            "SLEIGH translation has no ProgramDB-compatible default space");
    }

    // ProgramAddressFactory augments the Language factory with these fixed
    // spaces plus the compiler-specific stack space.
    spaces.push_back(other_space());
    spaces.push_back(external_space());

    const auto stack_base_name = compiler_spec.stack_space.empty()
        ? default_space->name() : compiler_spec.stack_space;
    const auto stack_base = std::ranges::find_if(
        spaces, [&](const auto &candidate) {
            return candidate->name() == stack_base_name;
        });
    if (stack_base == spaces.end()) {
        throw std::runtime_error(
            "compiler stack base space is undefined: " + stack_base_name);
    }
    std::uint32_t stack_bits = default_space->size();
    if (!compiler_spec.stack_pointer_register.empty()) {
        const auto &stack_register =
            translate.getRegister(compiler_spec.stack_pointer_register);
        if (stack_register.size <= 0) {
            throw std::runtime_error(
                "compiler stack pointer has an invalid size: " +
                compiler_spec.stack_pointer_register);
        }
        stack_bits = std::min(
            static_cast<std::uint32_t>(stack_register.size) * 8U,
            (*stack_base)->size());
    }
    else {
        stack_bits = (*stack_base)->size();
    }
    spaces.push_back(AddressSpace::create(
        {"stack", stack_bits, (*stack_base)->addressable_unit_size(),
         AddressSpaceType::stack, 0}));
    spaces.push_back(hash_space());
    spaces.push_back(variable_space());

    return std::make_shared<AddressFactory>(
        std::move(spaces), std::move(default_space));
}

AddressFactory::AddressFactory(std::vector<std::shared_ptr<AddressSpace>> spaces,
                               std::shared_ptr<AddressSpace> default_space) {
    if (spaces.empty()) {
        throw std::invalid_argument("address factory requires at least one address space");
    }
    spaces_.reserve(spaces.size());
    for (auto &candidate : spaces) {
        if (!candidate) {
            throw std::invalid_argument("address factory cannot contain a null space");
        }
        index_space(candidate);
        spaces_.push_back(std::move(candidate));
    }

    if (default_space) {
        const auto found = std::ranges::find_if(spaces_, [&](const auto &candidate) {
            return candidate->equivalent(*default_space);
        });
        if (found == spaces_.end()) {
            throw std::invalid_argument("default address space is not part of the factory");
        }
        default_space_ = *found;
    }
    else {
        default_space_ = spaces_.front();
    }

    if (!register_space_) {
        register_space_ = default_register_space();
    }
    rebuild_memory_set();
    if (has_multiple_memory_spaces()) {
        for (const auto &candidate : spaces_) {
            if (candidate->is_memory_space() && !candidate->is_overlay_space()) {
                candidate->set_show_space_name(true);
            }
        }
    }
}

void AddressFactory::index_space(const std::shared_ptr<AddressSpace> &candidate) {
    if (by_name_.contains(candidate->name())) {
        throw std::invalid_argument("duplicate address-space name: " + candidate->name());
    }
    if (by_id_.contains(candidate->space_id())) {
        throw std::invalid_argument("duplicate address-space id: " +
                                    std::to_string(candidate->space_id()));
    }
    by_name_.emplace(candidate->name(), candidate);
    by_id_.emplace(candidate->space_id(), candidate);

    switch (candidate->type()) {
    case AddressSpaceType::constant:
        if (constant_space_) {
            throw std::invalid_argument("only one constant address space is supported");
        }
        constant_space_ = candidate;
        break;
    case AddressSpaceType::unique:
        if (unique_space_) {
            throw std::invalid_argument("only one unique address space is supported");
        }
        unique_space_ = candidate;
        break;
    case AddressSpaceType::stack:
        if (stack_space_) {
            throw std::invalid_argument("only one stack address space is supported");
        }
        stack_space_ = candidate;
        break;
    case AddressSpaceType::reg:
        if (register_space_ || folded_name(candidate->name()) != "register") {
            throw std::invalid_argument(
                "Ghidra supports one register address space named REGISTER");
        }
        register_space_ = candidate;
        break;
    default:
        break;
    }
}

void AddressFactory::rebuild_memory_set() {
    memory_set_.clear();
    for (const auto &candidate : spaces_) {
        if (candidate->is_memory_space()) {
            memory_set_.add(candidate->min_address(), candidate->max_address());
        }
    }
}

std::optional<Address> AddressFactory::parse_address(const std::string &text) const {
    try {
        if (const auto address = default_space_->parse_address(text)) {
            return address;
        }
    }
    catch (const AddressError &) {
    }
    for (const auto &candidate : spaces_) {
        if (candidate == default_space_) {
            continue;
        }
        try {
            if (const auto address = candidate->parse_address(text)) {
                return address;
            }
        }
        catch (const AddressError &) {
        }
    }
    return std::nullopt;
}

std::vector<Address> AddressFactory::parse_all_addresses(const std::string &text,
                                                         bool case_sensitive) const {
    std::vector<Address> loaded;
    std::vector<Address> non_loaded;
    for (const auto &candidate : spaces_) {
        if (!candidate->is_memory_space()) {
            continue;
        }
        try {
            const auto parsed = candidate->parse_address(text, case_sensitive);
            if (!parsed) {
                continue;
            }
            if (candidate->is_non_loaded_memory_space()) {
                non_loaded.push_back(*parsed);
            }
            else if (candidate == default_space_) {
                loaded.insert(loaded.begin(), *parsed);
            }
            else {
                loaded.push_back(*parsed);
            }
        }
        catch (const AddressError &) {
        }
    }
    if (loaded.empty() && non_loaded.size() == 1) {
        return non_loaded;
    }
    return loaded;
}

const std::shared_ptr<AddressSpace> &AddressFactory::default_space() const noexcept {
    return default_space_;
}
const std::vector<std::shared_ptr<AddressSpace>> &AddressFactory::all_spaces() const noexcept {
    return spaces_;
}

std::vector<std::shared_ptr<AddressSpace>> AddressFactory::physical_spaces() const {
    std::vector<std::shared_ptr<AddressSpace>> result;
    for (const auto &candidate : spaces_) {
        if (candidate->is_memory_space()) {
            result.push_back(candidate);
        }
    }
    return result;
}

std::shared_ptr<AddressSpace> AddressFactory::space(const std::string &name) const noexcept {
    const auto found = by_name_.find(name);
    return found == by_name_.end() ? nullptr : found->second;
}

std::shared_ptr<AddressSpace> AddressFactory::space(std::int32_t id) const noexcept {
    const auto found = by_id_.find(id);
    return found == by_id_.end() ? nullptr : found->second;
}

std::shared_ptr<AddressSpace> AddressFactory::constant_space() const noexcept { return constant_space_; }
std::shared_ptr<AddressSpace> AddressFactory::unique_space() const noexcept { return unique_space_; }
std::shared_ptr<AddressSpace> AddressFactory::stack_space() const noexcept { return stack_space_; }
std::shared_ptr<AddressSpace> AddressFactory::register_space() const noexcept { return register_space_; }

bool AddressFactory::is_valid(const Address &address) const noexcept {
    return address.is_valid() && std::ranges::any_of(spaces_, [&](const auto &candidate) {
        return candidate->equivalent(*address.space());
    });
}

bool AddressFactory::has_multiple_memory_spaces() const noexcept {
    return std::ranges::count_if(spaces_, [](const auto &candidate) {
               return candidate->is_memory_space();
           }) > 1;
}

bool AddressFactory::has_stale_overlay_condition() const noexcept { return stale_overlay_; }

void AddressFactory::refresh_stale_overlay_status() noexcept {
    stale_overlay_ = std::ranges::any_of(spaces_, [](const auto &space) {
        return space->is_overlay_space() &&
               space->ordered_key() != space->name();
    });
}

Address AddressFactory::address(std::int32_t space_id, std::uint64_t offset) const {
    const auto selected = space(space_id);
    if (!selected) {
        throw AddressOutOfBoundsError("unknown address-space id: " + std::to_string(space_id));
    }
    return selected->address(offset);
}

Address AddressFactory::constant_address(std::uint64_t offset) const {
    if (!constant_space_) {
        throw AddressOutOfBoundsError("address factory has no constant space");
    }
    return constant_space_->address(offset);
}

std::uint64_t AddressFactory::old_index(const Address &address) {
    if (address.is_external_entry_address()) {
        return std::bit_cast<std::uint64_t>(std::int64_t{-2});
    }
    if (!is_valid(address)) {
        throw std::invalid_argument("cannot encode an address from an unknown space");
    }
    const std::uint64_t id = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(address.space()->space_id()));
    return (id << 48) + address.offset();
}

Address AddressFactory::decode_old_index(std::uint64_t value) const {
    if (value == std::bit_cast<std::uint64_t>(std::int64_t{-2})) {
        return Address::external_entry_address();
    }
    const std::uint16_t raw_id = static_cast<std::uint16_t>(value >> 48);
    const std::int32_t id = std::bit_cast<std::int16_t>(raw_id);
    const auto selected = space(id);
    if (!selected) {
        throw AddressOutOfBoundsError("old address encoding references an unknown space");
    }
    return selected->address(value & 0xffffffffULL);
}

AddressSet AddressFactory::memory_address_set() const { return memory_set_; }

AddressSet AddressFactory::address_set(const Address &min, const Address &max) const {
    if (!min.is_valid() || !max.is_valid() || min > max) {
        throw std::invalid_argument("invalid factory address-set bounds");
    }
    if (min.same_space(max)) {
        return AddressSet(min, max);
    }
    AddressSet result;
    for (const auto &range : memory_set_.ranges()) {
        if (range.max_address() < min || range.min_address() > max) {
            continue;
        }
        Address first = range.min_address();
        Address last = range.max_address();
        if (first.same_space(min) && min > first) {
            first = min;
        }
        if (last.same_space(max) && max < last) {
            last = max;
        }
        result.add(first, last);
    }
    return result;
}

void AddressFactory::add_space(std::shared_ptr<AddressSpace> candidate) {
    if (!candidate) {
        throw std::invalid_argument("cannot add a null address space");
    }
    index_space(candidate);
    spaces_.push_back(std::move(candidate));
    rebuild_memory_set();
}

void AddressFactory::remove_space(const std::string &name) {
    const auto selected = space(name);
    if (!selected) {
        return;
    }
    if (selected == default_space_) {
        throw std::logic_error("cannot remove the default address space");
    }
    if (selected->is_overlay_space()) {
        stale_overlay_ = true;
    }
    by_name_.erase(name);
    by_id_.erase(selected->space_id());
    std::erase(spaces_, selected);
    if (selected == constant_space_) constant_space_.reset();
    if (selected == unique_space_) unique_space_.reset();
    if (selected == stack_space_) stack_space_.reset();
    if (selected == register_space_) register_space_ = default_register_space();
    rebuild_memory_set();
}

void AddressFactory::rename_overlay(const std::string &old_name, std::string new_name) {
    if (by_name_.contains(new_name)) {
        throw std::invalid_argument("address-space name already exists: " + new_name);
    }
    const auto selected = space(old_name);
    if (!selected || !selected->is_overlay_space()) {
        throw std::invalid_argument("overlay address space not found: " + old_name);
    }
    by_name_.erase(old_name);
    selected->rename_overlay(std::move(new_name));
    by_name_.emplace(selected->name(), selected);
    refresh_stale_overlay_status();
}

} // namespace llmghidra::program
