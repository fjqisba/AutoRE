#include "llmghidra/program/program_context_database.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/register_context_manager.hpp"

#include "translate.hh"

#include <algorithm>
#include <charconv>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <tuple>

namespace llmghidra::program {
namespace {

[[nodiscard]] std::uint64_t parse_integer(
    std::string_view text, const char *attribute) {
    bool negative = false;
    if (!text.empty() && text.front() == '-') {
        negative = true;
        text.remove_prefix(1);
    }
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        base = 16;
        text.remove_prefix(2);
    }
    std::uint64_t magnitude{};
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), magnitude, base);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size()) {
        throw std::runtime_error(
            std::string("invalid tracked context setting ") + attribute);
    }
    return negative ? std::uint64_t{0} - magnitude : magnitude;
}

[[nodiscard]] const std::string &required_attribute(
    const std::unordered_map<std::string, std::string> &setting,
    const char *name) {
    const auto found = setting.find(name);
    if (found == setting.end() || found->second.empty()) {
        throw std::runtime_error(
            std::string("tracked context setting is missing ") + name);
    }
    return found->second;
}

[[nodiscard]] bool masks_intersect(
    const RegisterValue &value,
    const RegisterValue &target) noexcept {
    const auto count = std::min(value.mask.size(), target.mask.size());
    for (std::size_t index = 0; index < count; ++index) {
        if ((value.mask[index] & target.mask[index]) != 0) return true;
    }
    return false;
}

} // namespace

ProgramContextDatabase::ProgramContextDatabase(
    RegisterContextManager &register_context,
    const AddressFactory &address_factory,
    const ProgramArchitecture &architecture,
    const ghidra::Translate &translate)
    : register_context_(&register_context),
      address_factory_(&address_factory),
      architecture_(&architecture),
      translate_(&translate) {
    if (!architecture.processor_context_register) return;
    context_register_ = *architecture.processor_context_register;
    const auto description = architecture.register_named(context_register_);
    if (!description || description->size <= 0) {
        throw std::invalid_argument(
            "ProgramContextDatabase processor-context register is unavailable");
    }
    context_register_size_ = static_cast<std::size_t>(description->size);
}

void ProgramContextDatabase::registerVariable(
    const std::string &name,
    ghidra::int4 start_bit,
    ghidra::int4 end_bit) {
    if (name.empty() || start_bit < 0 || end_bit < start_bit) {
        throw std::invalid_argument(
            "SLEIGH registered an invalid processor-context field");
    }
    if (context_register_.empty()) {
        throw std::runtime_error(
            "SLEIGH context fields require a ProgramDB context register");
    }
    ghidra::ContextInternal::registerVariable(name, start_bit, end_bit);
    default_context_.resize(
        static_cast<std::size_t>(getContextSize()), ghidra::uintm{0});
    query_context_.resize(default_context_.size(), ghidra::uintm{0});

    const ProcessorContextFieldDescription description{
        name,
        static_cast<std::uint32_t>(start_bit),
        static_cast<std::uint32_t>(end_bit)};
    const auto existing = std::ranges::find_if(
        registered_fields_, [&](const auto &candidate) {
            return candidate.name == description.name;
        });
    if (existing == registered_fields_.end()) {
        registered_fields_.push_back(description);
    }
    else if (existing->start_bit != description.start_bit ||
             existing->end_bit != description.end_bit) {
        throw std::runtime_error(
            "SLEIGH re-registered a context field with a different bit range");
    }
}

Address ProgramContextDatabase::to_program_address(
    const ghidra::Address &address) const {
    if (address.isInvalid() || address.getSpace() == nullptr) {
        throw std::invalid_argument(
            "cannot translate an invalid SLEIGH address to ProgramDB");
    }
    const auto space = address_factory_->space(address.getSpace()->getName());
    if (!space) {
        throw std::runtime_error(
            "SLEIGH address space is missing from ProgramDB: " +
            address.getSpace()->getName());
    }
    return space->address(static_cast<std::uint64_t>(address.getOffset()));
}

ghidra::Address ProgramContextDatabase::to_sleigh_address(
    const Address &address) const {
    if (!address.is_valid()) return {};
    auto *space = translate_->getSpaceByName(address.space()->name());
    if (space == nullptr) {
        throw std::runtime_error(
            "ProgramDB address space is missing from SLEIGH: " +
            address.space()->name());
    }
    return ghidra::Address(space, address.offset());
}

ghidra::uintm *ProgramContextDatabase::getDefaultValue() {
    return default_context_.data();
}

const ghidra::uintm *ProgramContextDatabase::getDefaultValue() const {
    return default_context_.data();
}

void ProgramContextDatabase::overlay_context_value(
    const RegisterValue &value) const {
    const auto byte_count = std::min(
        context_register_size_, value.mask.size());
    for (std::size_t byte = 0; byte < byte_count; ++byte) {
        const auto word = byte / sizeof(ghidra::uintm);
        if (word >= query_context_.size()) break;
        const auto byte_in_word = byte % sizeof(ghidra::uintm);
        const auto shift = static_cast<unsigned>(
            (sizeof(ghidra::uintm) - byte_in_word - 1U) * 8U);
        const auto mask = static_cast<ghidra::uintm>(value.mask[byte]) << shift;
        const auto bits = static_cast<ghidra::uintm>(value.value[byte]) << shift;
        query_context_[word] =
            (query_context_[word] & ~mask) | (bits & mask);
    }
}

const ghidra::uintm *ProgramContextDatabase::getContext(
    const ghidra::Address &address) const {
    query_context_ = default_context_;
    const auto program_address = to_program_address(address);
    if (!context_register_.empty()) {
        if (const auto value = register_context_->value_at(
            context_register_, program_address, true)) {
            overlay_context_value(*value);
        }
    }
    return query_context_.data();
}

const ghidra::uintm *ProgramContextDatabase::getContext(
    const ghidra::Address &address,
    ghidra::uintb &first,
    ghidra::uintb &last) const {
    // Exact-address bounds deliberately prevent ContextCache from hiding a
    // ProgramDB transaction's newly committed register-context value.
    first = address.getOffset();
    last = address.getOffset();
    return getContext(address);
}

RegisterValue ProgramContextDatabase::context_word_value(
    ghidra::int4 word,
    ghidra::uintm mask,
    ghidra::uintm value) const {
    if (word < 0 || static_cast<std::size_t>(word) >= default_context_.size()) {
        throw std::out_of_range("SLEIGH context word is outside the context blob");
    }
    RegisterValue result;
    result.register_name = context_register_;
    result.mask.assign(context_register_size_, 0);
    result.value.assign(context_register_size_, 0);
    const auto first_byte =
        static_cast<std::size_t>(word) * sizeof(ghidra::uintm);
    for (std::size_t index = 0; index < sizeof(ghidra::uintm); ++index) {
        const auto destination = first_byte + index;
        if (destination >= context_register_size_) break;
        const auto shift = static_cast<unsigned>(
            (sizeof(ghidra::uintm) - index - 1U) * 8U);
        result.mask[destination] = static_cast<std::uint8_t>(mask >> shift);
        result.value[destination] = static_cast<std::uint8_t>(
            (value & mask) >> shift);
    }
    return result;
}

Address ProgramContextDatabase::change_point_end(
    const Address &start,
    ghidra::int4 word,
    ghidra::uintm mask) const {
    const auto target = context_word_value(word, mask, 0);
    Address result = start.space()->max_address();
    const auto consider = [&](const std::vector<RegisterValueRange> &ranges) {
        for (const auto &entry : ranges) {
            if (!entry.range.min_address().same_space(start) ||
                entry.range.max_address() < start ||
                !masks_intersect(entry.value, target)) {
                continue;
            }
            Address candidate = result;
            if (entry.range.contains(start)) {
                candidate = entry.range.max_address();
            }
            else if (entry.range.min_address() > start) {
                candidate = *entry.range.min_address().previous();
            }
            if (candidate < result) result = candidate;
        }
    };
    consider(register_context_->default_ranges(context_register_));
    consider(register_context_->ranges(context_register_));
    return result;
}

void ProgramContextDatabase::contextChangePointChanged(
    const ghidra::Address &address,
    ghidra::int4 word,
    ghidra::uintm mask,
    ghidra::uintm value) {
    const auto start = to_program_address(address);
    register_context_->set_value(
        start, change_point_end(start, word, mask),
        context_word_value(word, mask, value));
}

void ProgramContextDatabase::contextRegionChanged(
    const ghidra::Address &first,
    const ghidra::Address &end_open,
    ghidra::int4 word,
    ghidra::uintm mask,
    ghidra::uintm value) {
    const auto start = to_program_address(first);
    Address end = start.space()->max_address();
    if (!end_open.isInvalid() && end_open.getSpace() == first.getSpace()) {
        if (end_open.getOffset() <= first.getOffset()) return;
        end = start.space()->address(
            static_cast<std::uint64_t>(end_open.getOffset() - 1U));
    }
    register_context_->set_value(
        start, end, context_word_value(word, mask, value));
}

bool ProgramContextDatabase::same_storage(
    const ghidra::VarnodeData &left,
    const ghidra::VarnodeData &right) noexcept {
    return left.space == right.space && left.offset == right.offset &&
           left.size == right.size;
}

ghidra::TrackedSet ProgramContextDatabase::tracked_value_at(
    const TrackedSpaceState &state,
    ghidra::uintb offset) const {
    const auto after = state.partitions.upper_bound(offset);
    if (after == state.partitions.begin()) return tracked_default_;
    return std::prev(after)->second;
}

ghidra::TrackedSet &ProgramContextDatabase::getTrackedDefault() {
    return tracked_default_;
}

const ghidra::TrackedSet &ProgramContextDatabase::getTrackedSet(
    const ghidra::Address &address) const {
    if (address.isInvalid() || address.getSpace() == nullptr) {
        return tracked_default_;
    }
    const auto found = tracked_spaces_.find(address.getSpace());
    if (found == tracked_spaces_.end()) return tracked_default_;
    const auto after = found->second.partitions.upper_bound(address.getOffset());
    if (after == found->second.partitions.begin()) return tracked_default_;
    return std::prev(after)->second;
}

ghidra::TrackedSet &ProgramContextDatabase::createSet(
    const ghidra::Address &first,
    const ghidra::Address &end_open) {
    if (first.isInvalid() || first.getSpace() == nullptr) {
        throw std::invalid_argument("tracked context range has no start address");
    }
    if (!end_open.isInvalid() && end_open.getSpace() != first.getSpace()) {
        throw std::invalid_argument(
            "tracked context range crosses address spaces");
    }
    if (!end_open.isInvalid() &&
        end_open.getOffset() <= first.getOffset()) {
        throw std::invalid_argument("tracked context range is empty or reversed");
    }
    auto &state = tracked_spaces_[first.getSpace()];
    const auto inherited = tracked_value_at(state, first.getOffset());
    auto [begin, inserted] = state.partitions.try_emplace(
        first.getOffset(), inherited);
    if (!inserted) begin->second = inherited;

    auto erase_end = state.partitions.end();
    if (!end_open.isInvalid()) {
        const auto after_value = tracked_value_at(state, end_open.getOffset());
        erase_end = state.partitions.try_emplace(
            end_open.getOffset(), after_value).first;
    }
    state.partitions.erase(std::next(begin), erase_end);
    begin->second.clear();
    return begin->second;
}

void ProgramContextDatabase::encode(ghidra::Encoder &encoder) const {
    std::vector<Address> points;
    if (!context_register_.empty()) {
        const auto collect = [&](const std::vector<RegisterValueRange> &ranges) {
            for (const auto &entry : ranges) {
                points.push_back(entry.range.min_address());
                if (const auto after = entry.range.max_address().next()) {
                    points.push_back(*after);
                }
            }
        };
        collect(register_context_->default_ranges(context_register_));
        collect(register_context_->ranges(context_register_));
    }
    std::ranges::sort(points);
    points.erase(std::unique(points.begin(), points.end()), points.end());

    bool has_tracked_points = false;
    for (const auto &[space, state] : tracked_spaces_) {
        (void)space;
        if (!state.partitions.empty()) {
            has_tracked_points = true;
            break;
        }
    }
    if (points.empty() && !has_tracked_points) return;

    encoder.openElement(ghidra::ELEM_CONTEXT_POINTS);
    for (const auto &point : points) {
        const auto sleigh_address = to_sleigh_address(point);
        const auto *blob = getContext(sleigh_address);
        encoder.openElement(ghidra::ELEM_CONTEXT_POINTSET);
        sleigh_address.getSpace()->encodeAttributes(
            encoder, sleigh_address.getOffset());
        for (const auto &field : registered_fields_) {
            const ghidra::ContextBitRange bit_range(
                static_cast<ghidra::int4>(field.start_bit),
                static_cast<ghidra::int4>(field.end_bit));
            encoder.openElement(ghidra::ELEM_SET);
            encoder.writeString(ghidra::ATTRIB_NAME, field.name);
            encoder.writeUnsignedInteger(
                ghidra::ATTRIB_VAL, bit_range.getValue(blob));
            encoder.closeElement(ghidra::ELEM_SET);
        }
        encoder.closeElement(ghidra::ELEM_CONTEXT_POINTSET);
    }
    for (const auto &[space, state] : tracked_spaces_) {
        for (const auto &[offset, values] : state.partitions) {
            if (values.empty()) {
                encoder.openElement(ghidra::ELEM_TRACKED_POINTSET);
                space->encodeAttributes(encoder, offset);
                encoder.closeElement(ghidra::ELEM_TRACKED_POINTSET);
            }
            else {
                encodeTracked(
                    encoder, ghidra::Address(space, offset), values);
            }
        }
    }
    encoder.closeElement(ghidra::ELEM_CONTEXT_POINTS);
}

void ProgramContextDatabase::decode(ghidra::Decoder &decoder) {
    const auto element = decoder.openElement(ghidra::ELEM_CONTEXT_POINTS);
    for (;;) {
        const auto child = decoder.openElement();
        if (child == 0) break;
        if (child == ghidra::ELEM_CONTEXT_POINTSET) {
            const auto first_attribute = decoder.getNextAttributeId();
            decoder.rewindAttributes();
            const bool is_default = first_attribute == 0;
            ghidra::Address address;
            if (!is_default) {
                ghidra::VarnodeData location;
                location.decodeFromAttributes(decoder);
                address = location.getAddr();
            }
            for (;;) {
                const auto setting = decoder.openElement();
                if (setting != ghidra::ELEM_SET) break;
                const auto value = decoder.readUnsignedInteger(
                    ghidra::ATTRIB_VAL);
                const auto name = decoder.readString(ghidra::ATTRIB_NAME);
                if (is_default) setVariableDefault(name, value);
                else setVariable(name, address, value);
                decoder.closeElement(setting);
            }
        }
        else if (child == ghidra::ELEM_TRACKED_POINTSET) {
            ghidra::VarnodeData location;
            location.decodeFromAttributes(decoder);
            auto &values = tracked_spaces_[location.space]
                               .partitions[location.offset];
            decodeTracked(decoder, values);
        }
        else {
            throw ghidra::LowlevelError("Bad <context_points> tag");
        }
        decoder.closeElement(child);
    }
    decoder.closeElement(element);
}

void ProgramContextDatabase::decodeFromSpec(ghidra::Decoder &decoder) {
    // Retain the standard decompiler XML decoder so Architecture's pspec and
    // cspec flows can use this ContextDatabase without a Java-side alternate
    // entry point.  Low-level context defaults/ranges are authoritative in the
    // parsed ProcessorSpec/CompilerSpec and RegisterContextManager; the
    // inherited ContextInternal partition remains the compatibility mirror
    // used by the SLEIGH mutation protocol.  createSet() is virtual, so tracked
    // ranges decoded here are routed into tracked_spaces_.
    ghidra::ContextInternal::decodeFromSpec(decoder);
}

void ProgramContextDatabase::overlay_tracked_setting(
    const std::unordered_map<std::string, std::string> &setting) {
    const auto &space_name = required_attribute(setting, "space");
    auto *space = translate_->getSpaceByName(space_name);
    if (space == nullptr) {
        throw std::runtime_error(
            "tracked context setting uses an unknown SLEIGH space: " +
            space_name);
    }
    const auto &register_name = required_attribute(setting, "name");
    const auto &storage = translate_->getRegister(register_name);
    const auto value = parse_integer(
        required_attribute(setting, "val"), "val");

    ghidra::uintb first = 0;
    ghidra::uintb last = space->getHighest();
    if (const auto found = setting.find("first"); found != setting.end()) {
        first = parse_integer(found->second, "first");
    }
    if (const auto found = setting.find("last"); found != setting.end()) {
        last = parse_integer(found->second, "last");
    }
    if (first > last || last > space->getHighest()) {
        throw std::runtime_error("tracked context setting range is invalid");
    }

    auto &state = tracked_spaces_[space];
    const auto start_value = tracked_value_at(state, first);
    state.partitions.try_emplace(first, start_value);
    const bool bounded = last != space->getHighest();
    const ghidra::uintb end_open = bounded ? last + 1U : 0;
    if (bounded) {
        const auto after_value = tracked_value_at(state, end_open);
        state.partitions.try_emplace(end_open, after_value);
    }

    for (auto iterator = state.partitions.lower_bound(first);
         iterator != state.partitions.end() &&
         (!bounded || iterator->first < end_open); ++iterator) {
        auto &values = iterator->second;
        const auto existing = std::ranges::find_if(
            values, [&](const auto &candidate) {
                return same_storage(candidate.loc, storage);
            });
        ghidra::TrackedContext tracked{storage, value};
        if (existing == values.end()) values.push_back(tracked);
        else *existing = tracked;
    }
}

void ProgramContextDatabase::initialize_tracked_values(
    const ProcessorSpec &processor_spec,
    const CompilerSpec &compiler_spec) {
    tracked_default_.clear();
    tracked_spaces_.clear();
    for (const auto &setting : processor_spec.tracked_settings) {
        overlay_tracked_setting(setting);
    }
    for (const auto &setting : compiler_spec.tracked_settings) {
        overlay_tracked_setting(setting);
    }
}

void ProgramContextDatabase::validate_registered_metadata() const {
    if (static_cast<std::size_t>(getContextSize()) *
            sizeof(ghidra::uintm) > context_register_size_) {
        throw std::runtime_error(
            "SLEIGH context blob exceeds the ProgramDB context register");
    }
    auto registered = registered_fields_;
    auto expected = architecture_->processor_context_fields;
    const auto order = [](const auto &left, const auto &right) {
        return std::tie(left.name, left.start_bit, left.end_bit) <
               std::tie(right.name, right.start_bit, right.end_bit);
    };
    std::ranges::sort(registered, order);
    std::ranges::sort(expected, order);
    if (registered != expected) {
        throw std::runtime_error(
            "SLEIGH registered context fields do not match ProgramArchitecture");
    }
}

const std::vector<ProcessorContextFieldDescription> &
ProgramContextDatabase::registered_fields() const noexcept {
    return registered_fields_;
}

} // namespace llmghidra::program
