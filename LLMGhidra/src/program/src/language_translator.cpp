#include "llmghidra/program/language_translator.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/program_architecture.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace llmghidra::program {
namespace {

[[nodiscard]] std::string folded(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] bool bit_is_set(
    const std::vector<std::uint8_t> &bytes,
    std::uint32_t absolute_msb_bit) {
    const auto byte = static_cast<std::size_t>(absolute_msb_bit / 8U);
    if (byte >= bytes.size()) return false;
    return (bytes[byte] & static_cast<std::uint8_t>(
        1U << (7U - absolute_msb_bit % 8U))) != 0;
}

void set_bit(std::vector<std::uint8_t> &bytes,
             std::uint32_t absolute_msb_bit,
             bool enabled = true) {
    const auto byte = static_cast<std::size_t>(absolute_msb_bit / 8U);
    if (byte >= bytes.size()) {
        throw std::out_of_range("translated register bit is outside its base");
    }
    const auto mask = static_cast<std::uint8_t>(
        1U << (7U - absolute_msb_bit % 8U));
    if (enabled) bytes[byte] |= mask;
    else bytes[byte] &= static_cast<std::uint8_t>(~mask);
}

[[nodiscard]] bool field_fully_defined(
    const RegisterValue &value,
    const ProcessorContextFieldDescription &field) {
    for (auto bit = field.start_bit; bit <= field.end_bit; ++bit) {
        if (!bit_is_set(value.mask, bit)) return false;
    }
    return true;
}

[[nodiscard]] std::uint64_t field_value(
    const RegisterValue &value,
    const ProcessorContextFieldDescription &field) {
    std::uint64_t result{};
    const auto width = field.end_bit - field.start_bit + 1U;
    if (width > 64U) {
        throw std::runtime_error(
            "processor-context field exceeds native translation width");
    }
    for (std::uint32_t relative = 0; relative < width; ++relative) {
        const auto absolute = field.end_bit - relative;
        if (bit_is_set(value.value, absolute)) result |= 1ULL << relative;
    }
    return result;
}

void set_field(RegisterValue &value,
               const ProcessorContextFieldDescription &field,
               std::uint64_t field_bits) {
    const auto width = field.end_bit - field.start_bit + 1U;
    if (width > 64U) {
        throw std::runtime_error(
            "processor-context field exceeds native translation width");
    }
    for (std::uint32_t relative = 0; relative < width; ++relative) {
        const auto absolute = field.end_bit - relative;
        set_bit(value.mask, absolute);
        set_bit(value.value, absolute, ((field_bits >> relative) & 1U) != 0);
    }
}

[[nodiscard]] std::string base_name(
    const ProgramArchitecture &architecture,
    std::string name) {
    for (;;) {
        const auto description = architecture.register_named(name);
        if (!description) {
            throw std::runtime_error("language translator references an unknown register: " + name);
        }
        if (!description->base_register) return name;
        name = *description->base_register;
    }
}

} // namespace

SimpleLanguageTranslator::SimpleLanguageTranslator(
    LanguageTranslationDescription description,
    std::shared_ptr<const ProgramArchitecture> old_architecture,
    std::shared_ptr<const ProgramArchitecture> new_architecture,
    std::shared_ptr<const AddressFactory> old_address_factory,
    std::shared_ptr<const AddressFactory> new_address_factory)
    : description_(std::move(description)),
      old_architecture_(std::move(old_architecture)),
      new_architecture_(std::move(new_architecture)),
      old_address_factory_(std::move(old_address_factory)),
      new_address_factory_(std::move(new_address_factory)) {
    if (!old_architecture_ || !new_architecture_ ||
        !old_address_factory_ || !new_address_factory_) {
        throw std::invalid_argument(
            "language translator requires old/new architectures and address factories");
    }
    for (const auto &[old_name, new_name] : description_.registers) {
        const bool ordinary_mapping =
            canonical_register(*old_architecture_, old_name).has_value() &&
            canonical_register(*new_architecture_, new_name).has_value();
        const bool context_field_mapping =
            canonical_context_field(*old_architecture_, old_name).has_value() &&
            canonical_context_field(*new_architecture_, new_name).has_value();
        if (!ordinary_mapping && !context_field_mapping) {
            throw std::runtime_error(
                "language translation contains an invalid register mapping: " +
                old_name + " -> " + new_name);
        }
    }
    for (const auto &[name, value] : description_.context_values) {
        (void)value;
        const auto found = std::ranges::find_if(
            new_architecture_->processor_context_fields,
            [&](const auto &field) {
                return folded(field.name) == folded(name);
            });
        if (found == new_architecture_->processor_context_fields.end()) {
            throw std::runtime_error(
                "language translation sets an unknown context field: " + name);
        }
    }
    validate_address_spaces();
}

const ProgramArchitecture &
SimpleLanguageTranslator::old_architecture() const {
    return *old_architecture_;
}

const std::string &SimpleLanguageTranslator::old_language_id() const {
    return description_.from_language_id;
}

std::int32_t SimpleLanguageTranslator::old_language_version() const {
    return description_.from_version;
}

const std::string &SimpleLanguageTranslator::new_language_id() const {
    return description_.to_language_id;
}

std::int32_t SimpleLanguageTranslator::new_language_version() const {
    return description_.to_version;
}

const ProgramArchitecture &
SimpleLanguageTranslator::new_architecture() const {
    return *new_architecture_;
}

const AddressFactory &
SimpleLanguageTranslator::old_address_factory() const {
    return *old_address_factory_;
}

const AddressFactory &
SimpleLanguageTranslator::new_address_factory() const {
    return *new_address_factory_;
}

std::optional<std::string> SimpleLanguageTranslator::canonical_register(
    const ProgramArchitecture &architecture,
    const std::string &name) const {
    if (const auto exact = architecture.registers.find(name);
        exact != architecture.registers.end()) {
        return exact->first;
    }
    const auto wanted = folded(name);
    for (const auto &[candidate, description] : architecture.registers) {
        (void)description;
        if (folded(candidate) == wanted) return candidate;
    }
    return std::nullopt;
}

std::optional<std::string> SimpleLanguageTranslator::canonical_context_field(
    const ProgramArchitecture &architecture,
    const std::string &name) const {
    const auto wanted = folded(name);
    const auto found = std::ranges::find_if(
        architecture.processor_context_fields,
        [&](const auto &field) { return folded(field.name) == wanted; });
    return found == architecture.processor_context_fields.end()
        ? std::nullopt
        : std::optional<std::string>(found->name);
}

void SimpleLanguageTranslator::validate_address_spaces() const {
    const auto require_fits = [](const AddressSpace &old_space,
                                 const AddressSpace &new_space) {
        if (old_space.type() != new_space.type() ||
            old_space.is_segmented_space() != new_space.is_segmented_space() ||
            old_space.size() > new_space.size() ||
            old_space.addressable_unit_size() !=
                new_space.addressable_unit_size()) {
            throw std::runtime_error(
                "language translation maps incompatible address spaces: " +
                old_space.name() + " -> " + new_space.name());
        }
    };

    if (description_.address_spaces.empty()) {
        require_fits(*old_address_factory_->default_space(),
                     *new_address_factory_->default_space());
        if (old_address_factory_->register_space() &&
            new_address_factory_->register_space()) {
            require_fits(*old_address_factory_->register_space(),
                         *new_address_factory_->register_space());
        }
        for (const auto &old_space : old_address_factory_->physical_spaces()) {
            if (old_space->equivalent(*old_address_factory_->default_space())) {
                continue;
            }
            const auto target = new_address_factory_->space(old_space->name());
            if (!target) {
                throw std::runtime_error(
                    "default language translation cannot map address space: " +
                    old_space->name());
            }
            require_fits(*old_space, *target);
        }
        return;
    }

    for (const auto &old_space : old_address_factory_->physical_spaces()) {
        const auto mapping = description_.address_spaces.find(old_space->name());
        if (mapping == description_.address_spaces.end()) {
            throw std::runtime_error(
                "explicit language translation omits address space: " +
                old_space->name());
        }
        if (!mapping->second) {
            if (old_space->equivalent(*old_address_factory_->default_space())) {
                throw std::runtime_error(
                    "language translation cannot delete the default address space");
            }
            continue;
        }
        const auto target = new_address_factory_->space(*mapping->second);
        if (!target) {
            throw std::runtime_error(
                "language translation targets an unknown address space: " +
                *mapping->second);
        }
        require_fits(*old_space, *target);
    }
}

std::optional<std::string> SimpleLanguageTranslator::new_address_space(
    const std::string &old_name) const {
    if (!description_.address_spaces.empty()) {
        const auto found = description_.address_spaces.find(old_name);
        return found == description_.address_spaces.end()
            ? std::nullopt : found->second;
    }
    const auto old_space = old_address_factory_->space(old_name);
    if (!old_space) return std::nullopt;
    if (old_space->equivalent(*old_address_factory_->default_space())) {
        return new_address_factory_->default_space()->name();
    }
    if (old_space->is_register_space() &&
        new_address_factory_->register_space()) {
        return new_address_factory_->register_space()->name();
    }
    if (old_space->is_stack_space() && new_address_factory_->stack_space()) {
        return new_address_factory_->stack_space()->name();
    }
    if (old_space->is_constant_space() &&
        new_address_factory_->constant_space()) {
        return new_address_factory_->constant_space()->name();
    }
    if (old_space->is_unique_space() && new_address_factory_->unique_space()) {
        return new_address_factory_->unique_space()->name();
    }
    const auto target = new_address_factory_->space(old_name);
    return target ? std::optional<std::string>(target->name()) : std::nullopt;
}

std::optional<Address> SimpleLanguageTranslator::new_address(
    const Address &old_address) const {
    if (!old_address.is_valid()) return Address::no_address();
    if (const auto same_name =
            new_address_factory_->space(old_address.space()->name());
        old_address.space()->is_overlay_space() && same_name &&
        same_name->is_overlay_space()) {
        if (old_address.offset() > same_name->max_offset()) return std::nullopt;
        return same_name->address_in_this_space(old_address.offset());
    }
    const auto target_name = new_address_space(old_address.space()->name());
    if (!target_name) return std::nullopt;
    const auto target = new_address_factory_->space(*target_name);
    if (!target || old_address.offset() < target->min_offset() ||
        old_address.offset() > target->max_offset()) {
        return std::nullopt;
    }
    if (old_address.space()->is_segmented_space() &&
        target->is_segmented_space()) {
        const auto segment = old_address.segment();
        const auto segment_offset = old_address.segment_offset();
        if (!segment || !segment_offset) return std::nullopt;
        return target->segmented_address(*segment, *segment_offset);
    }
    return target->address_in_this_space(old_address.offset());
}

std::optional<Address> SimpleLanguageTranslator::new_register_address(
    const Address &old_address,
    std::int32_t size) const {
    if (!old_address.is_register_address() || size <= 0) {
        return std::nullopt;
    }
    const std::pair<const std::string, RegisterDescription> *old_register = nullptr;

    // Match Language.getRegister(address, size): at the exact address choose
    // the smallest register whose storage can hold the varnode.
    for (const auto &candidate : old_architecture_->registers) {
        if (!candidate.second.address.same_space(old_address) ||
            candidate.second.address != old_address ||
            candidate.second.size < size) {
            continue;
        }
        if (!old_register ||
            candidate.second.size < old_register->second.size ||
            (candidate.second.size == old_register->second.size &&
             candidate.first < old_register->first)) {
            old_register = &candidate;
        }
    }

    // An address may be an offcut for a serialized register varnode.  Ghidra
    // falls back to the containing base register, not to an arbitrary child.
    if (!old_register) {
        for (const auto &candidate : old_architecture_->registers) {
            if (candidate.second.base_register ||
                candidate.second.size <= 0 ||
                !candidate.second.address.same_space(old_address) ||
                candidate.second.address > old_address) {
                continue;
            }
            const auto shift = old_address.offset() -
                               candidate.second.address.offset();
            if (shift >= static_cast<std::uint64_t>(candidate.second.size)) {
                continue;
            }
            if (!old_register ||
                candidate.second.size > old_register->second.size ||
                (candidate.second.size == old_register->second.size &&
                 candidate.first < old_register->first)) {
                old_register = &candidate;
            }
        }
    }
    if (!old_register) return std::nullopt;
    const auto target_name = new_register(old_register->first);
    if (!target_name) return std::nullopt;
    const auto target = new_architecture_->register_named(*target_name);
    if (!target || target->size <= 0) return std::nullopt;

    const auto byte_shift = old_address.offset() -
                            old_register->second.address.offset();
    std::uint64_t translated_shift = byte_shift;
    if (new_architecture_->endian == Endian::big) {
        const auto size_difference = static_cast<std::int64_t>(target->size) -
                                     old_register->second.size;
        if (size_difference < 0 && translated_shift <
                static_cast<std::uint64_t>(-size_difference)) {
            return std::nullopt;
        }
        translated_shift = size_difference < 0
            ? translated_shift - static_cast<std::uint64_t>(-size_difference)
            : translated_shift + static_cast<std::uint64_t>(size_difference);
    }
    if (translated_shift > static_cast<std::uint64_t>(target->size) ||
        static_cast<std::uint64_t>(size) >
            static_cast<std::uint64_t>(target->size) - translated_shift) {
        return std::nullopt;
    }
    const auto target_space = new_address_factory_->register_space();
    if (!target_space || translated_shift > target_space->max_offset() ||
        target->address.offset() >
            target_space->max_offset() - translated_shift) {
        return std::nullopt;
    }
    return target_space->address_in_this_space(
        target->address.offset() + translated_shift);
}

std::optional<std::string> SimpleLanguageTranslator::new_register(
    const std::string &old_name) const {
    std::string target = old_name;
    if (const auto explicit_mapping = description_.registers.find(old_name);
        explicit_mapping != description_.registers.end()) {
        target = explicit_mapping->second;
    }
    if (const auto ordinary = canonical_register(*new_architecture_, target)) {
        return ordinary;
    }
    const auto old_register = old_architecture_->register_named(old_name);
    if (old_register && old_register->processor_context &&
        new_architecture_->processor_context_register) {
        return canonical_register(
            *new_architecture_,
            *new_architecture_->processor_context_register);
    }
    if (canonical_context_field(*old_architecture_, old_name)) {
        return canonical_context_field(*new_architecture_, target);
    }
    return std::nullopt;
}

std::optional<RegisterValue> SimpleLanguageTranslator::translate_normal_value(
    const RegisterValue &old_value,
    const std::string &target_name) const {
    const auto target = new_architecture_->register_named(target_name);
    if (!target || target->size <= 0) return std::nullopt;
    const auto target_base_name = base_name(*new_architecture_, target_name);
    const auto target_base = new_architecture_->register_named(target_base_name);
    if (!target_base || target_base->size <= 0 ||
        target_base->base_register) {
        throw std::runtime_error(
            "translated register does not resolve to a valid base register");
    }
    if (old_value.mask.size() != old_value.value.size()) {
        throw std::invalid_argument(
            "translated register value has mismatched mask/value widths");
    }
    const auto target_width = static_cast<std::size_t>(target_base->size);
    const auto old_width = old_value.mask.size();
    RegisterValue result{target_base_name,
                         std::vector<std::uint8_t>(target_width, 0),
                         std::vector<std::uint8_t>(target_width, 0)};
    const auto keep = std::min(old_width, target_width);
    const auto old_start = old_width - keep;
    const auto new_start = target_width - keep;
    bool copied_mask_is_full = keep != 0;
    for (std::size_t index = 0; index < keep; ++index) {
        const auto mask = old_value.mask[old_start + index];
        result.mask[new_start + index] = mask;
        result.value[new_start + index] = static_cast<std::uint8_t>(
            old_value.value[old_start + index] & mask);
        copied_mask_is_full = copied_mask_is_full && mask == 0xff;
    }
    if (target_width > old_width && copied_mask_is_full) {
        std::fill(result.mask.begin(),
                  result.mask.begin() + static_cast<std::ptrdiff_t>(new_start),
                  0xff);
    }

    if (target->base_register) {
        if (!target->address.same_space(target_base->address) ||
            target->address < target_base->address) {
            throw std::runtime_error(
                "translated sub-register is outside its base register");
        }
        const auto byte_delta = target->address.offset() -
                                target_base->address.offset();
        const auto target_size = static_cast<std::size_t>(target->size);
        if (byte_delta > target_width || target_size > target_width ||
            static_cast<std::uint64_t>(target_size) >
                static_cast<std::uint64_t>(target_width) - byte_delta) {
            throw std::runtime_error(
                "translated sub-register exceeds its base register");
        }
        const auto significance_offset = new_architecture_->endian == Endian::big
            ? static_cast<std::size_t>(byte_delta)
            : target_width - static_cast<std::size_t>(byte_delta) - target_size;
        for (std::size_t index = 0; index < target_width; ++index) {
            if (index >= significance_offset &&
                index < significance_offset + target_size) {
                continue;
            }
            result.mask[index] = 0;
            result.value[index] = 0;
        }
    }
    return result.has_any_value()
        ? std::optional<RegisterValue>(std::move(result)) : std::nullopt;
}

std::optional<RegisterValue> SimpleLanguageTranslator::translate_context_value(
    const RegisterValue &old_value,
    bool carry_old_values) const {
    if (!new_architecture_->processor_context_register) return std::nullopt;
    const auto &target_name = *new_architecture_->processor_context_register;
    const auto target = new_architecture_->register_named(target_name);
    if (!target || target->size <= 0 || target->base_register ||
        !target->processor_context) {
        throw std::runtime_error(
            "new processor-context base register metadata is invalid");
    }
    const auto target_width = static_cast<std::size_t>(target->size);
    RegisterValue result{target_name,
                         std::vector<std::uint8_t>(target_width, 0),
                         std::vector<std::uint8_t>(target_width, 0)};
    if (carry_old_values) {
        if (!old_architecture_->processor_context_register) {
            throw std::invalid_argument(
                "old context values require an old context base register");
        }
        const auto old_context = old_architecture_->register_named(
            *old_architecture_->processor_context_register);
        if (!old_context || old_context->size <= 0 ||
            old_value.mask.size() !=
                static_cast<std::size_t>(old_context->size) ||
            old_value.value.size() != old_value.mask.size()) {
            throw std::invalid_argument(
                "old processor-context value has an invalid width");
        }
        for (const auto &old_field : old_architecture_->processor_context_fields) {
            if (!field_fully_defined(old_value, old_field)) continue;
            std::string mapped_name = old_field.name;
            if (const auto mapping = description_.registers.find(old_field.name);
                mapping != description_.registers.end()) {
                mapped_name = mapping->second;
            }
            const auto new_field = std::ranges::find_if(
                new_architecture_->processor_context_fields,
                [&](const auto &field) {
                    return folded(field.name) == folded(mapped_name);
                });
            if (new_field ==
                new_architecture_->processor_context_fields.end()) {
                continue;
            }
            if (new_field->end_bit >= target_width * 8U) {
                throw std::runtime_error(
                    "translated context field exceeds the new context register");
            }
            set_field(result, *new_field, field_value(old_value, old_field));
        }
    }
    for (const auto &[name, value] : description_.context_values) {
        const auto field = std::ranges::find_if(
            new_architecture_->processor_context_fields,
            [&](const auto &candidate) {
                return folded(candidate.name) == folded(name);
            });
        if (field == new_architecture_->processor_context_fields.end() ||
            field->end_bit >= target_width * 8U) {
            throw std::runtime_error(
                "configured context field exceeds the new context register");
        }
        set_field(result, *field, value);
    }
    return result.has_any_value()
        ? std::optional<RegisterValue>(std::move(result)) : std::nullopt;
}

std::optional<RegisterValue> SimpleLanguageTranslator::new_register_value(
    const RegisterValue &old_value) const {
    const auto old_description = old_architecture_->register_named(
        old_value.register_name);
    if (!old_description || old_description->base_register) {
        throw std::invalid_argument(
            "translated RegisterValue must name an old base register");
    }
    if (old_description->size <= 0 ||
        old_value.mask.size() !=
            static_cast<std::size_t>(old_description->size) ||
        old_value.value.size() != old_value.mask.size()) {
        throw std::invalid_argument(
            "translated RegisterValue width does not match its old base register");
    }
    if (old_description->processor_context) {
        return translate_context_value(old_value,
                                       !description_.clear_all_context);
    }
    const auto target = new_register(old_value.register_name);
    return target ? translate_normal_value(old_value, *target) : std::nullopt;
}

bool SimpleLanguageTranslator::value_translation_required(
    const std::string &old_register) const {
    const auto old_description = old_architecture_->register_named(old_register);
    const auto target_name = new_register(old_register);
    if (!old_description || old_description->base_register) {
        return false;
    }
    if (old_description->processor_context &&
        (description_.clear_all_context ||
         !description_.context_values.empty())) {
        return true;
    }
    if (!target_name) return false;
    const auto target = new_architecture_->register_named(*target_name);
    if (!target) return false;
    if (old_description->processor_context) {
        if (!target->processor_context ||
            target->size != old_description->size) {
            return true;
        }
        for (const auto &old_field : old_architecture_->processor_context_fields) {
            std::string mapped_name = old_field.name;
            if (const auto mapping = description_.registers.find(old_field.name);
                mapping != description_.registers.end()) {
                mapped_name = mapping->second;
            }
            const auto new_field = std::ranges::find_if(
                new_architecture_->processor_context_fields,
                [&](const auto &candidate) {
                    return folded(candidate.name) == folded(mapped_name);
                });
            if (new_field ==
                    new_architecture_->processor_context_fields.end() ||
                old_field.start_bit != new_field->start_bit ||
                old_field.end_bit != new_field->end_bit) {
                return true;
            }
        }
    }
    return target->size != old_description->size ||
           target->least_significant_bit !=
               old_description->least_significant_bit ||
           target->bit_length != old_description->bit_length ||
           target->base_register.has_value();
}

std::string SimpleLanguageTranslator::new_compiler_spec_id(
    const std::string &old_id) const {
    const auto found = description_.compiler_specs.find(old_id);
    return found == description_.compiler_specs.end() ? old_id : found->second;
}

std::optional<RegisterValue>
SimpleLanguageTranslator::context_gap_value() const {
    if (description_.context_values.empty()) return std::nullopt;
    RegisterValue empty;
    if (old_architecture_->processor_context_register) {
        const auto &name = *old_architecture_->processor_context_register;
        const auto description = old_architecture_->register_named(name);
        empty.register_name = name;
        empty.mask.assign(static_cast<std::size_t>(description->size), 0);
        empty.value.assign(static_cast<std::size_t>(description->size), 0);
    }
    else if (new_architecture_->processor_context_register) {
        // No old context can be carried, but set_context still establishes the
        // new gap value.
        const auto &name = *new_architecture_->processor_context_register;
        const auto description = new_architecture_->register_named(name);
        empty.register_name = name;
        empty.mask.assign(static_cast<std::size_t>(description->size), 0);
        empty.value.assign(static_cast<std::size_t>(description->size), 0);
    }
    else {
        return std::nullopt;
    }
    return translate_context_value(empty, false);
}

std::vector<std::string>
SimpleLanguageTranslator::post_upgrade_handlers() const {
    return description_.post_upgrade_handler
        ? std::vector<std::string>{*description_.post_upgrade_handler}
        : std::vector<std::string>{};
}

const LanguageTranslationDescription &
SimpleLanguageTranslator::description() const noexcept {
    return description_;
}

} // namespace llmghidra::program
