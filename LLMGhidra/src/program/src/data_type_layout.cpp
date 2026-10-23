#include "llmghidra/program/data_type_manager.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <numeric>
#include <set>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <unordered_set>

namespace llmghidra::program {
namespace {

[[nodiscard]] std::int32_t checked_i32(std::int64_t value,
                                       std::string_view operation) {
    if (value < 0 || value > std::numeric_limits<std::int32_t>::max()) {
        throw std::overflow_error(std::string(operation) +
                                  " exceeds the ProgramDB signed 32-bit layout range");
    }
    return static_cast<std::int32_t>(value);
}

[[nodiscard]] std::int32_t aligned_offset(std::int32_t alignment,
                                          std::int32_t offset) {
    if (alignment <= 0 || offset < 0) {
        throw std::invalid_argument("layout alignment and offset must be positive");
    }
    const auto remainder = offset % alignment;
    if (remainder == 0) return offset;
    return checked_i32(static_cast<std::int64_t>(offset) + alignment - remainder,
                       "aligned offset");
}

[[nodiscard]] std::int32_t layout_lcm(std::int32_t left,
                                      std::int32_t right) {
    if (left <= 0 || right <= 0) {
        throw std::invalid_argument("layout alignment must be positive");
    }
    return checked_i32((static_cast<std::int64_t>(left) / std::gcd(left, right)) * right,
                       "alignment LCM");
}

[[nodiscard]] std::int32_t packed_alignment(std::int32_t alignment,
                                            std::int32_t packing) {
    if (packing > 0) return std::min(alignment, packing);
    return alignment;
}

[[nodiscard]] std::string simple_class_name(std::string value) {
    const auto separator = value.find_last_of("./$");
    if (separator != std::string::npos) value.erase(0, separator + 1);
    return value;
}

[[nodiscard]] bool contains_case_insensitive(std::string_view text,
                                             std::string_view needle) {
    return std::search(text.begin(), text.end(), needle.begin(), needle.end(),
                       [](unsigned char left, unsigned char right) {
                           return std::tolower(left) == std::tolower(right);
                       }) != text.end();
}

[[nodiscard]] std::optional<std::int32_t> numbered_builtin_size(
    const std::string &class_name,
    std::string_view prefix) {
    if (!class_name.starts_with(prefix)) return std::nullopt;
    const auto begin = class_name.data() + prefix.size();
    const auto end = class_name.data() + class_name.size();
    std::int32_t size{};
    const auto [cursor, error] = std::from_chars(begin, end, size);
    if (error == std::errc{} && cursor != begin &&
        std::string_view(cursor, static_cast<std::size_t>(end - cursor)) == "DataType") {
        return size;
    }
    return std::nullopt;
}

[[nodiscard]] DataTypeMetrics fixed_metrics(std::int32_t length,
                                             const DataOrganization &organization,
                                             std::optional<std::int32_t> alignment = std::nullopt) {
    const auto actual_alignment = alignment.value_or(static_cast<std::int32_t>(
        organization.alignment_for_size(static_cast<std::uint32_t>(length))));
    return {length, aligned_offset(std::max(1, actual_alignment), length),
            std::max(1, actual_alignment), false, length == 0};
}

[[nodiscard]] std::int32_t pointer_alignment(
    std::int32_t length,
    const DataOrganization &organization) {
    if (organization.size_alignment.contains(static_cast<std::uint32_t>(length))) {
        return checked_i32(organization.alignment_for_size(length), "pointer alignment");
    }
    return checked_i32(
        std::max<std::uint32_t>(1, organization.default_pointer_alignment),
        "pointer alignment");
}

[[nodiscard]] DataTypeMetrics builtin_metrics(
    const BuiltinDataType &value,
    const DataOrganization &organization) {
    const std::string type = simple_class_name(value.class_name);

    if (contains_case_insensitive(type, "VoidDataType")) {
        return {0, 0, 1, false, true};
    }
    if (contains_case_insensitive(type, "BadDataType") ||
        contains_case_insensitive(type, "Dynamic") ||
        contains_case_insensitive(type, "Factory") ||
        contains_case_insensitive(type, "StringDataType") ||
        contains_case_insensitive(type, "Leb128")) {
        return {-1, -1, 1, true, false};
    }
    if (contains_case_insensitive(type, "PointerDataType")) {
        const auto size = checked_i32(organization.pointer_size, "pointer size");
        const auto alignment = pointer_alignment(size, organization);
        return {size, size, alignment, false, false};
    }
    if (contains_case_insensitive(type, "WideChar16")) return fixed_metrics(2, organization);
    if (contains_case_insensitive(type, "WideChar32")) return fixed_metrics(4, organization);
    if (contains_case_insensitive(type, "WideChar")) {
        return fixed_metrics(checked_i32(organization.wchar_size, "wchar size"), organization);
    }
    if (contains_case_insensitive(type, "LongDouble")) {
        return fixed_metrics(checked_i32(organization.long_double_size, "long double size"),
                             organization);
    }
    if (contains_case_insensitive(type, "LongLong")) {
        return fixed_metrics(checked_i32(organization.long_long_size, "long long size"),
                             organization);
    }
    if (contains_case_insensitive(type, "Double")) {
        return fixed_metrics(checked_i32(organization.double_size, "double size"), organization);
    }
    if (contains_case_insensitive(type, "Float")) {
        return fixed_metrics(checked_i32(organization.float_size, "float size"), organization);
    }
    if (contains_case_insensitive(type, "Short")) {
        return fixed_metrics(checked_i32(organization.short_size, "short size"), organization);
    }
    if (contains_case_insensitive(type, "IntegerDataType") ||
        contains_case_insensitive(type, "UnsignedIntegerDataType")) {
        return fixed_metrics(checked_i32(organization.integer_size, "integer size"),
                             organization);
    }
    if (contains_case_insensitive(type, "LongDataType") ||
        contains_case_insensitive(type, "UnsignedLongDataType")) {
        return fixed_metrics(checked_i32(organization.long_size, "long size"), organization);
    }
    if (const auto size = numbered_builtin_size(type, "Integer")) {
        return fixed_metrics(*size, organization);
    }
    if (const auto size = numbered_builtin_size(type, "UnsignedInteger")) {
        return fixed_metrics(*size, organization);
    }
    if (const auto size = numbered_builtin_size(type, "SignedInteger")) {
        return fixed_metrics(*size, organization);
    }
    if (contains_case_insensitive(type, "QWord")) return fixed_metrics(8, organization);
    if (contains_case_insensitive(type, "DWord")) return fixed_metrics(4, organization);
    if (contains_case_insensitive(type, "Word")) return fixed_metrics(2, organization);
    if (contains_case_insensitive(type, "Char") ||
        contains_case_insensitive(type, "Byte") ||
        contains_case_insensitive(type, "Boolean") ||
        contains_case_insensitive(type, "Undefined1") ||
        contains_case_insensitive(type, "DefaultDataType")) {
        const auto size = contains_case_insensitive(type, "Char")
                              ? checked_i32(organization.char_size, "char size")
                              : 1;
        return fixed_metrics(size, organization);
    }

    // BuiltIn records persist a Java class identity but no length.  Unknown
    // extension classes are therefore dynamic until their native provider is
    // registered; component use-sites retain their persisted concrete length.
    return {-1, -1, 1, true, false};
}

[[nodiscard]] std::int32_t minimum_composite_alignment(
    const CompositeDataType &value,
    const DataOrganization &organization) {
    if (value.minimum_alignment == CompositeDataType::machine_alignment) {
        return checked_i32(std::max<std::uint32_t>(1, organization.machine_alignment),
                           "machine alignment");
    }
    if (value.minimum_alignment > CompositeDataType::default_alignment) {
        return value.minimum_alignment;
    }
    return 1;
}

[[nodiscard]] std::int32_t finish_composite_alignment(
    std::int32_t component_alignment,
    const CompositeDataType &value,
    const DataOrganization &organization) {
    std::int32_t alignment = component_alignment;
    const auto minimum = minimum_composite_alignment(value, organization);
    if (alignment % minimum != 0) alignment = layout_lcm(alignment, minimum);
    if (organization.absolute_max_alignment != 0) {
        alignment = std::min(
            alignment,
            checked_i32(organization.absolute_max_alignment, "absolute maximum alignment"));
    }
    return std::max(1, alignment);
}

struct PackedBitField {
    BitFieldDataType type;
    std::int32_t base_size{};
    std::int32_t base_alignment{1};
    std::int32_t effective_bits{};
    std::int32_t storage_size{};
};

[[nodiscard]] PackedBitField bitfield_info(const DataTypeManager &manager,
                                           std::int64_t id,
                                           const DataOrganization &organization) {
    auto value = manager.data_type(id);
    if (!value || !std::holds_alternative<BitFieldDataType>(*value)) {
        throw std::invalid_argument("component does not reference a valid bitfield");
    }
    PackedBitField result;
    result.type = std::get<BitFieldDataType>(*value);
    const auto base = manager.data_type_metrics(result.type.base_type_id, organization);
    if (base.dynamic || base.length <= 0) {
        throw std::invalid_argument("bitfield base type must have a fixed positive size");
    }
    result.base_size = base.length;
    result.base_alignment = base.alignment;
    result.effective_bits = std::min<std::int32_t>(
        result.type.declared_bit_size,
        checked_i32(static_cast<std::int64_t>(base.length) * 8, "bitfield width"));
    result.storage_size = result.effective_bits == 0
                              ? 1
                              : (result.effective_bits + result.type.bit_offset + 7) / 8;
    return result;
}

class StructurePacker {
public:
    StructurePacker(const DataTypeManager &manager,
                    CompositeDataType &composite,
                    const DataOrganization &organization,
                    Endian endian)
        : manager_(manager), composite_(composite), organization_(organization),
          endian_(endian), packing_(composite.packing) {}

    void pack() {
        for (std::size_t index = 0; index < composite_.components.size(); ++index) {
            add_component(composite_.components[index],
                          index + 1 == composite_.components.size());
        }
        auto length = packed_length();
        composite_.alignment = finish_composite_alignment(
            component_alignment_lcm_, composite_, organization_);
        composite_.length = length == 0 ? 0 : aligned_offset(composite_.alignment, length);
    }

private:
    [[nodiscard]] bool is_bitfield(const CompositeComponent &component) const noexcept {
        return component.data_type_id > 0 &&
               DataTypeManager::kind(component.data_type_id) == DataTypeKind::bitfield;
    }

    [[nodiscard]] bool is_zero_bitfield(const CompositeComponent &component) const {
        return is_bitfield(component) &&
               bitfield_info(manager_, component.data_type_id, organization_).effective_bits == 0;
    }

    [[nodiscard]] std::int32_t bitfield_alignment(const PackedBitField &field) const {
        if (!organization_.bitfield_use_ms_convention &&
            packing_ != CompositeDataType::default_packing) {
            return 1;
        }
        return packed_alignment(field.base_alignment, packing_);
    }

    [[nodiscard]] bool ignored_zero_bitfield(const PackedBitField &field) const {
        if (field.effective_bits != 0 || !organization_.bitfield_use_ms_convention) return false;
        return last_ == nullptr || !is_bitfield(*last_);
    }

    [[nodiscard]] std::int32_t zero_bitfield_alignment(
        const PackedBitField &field,
        bool is_last) const {
        if (ignored_zero_bitfield(field)) return -1;
        if (!organization_.effective_bitfield_type_alignment()) {
            const auto boundary = organization_.effective_zero_length_bitfield_boundary();
            return boundary > 0 ? checked_i32(boundary, "zero-width bitfield boundary") : 1;
        }
        auto pack = packing_;
        if (!organization_.bitfield_use_ms_convention && !is_last) {
            pack = CompositeDataType::no_packing;
        }
        return packed_alignment(field.base_alignment, pack);
    }

    void update(CompositeComponent &component,
                std::int32_t offset,
                std::int32_t length,
                std::int32_t alignment) {
        component.ordinal = next_ordinal_;
        component.offset = offset;
        component.length = length;
        last_alignment_ = std::max(last_alignment_, alignment);
    }

    void rewrite_bitfield(CompositeComponent &component,
                          const PackedBitField &field,
                          std::int32_t bit_offset) const {
        if (field.type.bit_offset == bit_offset) return;
        auto adjusted = field.type;
        adjusted.bit_offset = static_cast<std::uint8_t>(bit_offset);
        adjusted.extra_storage =
            field.effective_bits + bit_offset > field.base_size * 8;
        component.data_type_id = manager_.create_bitfield(adjusted).id;
    }

    void adjust_zero(std::int32_t ordinal,
                     std::int32_t following_alignment) {
        const auto natural = aligned_offset(following_alignment, group_offset_);
        const auto imposed = aligned_offset(std::max(1, zero_alignment_), group_offset_);
        group_offset_ = std::max(natural, imposed);
        const auto saved = next_ordinal_;
        next_ordinal_ = ordinal;
        update(*last_, group_offset_, 0, following_alignment);
        next_ordinal_ = saved;
    }

    void pack_normal(CompositeComponent &component,
                     std::int32_t minimum_offset) {
        const auto metrics = manager_.data_type_metrics(component.data_type_id, organization_);
        auto length = metrics.zero_length ? 0 : metrics.aligned_length;
        if (length < 0) length = component.length;
        if (length < 0) throw std::invalid_argument("dynamic component requires a use-site length");
        const auto alignment = packed_alignment(metrics.alignment, packing_);
        std::int32_t offset{};
        if (last_ && is_zero_bitfield(*last_)) {
            adjust_zero(next_ordinal_ - 1, alignment);
            offset = group_offset_;
        }
        else {
            offset = aligned_offset(alignment, minimum_offset);
            if (!last_) group_offset_ = offset;
        }
        update(component, offset, length, alignment);
    }

    void pack_bitfield(CompositeComponent &component) {
        auto field = bitfield_info(manager_, component.data_type_id, organization_);
        if (last_ && is_zero_bitfield(*last_)) {
            const auto alignment = organization_.bitfield_use_ms_convention
                                       ? bitfield_alignment(field)
                                       : std::max(1, zero_alignment_);
            adjust_zero(next_ordinal_ - 1, alignment);
        }

        auto conveyed_alignment = packed_alignment(field.base_alignment, packing_);
        last_alignment_ = std::max(last_alignment_, conveyed_alignment);
        std::int32_t offset{};
        std::int32_t bits_consumed{};
        if (!last_) {
            offset = aligned_offset(conveyed_alignment, group_offset_);
            group_offset_ = offset;
        }
        else if (is_zero_bitfield(*last_)) {
            offset = group_offset_;
        }
        else {
            const auto placement_alignment = bitfield_alignment(field);
            std::optional<PackedBitField> previous_field;
            if (is_bitfield(*last_)) {
                previous_field = bitfield_info(manager_, last_->data_type_id, organization_);
                offset = checked_i32(static_cast<std::int64_t>(last_->offset) +
                                         std::max(0, last_->length) - 1,
                                     "bitfield end offset");
                if (endian_ == Endian::big) {
                    bits_consumed = 8 - previous_field->type.bit_offset;
                }
                else {
                    bits_consumed = (previous_field->effective_bits +
                                     previous_field->type.bit_offset) % 8;
                }
                if (bits_consumed == 8 || bits_consumed == 0) {
                    bits_consumed = 0;
                    offset = checked_i32(static_cast<std::int64_t>(offset) + 1,
                                         "bitfield next byte offset");
                }
            }
            else {
                offset = checked_i32(static_cast<std::int64_t>(last_->offset) + last_->length,
                                     "component end offset");
            }

            auto byte_size = (field.effective_bits + bits_consumed + 7) / 8;
            auto end_offset = checked_i32(static_cast<std::int64_t>(offset) + byte_size - 1,
                                          "bitfield end offset");
            if (offset % placement_alignment != 0 || byte_size > field.base_size) {
                const auto aligned_base = aligned_offset(placement_alignment, offset) -
                                          placement_alignment;
                if (end_offset >= aligned_base + field.base_size) {
                    offset = aligned_offset(
                        placement_alignment,
                        checked_i32(static_cast<std::int64_t>(offset) + 1,
                                    "bitfield allocation offset"));
                    bits_consumed = 0;
                    end_offset = checked_i32(
                        static_cast<std::int64_t>(offset) + byte_size - 1,
                        "bitfield allocation end");
                }
            }
            if (group_offset_ >= 0 && previous_field &&
                end_offset >= group_offset_ + previous_field->base_size) {
                group_offset_ = organization_.bitfield_use_ms_convention ? offset : -1;
            }
        }

        const auto byte_size = (field.effective_bits + bits_consumed + 7) / 8;
        const auto bit_offset = endian_ == Endian::big
                                    ? byte_size * 8 - field.effective_bits - bits_consumed
                                    : bits_consumed;
        rewrite_bitfield(component, field, bit_offset);
        update(component, offset, byte_size, conveyed_alignment);
    }

    [[nodiscard]] bool pack_with_previous(CompositeComponent &component) {
        if (!last_ || is_zero_bitfield(component)) return false;
        if (is_bitfield(component)) {
            if (!is_zero_bitfield(*last_) && organization_.bitfield_use_ms_convention) {
                if (!is_bitfield(*last_)) return false;
                const auto current = bitfield_info(manager_, component.data_type_id, organization_);
                const auto previous = bitfield_info(manager_, last_->data_type_id, organization_);
                if (current.base_size != previous.base_size) return false;
            }
            pack_bitfield(component);
            return true;
        }
        if (!is_zero_bitfield(*last_) && organization_.bitfield_use_ms_convention) return false;
        const auto offset = is_zero_bitfield(*last_)
                                ? group_offset_
                                : checked_i32(static_cast<std::int64_t>(last_->offset) +
                                                  last_->length,
                                              "component end offset");
        pack_normal(component, offset);
        return true;
    }

    void start_group(CompositeComponent &component, bool is_last) {
        group_offset_ = packed_length();
        last_alignment_ = 1;
        if (!is_bitfield(component)) {
            last_ = nullptr;
            pack_normal(component, group_offset_);
            return;
        }
        auto field = bitfield_info(manager_, component.data_type_id, organization_);
        if (field.effective_bits != 0) {
            last_ = nullptr;
            pack_bitfield(component);
            return;
        }

        const auto alignment = zero_bitfield_alignment(field, is_last);
        const auto zero_bit_offset = endian_ == Endian::big ? 7 : 0;
        rewrite_bitfield(component, field, zero_bit_offset);
        if (is_last) {
            const auto offset = aligned_offset(field.base_alignment, group_offset_);
            update(component, offset, 0, alignment > 0 ? alignment : 1);
            group_offset_ = -1;
        }
        else {
            zero_alignment_ = alignment;
            if (organization_.bitfield_use_ms_convention) last_alignment_ = alignment;
        }
    }

    void add_component(CompositeComponent &component, bool is_last) {
        if (!pack_with_previous(component)) start_group(component, is_last);
        last_ = &component;
        ++next_ordinal_;
        auto imparted = last_alignment_;
        if (packing_ > 0) imparted = std::min(imparted, packing_);
        if (imparted > 0) component_alignment_lcm_ =
            layout_lcm(component_alignment_lcm_, imparted);
    }

    [[nodiscard]] std::int32_t packed_length() const {
        if (!last_) return 0;
        if (group_offset_ >= 0 && is_bitfield(*last_) &&
            organization_.bitfield_use_ms_convention) {
            const auto field = bitfield_info(manager_, last_->data_type_id, organization_);
            return checked_i32(static_cast<std::int64_t>(group_offset_) + field.base_size,
                               "MS bitfield allocation length");
        }
        auto offset = checked_i32(static_cast<std::int64_t>(last_->offset) + last_->length,
                                  "structure length");
        if (!organization_.bitfield_use_ms_convention && is_zero_bitfield(*last_)) {
            const auto field = bitfield_info(manager_, last_->data_type_id, organization_);
            offset = aligned_offset(field.base_alignment, offset);
        }
        return offset;
    }

    const DataTypeManager &manager_;
    CompositeDataType &composite_;
    const DataOrganization &organization_;
    Endian endian_;
    std::int32_t packing_{};
    std::int32_t next_ordinal_{};
    std::int32_t zero_alignment_{1};
    std::int32_t last_alignment_{1};
    std::int32_t group_offset_{-1};
    std::int32_t component_alignment_lcm_{1};
    CompositeComponent *last_{};
};

void normalize_ordinals(CompositeDataType &value) {
    for (std::size_t index = 0; index < value.components.size(); ++index) {
        value.components[index].ordinal = checked_i32(index, "component ordinal");
    }
}

[[nodiscard]] CompositeDataType require_composite(const DataTypeManager &manager,
                                                  std::int64_t id) {
    const auto value = manager.data_type(id);
    if (!value || !std::holds_alternative<CompositeDataType>(*value)) {
        throw std::out_of_range("composite data type does not exist");
    }
    return std::get<CompositeDataType>(*value);
}

} // namespace

DataTypeMetrics DataTypeManager::data_type_metrics(
    std::int64_t id,
    const DataOrganization &organization) const {
    std::vector<std::int64_t> active;
    return data_type_metrics_impl(id, organization, active);
}

DataTypeMetrics DataTypeManager::data_type_metrics_impl(
    std::int64_t id,
    const DataOrganization &organization,
    std::vector<std::int64_t> &active) const {
    const auto value = data_type(id);
    if (!value) throw std::out_of_range("data type does not exist");
    if (std::ranges::find(active, id) != active.end()) {
        throw std::logic_error("data-type size dependency cycle has no pointer break");
    }

    // Pointer metrics never recurse into the referent and therefore provide
    // the legal break for self-referential composites.
    if (const auto *pointer = std::get_if<PointerDataType>(&*value)) {
        const auto length = pointer->length < 0
                                ? checked_i32(organization.pointer_size, "pointer size")
                                : pointer->length;
        const auto alignment = pointer_alignment(length, organization);
        return {length, length, alignment, false, false};
    }
    if (const auto *builtin = std::get_if<BuiltinDataType>(&*value)) {
        return builtin_metrics(*builtin, organization);
    }
    if (const auto *enumeration = std::get_if<EnumDataType>(&*value)) {
        return fixed_metrics(enumeration->size, organization);
    }
    if (const auto *composite = std::get_if<CompositeDataType>(&*value)) {
        return {composite->length,
                composite->length == 0
                    ? 0
                    : aligned_offset(std::max(1, composite->alignment), composite->length),
                std::max(1, composite->alignment), false, composite->length == 0};
    }
    if (std::holds_alternative<FunctionDefinitionDataType>(*value)) {
        return {-1, -1, 1, true, false};
    }

    active.push_back(id);
    DataTypeMetrics result = std::visit(
        [&](const auto &item) -> DataTypeMetrics {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, ArrayDataType>) {
                const auto element = data_type_metrics_impl(
                    item.element_type_id, organization, active);
                const auto element_length = item.element_length > 0
                                                ? item.element_length
                                                : element.aligned_length;
                if (element_length < 0) return {-1, -1, element.alignment, true, false};
                const auto length = checked_i32(
                    static_cast<std::int64_t>(element_length) * item.element_count,
                    "array length");
                return {length, length, element.alignment,
                        false, length == 0};
            }
            else if constexpr (std::is_same_v<T, TypedefDataType>) {
                return data_type_metrics_impl(item.referenced_type_id, organization, active);
            }
            else if constexpr (std::is_same_v<T, BitFieldDataType>) {
                const auto base = data_type_metrics_impl(item.base_type_id, organization, active);
                if (base.dynamic || base.length <= 0) {
                    throw std::logic_error("bitfield base type has no fixed length");
                }
                const auto bits = std::min<std::int32_t>(
                    item.declared_bit_size,
                    checked_i32(static_cast<std::int64_t>(base.length) * 8,
                                "bitfield width"));
                const auto length = bits == 0 ? 1 : (bits + item.bit_offset + 7) / 8;
                return {length, length, base.alignment, false, bits == 0};
            }
            else {
                throw std::logic_error("unhandled data type in recursive metrics");
            }
        },
        *value);
    active.pop_back();
    return result;
}

CompositeDataType DataTypeManager::layout_composite(
    CompositeDataType value,
    const DataOrganization &organization,
    Endian endian) const {
    if (value.packing < CompositeDataType::no_packing ||
        value.minimum_alignment < CompositeDataType::machine_alignment) {
        throw std::invalid_argument("composite packing controls are invalid");
    }
    normalize_ordinals(value);

    if (value.packing == CompositeDataType::no_packing) {
        std::int32_t maximum_end{};
        for (auto &component : value.components) {
            require_data_type(component.data_type_id);
            const auto metrics = data_type_metrics(component.data_type_id, organization);
            if (component.length <= 0 && !metrics.zero_length) {
                if (metrics.aligned_length < 0) {
                    throw std::invalid_argument(
                        "dynamic component requires a positive use-site length");
                }
                component.length = metrics.aligned_length;
            }
            if (value.is_union) component.offset = 0;
            maximum_end = std::max(
                maximum_end,
                checked_i32(static_cast<std::int64_t>(component.offset) + component.length,
                            "composite component end"));
        }
        value.alignment = minimum_composite_alignment(value, organization);
        value.length = maximum_end;
        return value;
    }

    if (value.is_union) {
        std::int32_t length{};
        std::int32_t alignment_lcm{1};
        for (auto &component : value.components) {
            require_data_type(component.data_type_id);
            component.offset = 0;
            auto metrics = data_type_metrics(component.data_type_id, organization);
            component.length = metrics.zero_length ? 0 :
                (metrics.aligned_length >= 0 ? metrics.aligned_length : component.length);
            if (component.length < 0) {
                throw std::invalid_argument("dynamic union member requires a use-site length");
            }
            auto allocation = component.length;
            if (kind(component.data_type_id) == DataTypeKind::bitfield) {
                const auto field = bitfield_info(*this, component.data_type_id, organization);
                if (organization.bitfield_use_ms_convention) allocation = field.base_size;
                else if (field.effective_bits == 0) allocation = 0;
                else {
                    allocation = field.base_size;
                    if (value.packing > 0 && allocation > value.packing) {
                        allocation = layout_lcm(field.storage_size, value.packing);
                    }
                }
                if (!(field.effective_bits == 0 &&
                      !organization.bitfield_use_ms_convention)) {
                    alignment_lcm = layout_lcm(
                        alignment_lcm, packed_alignment(field.base_alignment, value.packing));
                }
            }
            else {
                alignment_lcm = layout_lcm(
                    alignment_lcm, packed_alignment(metrics.alignment, value.packing));
            }
            length = std::max(length, allocation);
        }
        value.alignment = finish_composite_alignment(alignment_lcm, value, organization);
        value.length = length == 0 ? 0 : aligned_offset(value.alignment, length);
        return value;
    }

    StructurePacker(*this, value, organization, endian).pack();
    return value;
}

CompositeDataType DataTypeManager::repack_composite(
    std::int64_t id,
    const DataOrganization &organization,
    Endian endian,
    DataTypeUpdateMode mode) {
    auto value = layout_composite(require_composite(*this, id), organization, endian);
    auto updated = std::get<CompositeDataType>(update_data_type(std::move(value), mode));
    propagate_data_type_layout(id, organization, endian);
    return updated;
}

DataType DataTypeManager::update_data_type(
    DataType value,
    const DataOrganization &organization,
    Endian endian,
    DataTypeUpdateMode mode) {
    const auto id = data_type_id(value);
    if (auto *composite = std::get_if<CompositeDataType>(&value)) {
        *composite = layout_composite(std::move(*composite), organization, endian);
    }
    else if (auto *array = std::get_if<ArrayDataType>(&value)) {
        const auto element = data_type_metrics(array->element_type_id, organization);
        if (!element.dynamic && element.aligned_length >= 0) {
            array->element_length = element.aligned_length;
        }
    }
    else if (auto *function = std::get_if<FunctionDefinitionDataType>(&value)) {
        for (auto &parameter : function->parameters) {
            const auto metrics = data_type_metrics(parameter.data_type_id, organization);
            if (!metrics.dynamic && metrics.length >= 0) {
                parameter.data_type_length = metrics.length;
            }
        }
    }
    auto updated = update_data_type(std::move(value), mode);
    propagate_data_type_layout(id, organization, endian);
    return updated;
}

CompositeDataType DataTypeManager::insert_component(
    std::int64_t composite_id,
    std::size_t ordinal,
    CompositeComponent component,
    const DataOrganization &organization,
    Endian endian) {
    auto value = require_composite(*this, composite_id);
    if (ordinal > value.components.size()) throw std::out_of_range("component ordinal is invalid");
    require_data_type(component.data_type_id);
    component.id = 0;
    const auto metrics = data_type_metrics(component.data_type_id, organization);
    if (component.length <= 0 && !metrics.zero_length) component.length = metrics.aligned_length;
    if (component.length < 0) {
        throw std::invalid_argument("dynamic component requires a positive use-site length");
    }
    if (value.packing == CompositeDataType::no_packing && !value.is_union) {
        component.offset = ordinal == 0
                               ? 0
                               : checked_i32(static_cast<std::int64_t>(
                                                 value.components[ordinal - 1].offset) +
                                                 value.components[ordinal - 1].length,
                                             "inserted component offset");
        for (std::size_t index = ordinal; index < value.components.size(); ++index) {
            value.components[index].offset = checked_i32(
                static_cast<std::int64_t>(value.components[index].offset) + component.length,
                "shifted component offset");
        }
    }
    value.components.insert(value.components.begin() + static_cast<std::ptrdiff_t>(ordinal),
                            std::move(component));
    normalize_ordinals(value);
    value = layout_composite(std::move(value), organization, endian);
    auto updated = std::get<CompositeDataType>(
        update_data_type(std::move(value), DataTypeUpdateMode::local_change));
    propagate_data_type_layout(composite_id, organization, endian);
    return updated;
}

CompositeDataType DataTypeManager::delete_components(
    std::int64_t composite_id,
    std::vector<std::size_t> ordinals,
    const DataOrganization &organization,
    Endian endian) {
    auto value = require_composite(*this, composite_id);
    std::ranges::sort(ordinals);
    if (std::ranges::adjacent_find(ordinals) != ordinals.end()) {
        throw std::invalid_argument("component ordinals must be unique");
    }
    for (auto iterator = ordinals.rbegin(); iterator != ordinals.rend(); ++iterator) {
        if (*iterator >= value.components.size()) throw std::out_of_range("component ordinal is invalid");
        const auto removed = value.components[*iterator];
        value.components.erase(value.components.begin() + static_cast<std::ptrdiff_t>(*iterator));
        if (value.packing == CompositeDataType::no_packing && !value.is_union) {
            for (auto &component : value.components) {
                if (component.offset > removed.offset) component.offset -= removed.length;
            }
        }
    }
    normalize_ordinals(value);
    value = layout_composite(std::move(value), organization, endian);
    auto updated = std::get<CompositeDataType>(
        update_data_type(std::move(value), DataTypeUpdateMode::local_change));
    propagate_data_type_layout(composite_id, organization, endian);
    return updated;
}

CompositeDataType DataTypeManager::replace_component(
    std::int64_t composite_id,
    std::size_t ordinal,
    CompositeComponent replacement,
    const DataOrganization &organization,
    Endian endian) {
    auto value = require_composite(*this, composite_id);
    if (ordinal >= value.components.size()) throw std::out_of_range("component ordinal is invalid");
    require_data_type(replacement.data_type_id);
    const auto old = value.components[ordinal];
    replacement.id = old.id;
    replacement.ordinal = old.ordinal;
    replacement.offset = old.offset;
    const auto metrics = data_type_metrics(replacement.data_type_id, organization);
    if (replacement.length <= 0 && !metrics.zero_length) replacement.length = metrics.aligned_length;
    if (replacement.length < 0) {
        throw std::invalid_argument("dynamic component requires a positive use-site length");
    }
    value.components[ordinal] = std::move(replacement);
    if (value.packing == CompositeDataType::no_packing && !value.is_union) {
        const auto delta = value.components[ordinal].length - old.length;
        for (std::size_t index = ordinal + 1; index < value.components.size(); ++index) {
            value.components[index].offset = checked_i32(
                static_cast<std::int64_t>(value.components[index].offset) + delta,
                "shifted component offset");
        }
    }
    value = layout_composite(std::move(value), organization, endian);
    auto updated = std::get<CompositeDataType>(
        update_data_type(std::move(value), DataTypeUpdateMode::local_change));
    propagate_data_type_layout(composite_id, organization, endian);
    return updated;
}

CompositeDataType DataTypeManager::reorder_component(
    std::int64_t composite_id,
    std::size_t from_ordinal,
    std::size_t to_ordinal,
    const DataOrganization &organization,
    Endian endian) {
    auto value = require_composite(*this, composite_id);
    if (from_ordinal >= value.components.size() || to_ordinal >= value.components.size()) {
        throw std::out_of_range("component ordinal is invalid");
    }
    auto moved = value.components[from_ordinal];
    value.components.erase(value.components.begin() + static_cast<std::ptrdiff_t>(from_ordinal));
    value.components.insert(value.components.begin() + static_cast<std::ptrdiff_t>(to_ordinal),
                            std::move(moved));
    normalize_ordinals(value);
    if (value.packing == CompositeDataType::no_packing && !value.is_union) {
        std::int32_t offset{};
        for (auto &component : value.components) {
            component.offset = offset;
            offset = checked_i32(static_cast<std::int64_t>(offset) + component.length,
                                 "reordered component offset");
        }
    }
    value = layout_composite(std::move(value), organization, endian);
    auto updated = std::get<CompositeDataType>(
        update_data_type(std::move(value), DataTypeUpdateMode::local_change));
    propagate_data_type_layout(composite_id, organization, endian);
    return updated;
}

CompositeDataType DataTypeManager::set_composite_packing(
    std::int64_t composite_id,
    std::int32_t packing,
    std::int32_t minimum_alignment,
    const DataOrganization &organization,
    Endian endian) {
    if (packing < CompositeDataType::no_packing ||
        minimum_alignment < CompositeDataType::machine_alignment) {
        throw std::invalid_argument("composite packing controls are invalid");
    }
    auto value = require_composite(*this, composite_id);
    value.packing = packing;
    value.minimum_alignment = minimum_alignment;
    value = layout_composite(std::move(value), organization, endian);
    auto updated = std::get<CompositeDataType>(
        update_data_type(std::move(value), DataTypeUpdateMode::local_change));
    propagate_data_type_layout(composite_id, organization, endian);
    return updated;
}

void DataTypeManager::propagate_data_type_layout(
    std::int64_t changed_id,
    const DataOrganization &organization,
    Endian endian) {
    require_mutation();
    require_data_type(changed_id);
    std::vector<std::int64_t> discovery{changed_id};
    std::unordered_set<std::int64_t> affected{changed_id};
    for (std::size_t cursor = 0; cursor < discovery.size(); ++cursor) {
        for (const auto parent_id : parent_data_types(discovery[cursor])) {
            const auto parent = data_type(parent_id);
            if (!parent || std::holds_alternative<PointerDataType>(*parent)) continue;
            if (affected.insert(parent_id).second) discovery.push_back(parent_id);
        }
    }

    std::unordered_set<std::int64_t> processed{changed_id};
    while (processed.size() < affected.size()) {
        bool made_progress = false;
        for (const auto parent_id : discovery) {
            if (processed.contains(parent_id)) continue;
            bool children_ready = true;
            for (const auto child_id : child_data_types(parent_id)) {
                if (affected.contains(child_id) && !processed.contains(child_id)) {
                    children_ready = false;
                    break;
                }
            }
            if (!children_ready) continue;

            auto parent = data_type(parent_id);
            if (!parent) {
                processed.insert(parent_id);
                made_progress = true;
                continue;
            }
            bool layout_changed = false;
            if (auto *array = std::get_if<ArrayDataType>(&*parent)) {
                const auto element = data_type_metrics(array->element_type_id, organization);
                if (!element.dynamic && element.aligned_length >= 0 &&
                    array->element_length != element.aligned_length) {
                    array->element_length = element.aligned_length;
                    layout_changed = true;
                }
            }
            else if (std::holds_alternative<TypedefDataType>(*parent)) {
                // Typedef has no stored length, but its parents observe the base
                // type's new metrics and must remain in the closure.
            }
            else if (auto *composite = std::get_if<CompositeDataType>(&*parent)) {
                const auto before_length = composite->length;
                const auto before_alignment = composite->alignment;
                const auto before_components = composite->components;
                if (composite->packing == CompositeDataType::no_packing) {
                    for (std::size_t index = 0; index < composite->components.size(); ++index) {
                        auto &component = composite->components[index];
                        const auto metrics = data_type_metrics(
                            component.data_type_id, organization);
                        if (metrics.dynamic || metrics.aligned_length < 0 ||
                            metrics.zero_length ||
                            component.length == metrics.aligned_length) {
                            continue;
                        }
                        const auto delta = metrics.aligned_length - component.length;
                        component.length = metrics.aligned_length;
                        if (!composite->is_union) {
                            for (std::size_t following = index + 1;
                                 following < composite->components.size(); ++following) {
                                composite->components[following].offset = checked_i32(
                                    static_cast<std::int64_t>(
                                        composite->components[following].offset) + delta,
                                    "propagated component offset");
                            }
                        }
                    }
                }
                *composite = layout_composite(std::move(*composite), organization, endian);
                layout_changed = before_length != composite->length ||
                                 before_alignment != composite->alignment ||
                                 before_components != composite->components;
            }
            else if (auto *function = std::get_if<FunctionDefinitionDataType>(&*parent)) {
                for (auto &parameter : function->parameters) {
                    const auto metrics = data_type_metrics(parameter.data_type_id, organization);
                    if (!metrics.dynamic && metrics.length >= 0 &&
                        parameter.data_type_length != metrics.length) {
                        parameter.data_type_length = metrics.length;
                        layout_changed = true;
                    }
                }
            }
            if (layout_changed) {
                (void)update_data_type(std::move(*parent),
                                       DataTypeUpdateMode::preserve_timestamps);
            }
            processed.insert(parent_id);
            made_progress = true;
        }
        if (!made_progress) {
            throw std::logic_error(
                "data-type layout propagation graph contains a non-pointer cycle");
        }
    }
    if (!deduplicating_automatic_types_) {
        deduplicating_automatic_types_ = true;
        try {
            deduplicate_automatic_data_types(changed_id);
            deduplicating_automatic_types_ = false;
        }
        catch (...) {
            deduplicating_automatic_types_ = false;
            throw;
        }
    }
}

} // namespace llmghidra::program
