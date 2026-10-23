#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cctype>
#include <limits>
#include <sstream>

namespace llmghidra::program {
namespace {

[[nodiscard]] bool ascii_equal(const std::string &lhs,
                               const std::string &rhs,
                               bool case_sensitive) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    if (case_sensitive) {
        return lhs == rhs;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        const auto left = static_cast<unsigned char>(lhs[i]);
        const auto right = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(left) != std::tolower(right)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::uint32_t unit_shift(std::uint32_t unit_size) {
    switch (unit_size) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
        return 2;
    case 8:
        return 3;
    default:
        throw std::invalid_argument("addressable unit size must be 1, 2, 4, or 8");
    }
}

[[nodiscard]] std::int64_t as_signed(std::uint64_t value) noexcept {
    return std::bit_cast<std::int64_t>(value);
}

[[nodiscard]] std::uint64_t parse_hex(const std::string &text) {
    if (text.empty() || text.size() > 16) {
        throw AddressFormatError("invalid hexadecimal address offset: " + text);
    }
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (error != std::errc{} || end != text.data() + text.size()) {
        throw AddressFormatError("invalid hexadecimal address offset: " + text);
    }
    return value;
}

[[nodiscard]] Address apply_unsigned_delta(const AddressSpace &space,
                                           const Address &address,
                                           bool subtract,
                                           std::uint64_t magnitude,
                                           bool wrap) {
    const std::uint64_t current = address.offset();
    if (!wrap) {
        if (subtract) {
            if (current < space.min_offset() || current - space.min_offset() < magnitude) {
                throw AddressOverflowError("address subtraction crosses the address-space minimum");
            }
        }
        else if (current > space.max_offset() || space.max_offset() - current < magnitude) {
            throw AddressOverflowError("address addition crosses the address-space maximum");
        }
    }
    const std::uint64_t result = subtract ? current - magnitude : current + magnitude;
    return wrap ? space.truncated_address(result, false) : space.address_in_this_space(result);
}

[[nodiscard]] Address apply_signed_delta(const AddressSpace &space,
                                         const Address &address,
                                         bool subtract,
                                         std::uint64_t magnitude,
                                         bool wrap) {
    const std::uint64_t current = address.offset();
    if (!wrap) {
        const std::int64_t signed_current = as_signed(current);
        const std::int64_t signed_minimum = as_signed(space.min_offset());
        const std::int64_t signed_maximum = as_signed(space.max_offset());
        if (subtract) {
            const std::uint64_t available =
                current - std::bit_cast<std::uint64_t>(signed_minimum);
            if (magnitude > available) {
                throw AddressOverflowError("address subtraction crosses the address-space minimum");
            }
        }
        else {
            const std::uint64_t available =
                std::bit_cast<std::uint64_t>(signed_maximum) - current;
            if (magnitude > available) {
                throw AddressOverflowError("address addition crosses the address-space maximum");
            }
        }
        (void)signed_current;
    }
    const std::uint64_t result = subtract ? current - magnitude : current + magnitude;
    return wrap ? space.truncated_address(result, false) : space.address_in_this_space(result);
}

} // namespace

std::shared_ptr<AddressSpace> AddressSpace::create(Config config) {
    return std::shared_ptr<AddressSpace>(new AddressSpace(std::move(config)));
}

std::shared_ptr<AddressSpace> AddressSpace::create_overlay(
    std::string name,
    std::shared_ptr<const AddressSpace> base_space,
    std::uint32_t unique,
    std::vector<std::pair<std::uint64_t, std::uint64_t>> regions,
    std::string ordered_key) {
    if (!base_space) {
        throw std::invalid_argument("overlay address space requires a base space");
    }
    return std::shared_ptr<AddressSpace>(new AddressSpace(
        std::move(name), std::move(base_space), unique, std::move(regions),
        std::move(ordered_key)));
}

std::shared_ptr<AddressSpace> AddressSpace::create_segmented(std::string name,
                                                            std::uint32_t unique) {
    Config config;
    config.name = std::move(name);
    config.size_bits = 21;
    config.addressable_unit_size = 1;
    config.type = AddressSpaceType::ram;
    config.unique = unique;
    config.kind = AddressSpaceKind::segmented_real_mode;
    return create(std::move(config));
}

std::shared_ptr<AddressSpace> AddressSpace::create_protected_segmented(
    std::string name,
    std::uint32_t unique) {
    Config config;
    config.name = std::move(name);
    config.size_bits = 32;
    config.addressable_unit_size = 1;
    config.type = AddressSpaceType::ram;
    config.unique = unique;
    config.kind = AddressSpaceKind::segmented_protected_mode;
    return create(std::move(config));
}

AddressSpace::AddressSpace(Config config)
    : name_(std::move(config.name)),
      size_bits_(config.size_bits),
      unit_size_(config.addressable_unit_size),
      type_(config.type),
      kind_(config.kind),
      unique_(config.unique),
      show_name_(config.show_space_name.value_or(config.type != AddressSpaceType::ram)),
      mapped_registers_(config.has_mapped_registers) {
    validate_and_initialize();
}

AddressSpace::AddressSpace(
    std::string name,
    std::shared_ptr<const AddressSpace> base_space,
    std::uint32_t unique,
    std::vector<std::pair<std::uint64_t, std::uint64_t>> regions,
    std::string ordered_key)
    : name_(std::move(name)),
      size_bits_(base_space->size()),
      unit_size_(base_space->addressable_unit_size()),
      type_(base_space->type()),
      unique_(unique),
      show_name_(true),
      base_space_(std::move(base_space)),
      overlay_regions_(std::move(regions)),
      ordered_key_(std::move(ordered_key)) {
    if (ordered_key_.empty()) {
        ordered_key_ = name_;
    }
    validate_and_initialize();
    normalize_overlay_regions();
}

void AddressSpace::validate_and_initialize() {
    if (name_.empty()) {
        throw std::invalid_argument("address-space name must not be empty");
    }
    if (type_ == AddressSpaceType::none) {
        size_bits_ = 0;
        unit_size_ = 1;
        unique_ = 0;
        min_offset_ = max_offset_ = 0;
        byte_span_ = 1;
        word_mask_ = 0;
        space_id_ = -1;
        signed_offset_ = false;
        return;
    }
    if (size_bits_ == 0 || size_bits_ > 64) {
        throw std::invalid_argument("address-space size must be between 1 and 64 bits");
    }
    if (unique_ > static_cast<std::uint32_t>(std::numeric_limits<std::int16_t>::max())) {
        throw std::invalid_argument("unique address-space id must fit in a signed 16-bit value");
    }
    const std::uint32_t shift = unit_shift(unit_size_);
    if (size_bits_ + shift > 64) {
        throw std::invalid_argument("address-space size and unit size exceed 64 offset bits");
    }

    const std::uint32_t byte_bits = size_bits_ + shift;
    byte_span_ = byte_bits == 64 ? 0 : (std::uint64_t{1} << byte_bits);
    word_mask_ = size_bits_ == 64 ? std::numeric_limits<std::uint64_t>::max()
                                  : (std::uint64_t{1} << size_bits_) - 1;
    signed_offset_ = type_ == AddressSpaceType::constant || type_ == AddressSpaceType::stack;
    if (signed_offset_) {
        if (byte_span_ == 0) {
            min_offset_ = std::bit_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::min());
            max_offset_ = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
        }
        else {
            const std::uint64_t half = byte_span_ >> 1;
            min_offset_ = 0U - half;
            max_offset_ = half - 1;
        }
    }
    else {
        min_offset_ = 0;
        max_offset_ = byte_span_ == 0 ? std::numeric_limits<std::uint64_t>::max()
                                     : byte_span_ - 1;
    }
    if (kind_ == AddressSpaceKind::segmented_real_mode) {
        if (size_bits_ != 21 || unit_size_ != 1 ||
            type_ != AddressSpaceType::ram || base_space_) {
            throw std::invalid_argument(
                "real-mode segmented spaces must be 21-bit byte-addressed RAM spaces");
        }
        max_offset_ = 0x10ffefULL;
        byte_span_ = max_offset_ + 1;
    }
    else if (kind_ == AddressSpaceKind::segmented_protected_mode &&
             (size_bits_ != 32 || unit_size_ != 1 ||
              type_ != AddressSpaceType::ram || base_space_)) {
        throw std::invalid_argument(
            "protected-mode segmented spaces must be 32-bit byte-addressed RAM spaces");
    }

    std::uint32_t log_size = 7;
    switch (size_bits_) {
    case 8:
        log_size = 0;
        break;
    case 16:
        log_size = 1;
        break;
    case 32:
        log_size = 2;
        break;
    case 64:
        log_size = 3;
        break;
    default:
        break;
    }
    space_id_ = static_cast<std::int32_t>(
        (unique_ << id_unique_shift) | (log_size << id_size_shift) |
        static_cast<std::uint32_t>(type_));
}

void AddressSpace::normalize_overlay_regions() {
    for (const auto &[first, second] : overlay_regions_) {
        make_valid_offset(first);
        make_valid_offset(second);
        if (first > second) {
            throw std::invalid_argument("overlay region start exceeds end");
        }
    }
    std::ranges::sort(overlay_regions_);
    std::vector<std::pair<std::uint64_t, std::uint64_t>> normalized;
    for (const auto &region : overlay_regions_) {
        if (normalized.empty() ||
            (normalized.back().second != std::numeric_limits<std::uint64_t>::max() &&
             region.first > normalized.back().second + 1)) {
            normalized.push_back(region);
        }
        else {
            normalized.back().second = std::max(normalized.back().second, region.second);
        }
    }
    overlay_regions_ = std::move(normalized);
}

const std::string &AddressSpace::name() const noexcept { return name_; }
std::uint32_t AddressSpace::size() const noexcept { return size_bits_; }
std::uint32_t AddressSpace::addressable_unit_size() const noexcept { return unit_size_; }
std::uint32_t AddressSpace::pointer_size() const noexcept {
    return is_segmented_space() ? 2U : (size_bits_ + 7U) / 8U;
}
AddressSpaceType AddressSpace::type() const noexcept { return type_; }
std::uint32_t AddressSpace::unique() const noexcept { return unique_; }
std::int32_t AddressSpace::space_id() const noexcept { return space_id_; }
bool AddressSpace::has_signed_offset() const noexcept { return signed_offset_; }
bool AddressSpace::show_space_name() const noexcept { return show_name_; }
bool AddressSpace::has_mapped_registers() const noexcept {
    return base_space_ ? base_space_->has_mapped_registers() : mapped_registers_;
}

bool AddressSpace::is_memory_space() const noexcept {
    return type_ == AddressSpaceType::ram || type_ == AddressSpaceType::code ||
           type_ == AddressSpaceType::other || type_ == AddressSpaceType::deleted;
}
bool AddressSpace::is_loaded_memory_space() const noexcept {
    return type_ == AddressSpaceType::ram || type_ == AddressSpaceType::code;
}
bool AddressSpace::is_non_loaded_memory_space() const noexcept {
    return type_ == AddressSpaceType::other;
}
bool AddressSpace::is_register_space() const noexcept { return type_ == AddressSpaceType::reg; }
bool AddressSpace::is_stack_space() const noexcept { return type_ == AddressSpaceType::stack; }
bool AddressSpace::is_unique_space() const noexcept { return type_ == AddressSpaceType::unique; }
bool AddressSpace::is_constant_space() const noexcept { return type_ == AddressSpaceType::constant; }
bool AddressSpace::is_variable_space() const noexcept { return type_ == AddressSpaceType::variable; }
bool AddressSpace::is_external_space() const noexcept { return type_ == AddressSpaceType::external; }
bool AddressSpace::is_overlay_space() const noexcept { return static_cast<bool>(base_space_); }
bool AddressSpace::is_segmented_space() const noexcept {
    return kind_ == AddressSpaceKind::segmented_real_mode ||
           kind_ == AddressSpaceKind::segmented_protected_mode;
}

std::uint64_t AddressSpace::min_offset() const noexcept { return min_offset_; }
std::uint64_t AddressSpace::max_offset() const noexcept { return max_offset_; }
Address AddressSpace::min_address() const { return unchecked_address(min_offset_); }
Address AddressSpace::max_address() const { return unchecked_address(max_offset_); }

std::uint64_t AddressSpace::addressable_word_offset(std::uint64_t byte_offset) const noexcept {
    if (signed_offset_ && as_signed(byte_offset) < 0) {
        const std::uint64_t magnitude = 0U - byte_offset;
        return 0U - (magnitude / unit_size_);
    }
    return byte_offset / unit_size_;
}

std::uint64_t AddressSpace::truncate_offset(std::uint64_t byte_offset) const noexcept {
    if (byte_span_ == 0) {
        return byte_offset;
    }
    if (!signed_offset_) {
        return byte_offset % byte_span_;
    }
    const std::uint64_t truncated = byte_offset & (byte_span_ - 1);
    const std::uint64_t sign_bit = byte_span_ >> 1;
    return (truncated & sign_bit) != 0 ? truncated | ~(byte_span_ - 1) : truncated;
}

std::uint64_t AddressSpace::truncate_addressable_word_offset(std::uint64_t word_offset) const noexcept {
    return word_offset & word_mask_;
}

std::uint64_t AddressSpace::make_valid_offset(std::uint64_t byte_offset) const {
    if (byte_span_ == 0) {
        return byte_offset;
    }
    if (!signed_offset_) {
        if (byte_offset <= max_offset_) {
            return byte_offset;
        }
        const std::int64_t signed_value = as_signed(byte_offset);
        const std::int64_t negative_limit = -static_cast<std::int64_t>(max_offset_) - 1;
        if (signed_value < 0 && signed_value >= negative_limit) {
            return byte_offset + byte_span_;
        }
    }
    else {
        const std::int64_t signed_value = as_signed(byte_offset);
        if (signed_value >= as_signed(min_offset_) && signed_value <= as_signed(max_offset_)) {
            return byte_offset;
        }
        if (byte_offset > max_offset_ && byte_offset < byte_span_) {
            return byte_offset - byte_span_;
        }
    }
    throw AddressOutOfBoundsError("address offset is outside space " + name_);
}

bool AddressSpace::is_valid_range(std::uint64_t byte_offset, std::uint64_t length) const noexcept {
    if (length == 0) {
        return false;
    }
    try {
        const Address first = address(byte_offset);
        if (signed_offset_) {
            (void)apply_signed_delta(*this, first, false, length - 1, false);
        }
        else {
            (void)apply_unsigned_delta(*this, first, false, length - 1, false);
        }
        return true;
    }
    catch (const AddressError &) {
        return false;
    }
}

Address AddressSpace::address(std::uint64_t byte_offset) const {
    const std::uint64_t valid = make_valid_offset(byte_offset);
    if (base_space_ && !contains_overlay_offset(valid)) {
        return base_space_->address(valid);
    }
    return unchecked_address(valid);
}

Address AddressSpace::address_signed(std::int64_t byte_offset) const {
    return address(std::bit_cast<std::uint64_t>(byte_offset));
}

Address AddressSpace::address(std::uint64_t offset, bool addressable_word) const {
    return address(addressable_word ? offset * unit_size_ : offset);
}

Address AddressSpace::truncated_address(std::uint64_t offset, bool addressable_word) const {
    if (addressable_word) {
        return address(truncate_addressable_word_offset(offset), true);
    }
    return address_in_this_space(truncate_offset(offset));
}

Address AddressSpace::address_in_this_space(std::uint64_t byte_offset) const {
    return unchecked_address(make_valid_offset(byte_offset));
}

Address AddressSpace::segmented_address(std::uint16_t segment,
                                        std::uint16_t offset) const {
    if (!is_segmented_space()) {
        throw std::logic_error("address space is not segmented");
    }
    const std::uint64_t flat = kind_ == AddressSpaceKind::segmented_protected_mode
        ? (static_cast<std::uint64_t>(segment) << 16) + offset
        : (static_cast<std::uint64_t>(segment) << 4) + offset;
    make_valid_offset(flat);
    return Address(shared_from_this(), flat, segment);
}

std::optional<Address> AddressSpace::address_in_segment(
    std::uint64_t flat_offset,
    std::uint16_t preferred_segment) const {
    if (!is_segmented_space()) {
        throw std::logic_error("address space is not segmented");
    }
    if (kind_ == AddressSpaceKind::segmented_protected_mode) {
        return std::nullopt;
    }
    const std::uint64_t base = static_cast<std::uint64_t>(preferred_segment) << 4;
    if (base > flat_offset || flat_offset - base > 0xffffULL) {
        return std::nullopt;
    }
    return segmented_address(preferred_segment,
                             static_cast<std::uint16_t>(flat_offset - base));
}

std::uint16_t AddressSpace::default_segment(std::uint64_t flat_offset) const {
    if (!is_segmented_space()) {
        throw std::logic_error("address space is not segmented");
    }
    if (kind_ == AddressSpaceKind::segmented_protected_mode) {
        return static_cast<std::uint16_t>(flat_offset >> 16);
    }
    return flat_offset > 0xfffffULL
               ? static_cast<std::uint16_t>(0xffff)
               : static_cast<std::uint16_t>((flat_offset >> 4) & 0xf000ULL);
}

std::uint16_t AddressSpace::segment_offset(std::uint64_t flat_offset,
                                           std::uint16_t segment) const {
    if (!is_segmented_space()) {
        throw std::logic_error("address space is not segmented");
    }
    if (kind_ == AddressSpaceKind::segmented_protected_mode) {
        return static_cast<std::uint16_t>(flat_offset & 0xffffULL);
    }
    const std::uint64_t base = static_cast<std::uint64_t>(segment) << 4;
    if (flat_offset < base || flat_offset - base > 0xffffULL) {
        throw AddressOutOfBoundsError("flat address cannot be represented by the segment");
    }
    return static_cast<std::uint16_t>(flat_offset - base);
}

std::optional<Address> AddressSpace::parse_address(const std::string &input,
                                                   bool case_sensitive) const {
    std::string text = input;
    if (base_space_) {
        for (std::size_t position = 0; (position = text.find("::", position)) != std::string::npos;) {
            text.replace(position, 2, ":");
        }
    }
    if (is_stack_space() && text.size() > 7 && text.starts_with("Stack[") && text.ends_with(']')) {
        text = text.substr(6, text.size() - 7);
    }

    if (is_segmented_space()) {
        std::vector<std::string> parts;
        std::size_t start = 0;
        for (std::size_t colon = 0; (colon = text.find(':', start)) != std::string::npos;) {
            parts.push_back(text.substr(start, colon - start));
            start = colon + 1;
        }
        parts.push_back(text.substr(start));
        if (parts.size() == 3) {
            if (!ascii_equal(name_, parts[0], case_sensitive)) {
                return std::nullopt;
            }
            parts.erase(parts.begin());
        }
        else if (parts.size() == 2 && ascii_equal(name_, parts[0], case_sensitive)) {
            parts.erase(parts.begin());
        }
        if (parts.size() == 2) {
            auto clean = [](std::string value) {
                if (value.starts_with("0x") || value.starts_with("0X")) {
                    value.erase(0, 2);
                }
                return value;
            };
            const std::uint64_t segment_value = parse_hex(clean(parts[0]));
            const std::uint64_t offset_value = parse_hex(clean(parts[1]));
            if (segment_value > 0xffff || offset_value > 0xffff) {
                throw AddressFormatError("segmented address component exceeds 16 bits: " + input);
            }
            return segmented_address(static_cast<std::uint16_t>(segment_value),
                                     static_cast<std::uint16_t>(offset_value));
        }
        if (parts.size() != 1) {
            throw AddressFormatError("invalid segmented address: " + input);
        }
        std::string flat = parts[0];
        if (flat.starts_with("0x") || flat.starts_with("0X")) {
            flat.erase(0, 2);
        }
        return address(parse_hex(flat));
    }

    std::string offset_text = text;
    if (const std::size_t colon = text.rfind(':'); colon != std::string::npos) {
        if (!ascii_equal(name_, text.substr(0, colon), case_sensitive)) {
            return std::nullopt;
        }
        offset_text = text.substr(colon + 1);
    }

    bool negative = false;
    if (!offset_text.empty() && (offset_text.front() == '+' || offset_text.front() == '-')) {
        negative = offset_text.front() == '-';
        offset_text.erase(offset_text.begin());
    }
    if (offset_text.starts_with("0x") || offset_text.starts_with("0X")) {
        offset_text.erase(0, 2);
    }

    std::uint64_t unit_remainder = 0;
    if (const std::size_t dot = offset_text.find('.'); dot != std::string::npos) {
        if (unit_size_ == 1 || dot == 0 || offset_text.find('.', dot + 1) != std::string::npos) {
            throw AddressFormatError("invalid addressable-unit suffix: " + input);
        }
        unit_remainder = parse_hex(offset_text.substr(dot + 1));
        if (unit_remainder >= unit_size_) {
            throw AddressFormatError("addressable-unit suffix exceeds unit size: " + input);
        }
        offset_text.resize(dot);
    }

    const std::uint64_t word = parse_hex(offset_text);
    if (word > (std::numeric_limits<std::uint64_t>::max() - unit_remainder) / unit_size_) {
        throw AddressFormatError("address offset exceeds 64 bits: " + input);
    }
    std::uint64_t offset = word * unit_size_ + unit_remainder;
    if (negative) {
        offset = 0U - offset;
    }
    try {
        return address_in_this_space(offset);
    }
    catch (const AddressOutOfBoundsError &error) {
        throw AddressFormatError(error.what());
    }
}

void AddressSpace::require_same_space(const Address &address) const {
    if (!address.is_valid() || !equivalent(*address.space())) {
        throw std::invalid_argument("address does not belong to space " + name_);
    }
}

Address AddressSpace::unchecked_address(std::uint64_t offset) const {
    if (is_segmented_space()) {
        return Address(shared_from_this(), offset, default_segment(offset));
    }
    return Address(shared_from_this(), offset);
}

Address AddressSpace::add_wrap(const Address &address, std::int64_t displacement) const {
    require_same_space(address);
    const bool subtract = displacement < 0;
    const std::uint64_t magnitude = subtract ? 0U - static_cast<std::uint64_t>(displacement)
                                             : static_cast<std::uint64_t>(displacement);
    return signed_offset_ ? apply_signed_delta(*this, address, subtract, magnitude, true)
                          : apply_unsigned_delta(*this, address, subtract, magnitude, true);
}

Address AddressSpace::subtract_wrap(const Address &address, std::int64_t displacement) const {
    require_same_space(address);
    const bool subtract = displacement >= 0;
    const std::uint64_t magnitude = subtract ? static_cast<std::uint64_t>(displacement)
                                             : 0U - static_cast<std::uint64_t>(displacement);
    return signed_offset_ ? apply_signed_delta(*this, address, subtract, magnitude, true)
                          : apply_unsigned_delta(*this, address, subtract, magnitude, true);
}

Address AddressSpace::add_no_wrap(const Address &address, std::int64_t displacement) const {
    require_same_space(address);
    const bool subtract = displacement < 0;
    const std::uint64_t magnitude = subtract ? 0U - static_cast<std::uint64_t>(displacement)
                                             : static_cast<std::uint64_t>(displacement);
    return signed_offset_ ? apply_signed_delta(*this, address, subtract, magnitude, false)
                          : apply_unsigned_delta(*this, address, subtract, magnitude, false);
}

Address AddressSpace::subtract_no_wrap(const Address &address, std::int64_t displacement) const {
    require_same_space(address);
    const bool subtract = displacement >= 0;
    const std::uint64_t magnitude = subtract ? static_cast<std::uint64_t>(displacement)
                                             : 0U - static_cast<std::uint64_t>(displacement);
    return signed_offset_ ? apply_signed_delta(*this, address, subtract, magnitude, false)
                          : apply_unsigned_delta(*this, address, subtract, magnitude, false);
}

std::int64_t AddressSpace::subtract(const Address &lhs, const Address &rhs) const {
    require_same_space(lhs);
    if (!rhs.is_valid()) {
        throw std::invalid_argument("cannot subtract NO_ADDRESS");
    }
    if (!equivalent(*rhs.space())) {
        const auto left_physical = physical_space();
        const auto right_physical = rhs.space()->physical_space();
        if (!left_physical->equivalent(*right_physical)) {
            throw std::invalid_argument("addresses are in unrelated address spaces");
        }
    }
    return as_signed(lhs.offset() - rhs.offset());
}

bool AddressSpace::is_successor(const Address &first, const Address &second) const noexcept {
    return first.same_space(second) && first.offset() != max_offset_ &&
           first.offset() + 1 == second.offset();
}

bool AddressSpace::contains_overlay_offset(std::uint64_t offset) const noexcept {
    if (!base_space_) {
        return false;
    }
    const auto found = std::ranges::lower_bound(
        overlay_regions_, offset, {}, [](const auto &region) { return region.second; });
    return found != overlay_regions_.end() && found->first <= offset;
}

const std::vector<std::pair<std::uint64_t, std::uint64_t>> &
AddressSpace::overlay_regions() const noexcept {
    return overlay_regions_;
}

void AddressSpace::set_overlay_regions(
    std::vector<std::pair<std::uint64_t, std::uint64_t>> regions) {
    if (!base_space_) {
        throw std::logic_error("only overlay spaces have overlay regions");
    }
    overlay_regions_ = std::move(regions);
    normalize_overlay_regions();
}

std::shared_ptr<const AddressSpace> AddressSpace::physical_space() const {
    return base_space_ ? base_space_->physical_space() : shared_from_this();
}

std::shared_ptr<const AddressSpace> AddressSpace::overlayed_space() const noexcept {
    return base_space_;
}

Address AddressSpace::overlay_address(const Address &input) const {
    if (base_space_ && input.is_valid() && base_space_->equivalent(*input.space()) &&
        contains_overlay_offset(input.offset())) {
        return unchecked_address(input.offset());
    }
    return input;
}

Address AddressSpace::translate_overlay_address(const Address &input, bool force) const {
    if (!base_space_ || !input.is_valid()) {
        return input;
    }
    if (!force && contains_overlay_offset(input.offset())) {
        return input;
    }
    return base_space_->address_in_this_space(input.offset());
}

const std::string &AddressSpace::ordered_key() const noexcept { return ordered_key_; }
void AddressSpace::set_show_space_name(bool show) noexcept { show_name_ = show; }
void AddressSpace::set_has_mapped_registers(bool present) noexcept { mapped_registers_ = present; }

void AddressSpace::rename_overlay(std::string new_name) {
    if (!base_space_) {
        throw std::logic_error("only overlay spaces may be renamed");
    }
    if (new_name.empty()) {
        throw std::invalid_argument("overlay name must not be empty");
    }
    name_ = std::move(new_name);
}

bool AddressSpace::equivalent(const AddressSpace &other) const noexcept {
    if (this == &other) {
        return true;
    }
    if (is_overlay_space() != other.is_overlay_space()) {
        return false;
    }
    if (base_space_) {
        return type_ == other.type_ && size_bits_ == other.size_bits_ &&
               ordered_key_ == other.ordered_key_ &&
               base_space_->equivalent(*other.base_space_);
    }
    return type_ == other.type_ && size_bits_ == other.size_bits_ && name_ == other.name_;
}

std::strong_ordering AddressSpace::compare(const AddressSpace &other) const noexcept {
    if (equivalent(other)) {
        return std::strong_ordering::equal;
    }
    if (is_overlay_space() != other.is_overlay_space()) {
        return is_overlay_space() ? std::strong_ordering::greater : std::strong_ordering::less;
    }
    if (base_space_) {
        if (const auto base_order = base_space_->compare(*other.base_space_); base_order != 0) {
            return base_order;
        }
        if (type_ != other.type_) {
            return static_cast<std::uint8_t>(type_) <=> static_cast<std::uint8_t>(other.type_);
        }
        return ordered_key_ <=> other.ordered_key_;
    }
    if (space_id_ != other.space_id_) {
        return space_id_ <=> other.space_id_;
    }
    if (name_ != other.name_) {
        return name_ <=> other.name_;
    }
    if (type_ != other.type_) {
        return static_cast<std::uint8_t>(type_) <=> static_cast<std::uint8_t>(other.type_);
    }
    return size_bits_ <=> other.size_bits_;
}

const std::shared_ptr<AddressSpace> &other_space() {
    static const auto value = AddressSpace::create({"OTHER", 64, 1, AddressSpaceType::other, 1});
    return value;
}
const std::shared_ptr<AddressSpace> &external_space() {
    static const auto value = AddressSpace::create({"EXTERNAL", 32, 1, AddressSpaceType::external, 0});
    return value;
}
const std::shared_ptr<AddressSpace> &variable_space() {
    static const auto value = AddressSpace::create({"VARIABLE", 32, 1, AddressSpaceType::variable, 0});
    return value;
}
const std::shared_ptr<AddressSpace> &hash_space() {
    static const auto value = AddressSpace::create({"HASH", 60, 1, AddressSpaceType::unknown, 0});
    return value;
}
const std::shared_ptr<AddressSpace> &default_register_space() {
    static const auto value = AddressSpace::create({"REGISTER", 32, 1, AddressSpaceType::reg, 0});
    return value;
}

} // namespace llmghidra::program
