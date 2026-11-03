#include "llmghidra/program/address.hpp"

#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <iomanip>
#include <limits>
#include <sstream>

namespace llmghidra::program {

bool AddressCount::is_zero() const noexcept {
    return high == 0 && low == 0;
}

bool AddressCount::fits_uint64() const noexcept {
    return high == 0;
}

std::uint64_t AddressCount::to_uint64() const {
    if (!fits_uint64()) {
        throw std::overflow_error("address count does not fit in uint64_t");
    }
    return low;
}

std::string AddressCount::to_string() const {
    if (is_zero()) {
        return "0";
    }

    std::array<std::uint32_t, 4> limbs{
        static_cast<std::uint32_t>(high >> 32),
        static_cast<std::uint32_t>(high),
        static_cast<std::uint32_t>(low >> 32),
        static_cast<std::uint32_t>(low),
    };
    std::string digits;
    while (std::ranges::any_of(limbs, [](std::uint32_t limb) { return limb != 0; })) {
        std::uint64_t remainder = 0;
        for (auto &limb : limbs) {
            const std::uint64_t value = (remainder << 32) | limb;
            limb = static_cast<std::uint32_t>(value / 10);
            remainder = value % 10;
        }
        digits.push_back(static_cast<char>('0' + remainder));
    }
    std::ranges::reverse(digits);
    return digits;
}

AddressCount &AddressCount::operator+=(AddressCount other) noexcept {
    const std::uint64_t old_low = low;
    low += other.low;
    high += other.high + (low < old_low ? 1U : 0U);
    return *this;
}

AddressCount &AddressCount::operator-=(AddressCount other) {
    if (*this < other) {
        throw std::underflow_error("negative address count");
    }
    const std::uint64_t old_low = low;
    low -= other.low;
    high -= other.high + (old_low < other.low ? 1U : 0U);
    return *this;
}

Address Address::no_address() noexcept {
    return {};
}

Address Address::external_entry_address() {
    static const auto space = AddressSpace::create(
        {"Entry Point", 0, 1, AddressSpaceType::none, 0});
    return space->address(0);
}

Address::Address(std::shared_ptr<const AddressSpace> space,
                 std::uint64_t offset,
                 std::optional<std::uint16_t> segment) noexcept
    : space_(std::move(space)), offset_(offset), segment_(segment) {}

bool Address::is_valid() const noexcept {
    return static_cast<bool>(space_);
}

bool Address::is_external_entry_address() const noexcept {
    return space_ && space_->type() == AddressSpaceType::none &&
           space_->name() == "Entry Point";
}

const std::shared_ptr<const AddressSpace> &Address::space() const noexcept {
    return space_;
}

std::uint64_t Address::offset() const noexcept {
    return offset_;
}

std::int64_t Address::signed_offset() const noexcept {
    return std::bit_cast<std::int64_t>(offset_);
}

std::uint64_t Address::addressable_word_offset() const {
    if (!space_) {
        throw AddressError("NO_ADDRESS has no addressable offset");
    }
    return space_->addressable_word_offset(offset_);
}

std::uint32_t Address::pointer_size() const {
    if (!space_) {
        throw AddressError("NO_ADDRESS has no pointer size");
    }
    return space_->pointer_size();
}

std::optional<std::uint16_t> Address::segment() const noexcept {
    return segment_;
}

std::optional<std::uint16_t> Address::segment_offset() const noexcept {
    if (!space_ || !segment_) {
        return std::nullopt;
    }
    return space_->segment_offset(offset_, *segment_);
}

Address Address::normalize_segment(std::uint16_t segment_value) const {
    if (!space_ || !space_->is_segmented_space()) {
        throw AddressError("address is not in a segmented space");
    }
    const auto normalized = space_->address_in_segment(offset_, segment_value);
    return normalized.value_or(*this);
}

Address Address::add_wrap(std::int64_t displacement) const {
    if (!space_) {
        throw AddressError("cannot add to NO_ADDRESS");
    }
    return space_->add_wrap(*this, displacement);
}

Address Address::subtract_wrap(std::int64_t displacement) const {
    if (!space_) {
        throw AddressError("cannot subtract from NO_ADDRESS");
    }
    return space_->subtract_wrap(*this, displacement);
}

Address Address::add_no_wrap(std::int64_t displacement) const {
    if (!space_) {
        throw AddressError("cannot add to NO_ADDRESS");
    }
    return space_->add_no_wrap(*this, displacement);
}

Address Address::subtract_no_wrap(std::int64_t displacement) const {
    if (!space_) {
        throw AddressError("cannot subtract from NO_ADDRESS");
    }
    return space_->subtract_no_wrap(*this, displacement);
}

std::int64_t Address::subtract(const Address &other) const {
    if (!space_) {
        throw AddressError("cannot subtract NO_ADDRESS");
    }
    return space_->subtract(*this, other);
}

std::optional<Address> Address::next() const {
    if (!space_ || offset_ == space_->max_offset()) {
        return std::nullopt;
    }
    return space_->add_wrap(*this, 1);
}

std::optional<Address> Address::previous() const {
    if (!space_ || offset_ == space_->min_offset()) {
        return std::nullopt;
    }
    return space_->subtract_wrap(*this, 1);
}

Address Address::physical_address() const {
    if (!space_) {
        return no_address();
    }
    if (space_->is_segmented_space()) {
        return *this;
    }
    const auto physical = space_->physical_space();
    if (physical->equivalent(*space_)) {
        return *this;
    }
    return physical->address_in_this_space(offset_);
}

bool Address::is_memory_address() const {
    return space_ && space_->is_memory_space();
}

bool Address::is_loaded_memory_address() const {
    return space_ && space_->is_loaded_memory_space();
}

bool Address::is_non_loaded_memory_address() const {
    return space_ && space_->is_non_loaded_memory_space();
}

bool Address::is_register_address() const {
    return space_ && space_->is_register_space();
}

bool Address::is_stack_address() const {
    return space_ && space_->is_stack_space();
}

bool Address::is_unique_address() const {
    return space_ && space_->is_unique_space();
}

bool Address::is_constant_address() const {
    return space_ && space_->is_constant_space();
}

bool Address::is_variable_address() const {
    return space_ && space_->is_variable_space();
}

bool Address::is_external_address() const {
    return space_ && space_->is_external_space();
}

std::string Address::to_string(bool show_space, std::uint32_t min_digits) const {
    if (!space_) {
        return "NO ADDRESS";
    }
    if (space_->type() == AddressSpaceType::none) {
        return space_->name();
    }

    if (segment_) {
        std::ostringstream segmented;
        if (show_space) {
            segmented << space_->name() << ':';
        }
        segmented << std::hex << std::nouppercase << std::setfill('0')
                  << std::setw(4) << *segment_ << ':' << std::setw(4)
                  << *segment_offset();
        return segmented.str();
    }

    const bool stack = space_->is_stack_space();
    std::ostringstream result;
    std::uint64_t display_offset = offset_;
    if (stack) {
        result << "Stack[";
        if (signed_offset() < 0) {
            result << '-';
            display_offset = 0U - display_offset;
        }
        result << "0x";
        min_digits = 1;
    }
    else if (show_space) {
        result << space_->name() << (space_->is_overlay_space() ? "::" : ":");
    }

    const std::uint32_t unit_size = stack ? 1 : space_->addressable_unit_size();
    const std::uint64_t unit_remainder = display_offset % unit_size;
    const std::uint64_t word_offset = display_offset / unit_size;
    const std::uint32_t maximum_digits = (space_->size() + 3U) / 4U;
    const std::uint32_t padding = std::min(min_digits, maximum_digits);

    result << std::hex << std::nouppercase << std::setfill('0')
           << std::setw(static_cast<int>(padding)) << word_offset;
    if (unit_remainder != 0) {
        result << '.' << unit_remainder;
    }
    if (stack) {
        result << ']';
    }
    return result.str();
}

std::string Address::to_string() const {
    return to_string(space_ && space_->show_space_name());
}

bool Address::same_space(const Address &other) const noexcept {
    if (!space_ || !other.space_) {
        return !space_ && !other.space_;
    }
    return space_->equivalent(*other.space_);
}

std::strong_ordering Address::compare(const Address &other) const noexcept {
    if (!space_ || !other.space_) {
        if (!space_ && !other.space_) {
            return std::strong_ordering::equal;
        }
        return space_ ? std::strong_ordering::greater : std::strong_ordering::less;
    }
    if (const auto order = space_->compare(*other.space_); order != 0) {
        return order;
    }
    if (space_->has_signed_offset()) {
        return signed_offset() <=> other.signed_offset();
    }
    return offset_ <=> other.offset_;
}

bool operator==(const Address &lhs, const Address &rhs) noexcept {
    return lhs.offset_ == rhs.offset_ && lhs.same_space(rhs);
}

} // namespace llmghidra::program
