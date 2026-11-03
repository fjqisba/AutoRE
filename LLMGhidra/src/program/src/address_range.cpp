#include "llmghidra/program/address_range.hpp"

#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <stdexcept>

namespace llmghidra::program {
namespace {

[[nodiscard]] AddressCount inclusive_distance(const Address &first,
                                              const Address &last) noexcept {
    const std::uint64_t difference = last.offset() - first.offset();
    const std::uint64_t low = difference + 1;
    return {low == 0 ? 1U : 0U, low};
}

void require_range_addresses(const Address &first, const Address &second) {
    if (!first.is_valid() || !second.is_valid()) {
        throw std::invalid_argument("address range endpoints must be valid addresses");
    }
    if (!first.same_space(second)) {
        throw std::invalid_argument("address range endpoints must belong to one address space");
    }
}

} // namespace

AddressRange::AddressRange(Address first, Address second) {
    require_range_addresses(first, second);
    if (first <= second) {
        min_ = std::move(first);
        max_ = std::move(second);
    }
    else {
        min_ = std::move(second);
        max_ = std::move(first);
    }
}

AddressRange::AddressRange(Address start, AddressCount requested_length) : min_(std::move(start)) {
    if (!min_.is_valid() || requested_length.is_zero()) {
        throw std::invalid_argument("address range requires a valid start and non-zero length");
    }
    const Address space_max = min_.space()->max_address();
    const AddressCount available = inclusive_distance(min_, space_max);
    if (requested_length > available) {
        throw AddressOverflowError("address range length crosses the address-space maximum");
    }
    if (requested_length == available) {
        max_ = space_max;
        return;
    }
    if (!requested_length.fits_uint64()) {
        throw AddressOverflowError("address range length is too large");
    }
    max_ = min_.space()->address_in_this_space(
        min_.offset() + requested_length.to_uint64() - 1);
}

const Address &AddressRange::min_address() const noexcept { return min_; }
const Address &AddressRange::max_address() const noexcept { return max_; }
const std::shared_ptr<const AddressSpace> &AddressRange::space() const noexcept { return min_.space(); }
AddressCount AddressRange::length() const noexcept { return inclusive_distance(min_, max_); }

bool AddressRange::contains(const Address &address) const noexcept {
    return address.is_valid() && address.same_space(min_) && min_ <= address && address <= max_;
}

bool AddressRange::intersects(const AddressRange &other) const noexcept {
    return min_.same_space(other.min_) && other.max_ >= min_ && other.min_ <= max_;
}

std::optional<AddressRange> AddressRange::intersection(const AddressRange &other) const {
    if (!intersects(other)) {
        return std::nullopt;
    }
    return AddressRange(std::max(min_, other.min_), std::min(max_, other.max_));
}

int AddressRange::compare(const Address &address) const noexcept {
    if (max_ < address) {
        return -1;
    }
    if (min_ > address) {
        return 1;
    }
    return 0;
}

std::string AddressRange::to_string() const {
    return "[" + min_.to_string() + ", " + max_.to_string() + "]";
}

std::strong_ordering operator<=>(const AddressRange &lhs, const AddressRange &rhs) noexcept {
    if (const auto order = lhs.min_ <=> rhs.min_; order != 0) {
        return order;
    }
    return lhs.max_ <=> rhs.max_;
}

} // namespace llmghidra::program
