#include "llmghidra/program/address_map.hpp"

#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace llmghidra::program {

AddressMap::AddressMap(std::uint8_t map_id, std::shared_ptr<AddressFactory> factory)
    : map_id_mask_(static_cast<std::uint64_t>(map_id) << 56),
      factory_(std::move(factory)) {}

std::uint32_t AddressMap::base_index(const Address &address) {
    if (!address.is_valid()) {
        throw std::invalid_argument("cannot encode NO_ADDRESS");
    }
    if (address.is_stack_address()) {
        if (stack_space_ && !stack_space_->equivalent(*address.space())) {
            throw std::invalid_argument("an address map supports only one stack space");
        }
        stack_space_ = address.space();
        return stack_space_id;
    }

    const std::uint64_t base_offset = address.offset() & ~address_offset_mask;
    const auto found = std::ranges::find_if(bases_, [&](const Address &base) {
        return base.same_space(address) && base.offset() == base_offset;
    });
    if (found != bases_.end()) {
        return static_cast<std::uint32_t>(std::distance(bases_.begin(), found));
    }
    if (bases_.size() >= stack_space_id) {
        throw std::overflow_error("address map exhausted its 24-bit base index");
    }
    bases_.push_back(address.space()->address_in_this_space(base_offset));
    return static_cast<std::uint32_t>(bases_.size() - 1);
}

std::uint64_t AddressMap::key(const Address &address) {
    std::scoped_lock lock(mutex_);
    const std::uint32_t index = base_index(address);
    return map_id_mask_ | (static_cast<std::uint64_t>(index) << address_offset_bits) |
           (address.offset() & address_offset_mask);
}

std::optional<Address> AddressMap::decode(std::uint64_t value) const {
    std::scoped_lock lock(mutex_);
    if ((value & 0xff00000000000000ULL) != map_id_mask_) {
        return std::nullopt;
    }
    const std::uint32_t index =
        static_cast<std::uint32_t>((value >> address_offset_bits) & base_id_mask);
    const std::uint64_t offset = value & address_offset_mask;
    if (index == stack_space_id) {
        return stack_space_ ? std::optional<Address>(stack_space_->address(
                                  static_cast<std::uint32_t>(offset)))
                            : std::nullopt;
    }
    if (index >= bases_.size()) {
        return std::nullopt;
    }
    return bases_[index].add_wrap(static_cast<std::int64_t>(offset));
}

void AddressMap::append_key_ranges(std::vector<AddressKeyRange> &result,
                                   const Address &start,
                                   const Address &end) {
    if (!start.same_space(end) || start > end) {
        throw std::invalid_argument("address-map range must be ordered within one space");
    }

    Address cursor = start;
    while (true) {
        const std::uint64_t page_base = cursor.offset() & ~address_offset_mask;
        const std::uint64_t page_limit_raw = page_base | address_offset_mask;
        Address page_end = cursor.space()->address_in_this_space(
            std::min(page_limit_raw, cursor.space()->max_offset()));
        if (page_end > end) {
            page_end = end;
        }
        result.push_back({key(cursor), key(page_end)});
        if (page_end == end) {
            break;
        }
        const auto next = page_end.next();
        if (!next) {
            throw AddressOverflowError("address-map page split crossed the space maximum");
        }
        cursor = *next;
    }
}

std::vector<AddressKeyRange> AddressMap::key_ranges(const Address &start,
                                                    const Address &end) {
    std::scoped_lock lock(mutex_);
    std::vector<AddressKeyRange> result;
    append_key_ranges(result, start, end);
    return result;
}

std::vector<AddressKeyRange> AddressMap::key_ranges(const AddressSet &set) {
    std::scoped_lock lock(mutex_);
    std::vector<AddressKeyRange> result;
    for (const auto &range : set.ranges()) {
        append_key_ranges(result, range.min_address(), range.max_address());
    }
    return result;
}

void AddressMap::reconcile() {
    std::scoped_lock lock(mutex_);
    if (!factory_) {
        return;
    }
    for (auto &base : bases_) {
        if (!base.space()->is_overlay_space()) {
            continue;
        }
        const auto current = factory_->space(base.space()->name());
        if (current && current->is_overlay_space() && current->equivalent(*base.space())) {
            base = current->address_in_this_space(base.offset());
        }
    }
}

} // namespace llmghidra::program
