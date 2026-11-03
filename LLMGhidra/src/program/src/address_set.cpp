#include "llmghidra/program/address_set.hpp"

#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace llmghidra::program {

AddressSet::AddressSet(Address address) {
    add(std::move(address));
}

AddressSet::AddressSet(AddressRange range) {
    add(std::move(range));
}

AddressSet::AddressSet(Address first, Address second) {
    add(std::move(first), std::move(second));
}

void AddressSet::clear() noexcept {
    ranges_.clear();
}

void AddressSet::add(Address address) {
    add(AddressRange(address, address));
}

bool AddressSet::adjacent(const Address &first, const Address &second) noexcept {
    return first.is_valid() && second.is_valid() && first.same_space(second) &&
           first.space()->is_successor(first, second);
}

void AddressSet::add(AddressRange range) {
    ranges_.push_back(std::move(range));
    std::ranges::sort(ranges_);

    std::vector<AddressRange> normalized;
    normalized.reserve(ranges_.size());
    for (const auto &candidate : ranges_) {
        if (normalized.empty()) {
            normalized.push_back(candidate);
            continue;
        }
        const AddressRange &current = normalized.back();
        if (current.space()->equivalent(*candidate.space()) &&
            (candidate.min_address() <= current.max_address() ||
             adjacent(current.max_address(), candidate.min_address()))) {
            normalized.back() = AddressRange(
                current.min_address(), std::max(current.max_address(), candidate.max_address()));
        }
        else {
            normalized.push_back(candidate);
        }
    }
    ranges_ = std::move(normalized);
}

void AddressSet::add(Address first, Address second) {
    if (!first.same_space(second) || first > second) {
        throw std::invalid_argument("address-set range must be ordered within one address space");
    }
    add(AddressRange(std::move(first), std::move(second)));
}

void AddressSet::add(const AddressSet &set) {
    for (const auto &range : set.ranges_) {
        add(range);
    }
}

void AddressSet::erase(AddressRange removed) {
    std::vector<AddressRange> result;
    result.reserve(ranges_.size() + 1);
    for (const auto &current : ranges_) {
        if (!current.intersects(removed)) {
            result.push_back(current);
            continue;
        }
        if (current.min_address() < removed.min_address()) {
            if (const auto end = removed.min_address().previous()) {
                result.emplace_back(current.min_address(), *end);
            }
        }
        if (current.max_address() > removed.max_address()) {
            if (const auto start = removed.max_address().next()) {
                result.emplace_back(*start, current.max_address());
            }
        }
    }
    ranges_ = std::move(result);
}

void AddressSet::erase(Address first, Address second) {
    if (!first.same_space(second) || first > second) {
        throw std::invalid_argument("address-set erase range must be ordered within one address space");
    }
    erase(AddressRange(std::move(first), std::move(second)));
}

void AddressSet::erase(const AddressSet &set) {
    for (const auto &range : set.ranges_) {
        erase(range);
    }
}

void AddressSet::delete_from_min(const Address &through) {
    std::vector<AddressRange> result;
    result.reserve(ranges_.size());
    for (const auto &range : ranges_) {
        if (range.max_address() <= through) {
            continue;
        }
        if (range.min_address() <= through && range.min_address().same_space(through)) {
            if (const auto start = through.next()) {
                result.emplace_back(*start, range.max_address());
            }
        }
        else {
            result.push_back(range);
        }
    }
    ranges_ = std::move(result);
}

void AddressSet::delete_to_max(const Address &from) {
    std::vector<AddressRange> result;
    result.reserve(ranges_.size());
    for (const auto &range : ranges_) {
        if (range.min_address() >= from) {
            continue;
        }
        if (range.max_address() >= from && range.min_address().same_space(from)) {
            if (const auto end = from.previous()) {
                result.emplace_back(range.min_address(), *end);
            }
        }
        else {
            result.push_back(range);
        }
    }
    ranges_ = std::move(result);
}

bool AddressSet::empty() const noexcept { return ranges_.empty(); }
std::size_t AddressSet::range_count() const noexcept { return ranges_.size(); }

AddressCount AddressSet::address_count() const noexcept {
    AddressCount count;
    for (const auto &range : ranges_) {
        count += range.length();
    }
    return count;
}

const std::vector<AddressRange> &AddressSet::ranges() const noexcept { return ranges_; }

std::optional<Address> AddressSet::min_address() const noexcept {
    return ranges_.empty() ? std::nullopt
                           : std::optional<Address>(ranges_.front().min_address());
}

std::optional<Address> AddressSet::max_address() const noexcept {
    return ranges_.empty() ? std::nullopt
                           : std::optional<Address>(ranges_.back().max_address());
}

std::optional<AddressRange> AddressSet::range_containing(const Address &address) const {
    const auto found = std::ranges::upper_bound(
        ranges_, address, {}, [](const AddressRange &range) { return range.min_address(); });
    if (found == ranges_.begin()) {
        return std::nullopt;
    }
    const auto &candidate = *std::prev(found);
    return candidate.contains(address) ? std::optional<AddressRange>(candidate) : std::nullopt;
}

bool AddressSet::contains(const Address &address) const noexcept {
    return range_containing(address).has_value();
}

bool AddressSet::contains(const Address &first, const Address &second) const {
    if (!first.same_space(second) || first > second) {
        throw std::invalid_argument("containment range must be ordered within one address space");
    }
    const auto range = range_containing(first);
    return range && range->max_address() >= second;
}

bool AddressSet::contains(const AddressSet &set) const noexcept {
    std::size_t own = 0;
    for (const auto &candidate : set.ranges_) {
        while (own < ranges_.size() && ranges_[own].max_address() < candidate.min_address()) {
            ++own;
        }
        if (own == ranges_.size() || !ranges_[own].space()->equivalent(*candidate.space()) ||
            ranges_[own].min_address() > candidate.min_address() ||
            ranges_[own].max_address() < candidate.max_address()) {
            return false;
        }
    }
    return true;
}

bool AddressSet::intersects(const Address &first, const Address &second) const {
    if (!first.same_space(second) || first > second) {
        throw std::invalid_argument("intersection range must be ordered within one address space");
    }
    const AddressRange query(first, second);
    return std::ranges::any_of(ranges_, [&](const AddressRange &range) {
        return range.intersects(query);
    });
}

bool AddressSet::intersects(const AddressSet &set) const noexcept {
    std::size_t left = 0;
    std::size_t right = 0;
    while (left < ranges_.size() && right < set.ranges_.size()) {
        if (ranges_[left].intersects(set.ranges_[right])) {
            return true;
        }
        if (ranges_[left].max_address() < set.ranges_[right].max_address()) {
            ++left;
        }
        else {
            ++right;
        }
    }
    return false;
}

std::optional<Address> AddressSet::first_address_in_common(const AddressSet &set) const noexcept {
    std::size_t left = 0;
    std::size_t right = 0;
    while (left < ranges_.size() && right < set.ranges_.size()) {
        if (const auto common = ranges_[left].intersection(set.ranges_[right])) {
            return common->min_address();
        }
        if (ranges_[left].max_address() < set.ranges_[right].max_address()) {
            ++left;
        }
        else {
            ++right;
        }
    }
    return std::nullopt;
}

AddressSet AddressSet::intersection(const AddressSet &set) const {
    AddressSet result;
    std::size_t left = 0;
    std::size_t right = 0;
    while (left < ranges_.size() && right < set.ranges_.size()) {
        if (const auto common = ranges_[left].intersection(set.ranges_[right])) {
            result.add(*common);
        }
        if (ranges_[left].max_address() < set.ranges_[right].max_address()) {
            ++left;
        }
        else {
            ++right;
        }
    }
    return result;
}

AddressSet AddressSet::intersect_range(const Address &first, const Address &second) const {
    return intersection(AddressSet(first, second));
}

AddressSet AddressSet::set_union(const AddressSet &set) const {
    AddressSet result = *this;
    result.add(set);
    return result;
}

AddressSet AddressSet::subtract(const AddressSet &set) const {
    AddressSet result = *this;
    result.erase(set);
    return result;
}

AddressSet AddressSet::symmetric_difference(const AddressSet &set) const {
    AddressSet result = subtract(set);
    result.add(set.subtract(*this));
    return result;
}

AddressSet::AddressIterator AddressSet::addresses(bool forward) const {
    return AddressIterator(*this, std::nullopt, forward);
}

AddressSet::AddressIterator AddressSet::addresses(Address start, bool forward) const {
    return AddressIterator(*this, std::move(start), forward);
}

std::string AddressSet::to_string() const {
    if (ranges_.empty()) {
        return "[empty]\n";
    }
    std::ostringstream output;
    for (const auto &range : ranges_) {
        output << range.to_string() << '\n';
    }
    return output.str();
}

AddressSet::AddressIterator::AddressIterator(const AddressSet &set,
                                             std::optional<Address> start,
                                             bool forward)
    : set_(&set), forward_(forward) {
    if (set.ranges_.empty()) {
        return;
    }

    if (forward_) {
        range_index_ = 0;
        if (start) {
            while (range_index_ < set.ranges_.size() &&
                   set.ranges_[range_index_].max_address() < *start) {
                ++range_index_;
            }
            if (range_index_ == set.ranges_.size()) {
                return;
            }
            const auto &range = set.ranges_[range_index_];
            current_ = range.contains(*start) ? *start : range.min_address();
        }
        else {
            current_ = set.ranges_.front().min_address();
        }
    }
    else {
        range_index_ = set.ranges_.size() - 1;
        if (start) {
            while (set.ranges_[range_index_].min_address() > *start) {
                if (range_index_ == 0) {
                    return;
                }
                --range_index_;
            }
            const auto &range = set.ranges_[range_index_];
            current_ = range.contains(*start) ? *start : range.max_address();
        }
        else {
            current_ = set.ranges_.back().max_address();
        }
    }
}

bool AddressSet::AddressIterator::has_next() const noexcept {
    return current_.has_value();
}

std::optional<Address> AddressSet::AddressIterator::next() {
    if (!current_) {
        return std::nullopt;
    }
    const Address result = *current_;
    const AddressRange &range = set_->ranges_[range_index_];
    if (forward_) {
        if (result == range.max_address()) {
            ++range_index_;
            current_ = range_index_ < set_->ranges_.size()
                           ? std::optional<Address>(set_->ranges_[range_index_].min_address())
                           : std::nullopt;
        }
        else {
            current_ = result.next();
        }
    }
    else {
        if (result == range.min_address()) {
            if (range_index_ == 0) {
                current_.reset();
            }
            else {
                --range_index_;
                current_ = set_->ranges_[range_index_].max_address();
            }
        }
        else {
            current_ = result.previous();
        }
    }
    return result;
}

} // namespace llmghidra::program
