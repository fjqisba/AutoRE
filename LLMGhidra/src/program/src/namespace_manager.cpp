#include "llmghidra/program/namespace_manager.hpp"

#include "llmghidra/program/symbol_manager.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

namespace llmghidra::program {
namespace {

[[nodiscard]] bool namespace_symbol_type(SymbolType type) noexcept {
    return type == SymbolType::library || type == SymbolType::name_space ||
           type == SymbolType::class_type || type == SymbolType::function;
}

} // namespace

NamespaceManager::NamespaceManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    SymbolManager &symbols,
    ProgramOpenMode mode)
    : symbols_(&symbols),
      ranges_(std::move(database), address_map, mode, "SCOPE ADDRESSES", true) {}

bool NamespaceManager::valid_namespace(std::int64_t namespace_id) const {
    if (namespace_id == global_namespace_id) return true;
    const auto symbol = symbols_->get(namespace_id);
    return symbol && namespace_symbol_type(symbol->type);
}

AddressSet NamespaceManager::direct_body(std::int64_t namespace_id) const {
    if (!valid_namespace(namespace_id)) {
        throw std::out_of_range("namespace does not exist");
    }
    return ranges_.address_set(namespace_id);
}

void NamespaceManager::append_body(std::int64_t namespace_id,
                                   AddressSet &result,
                                   std::vector<std::int64_t> &active) const {
    if (std::ranges::find(active, namespace_id) != active.end()) {
        throw std::runtime_error("namespace hierarchy contains a cycle");
    }
    active.push_back(namespace_id);
    result.add(direct_body(namespace_id));
    for (const auto &child : symbols_->in_namespace(namespace_id)) {
        if (namespace_symbol_type(child.type)) append_body(child.id, result, active);
    }
    active.pop_back();
}

AddressSet NamespaceManager::body(std::int64_t namespace_id,
                                  bool include_children) const {
    if (!include_children) return direct_body(namespace_id);
    AddressSet result;
    std::vector<std::int64_t> active;
    append_body(namespace_id, result, active);
    return result;
}

std::optional<AddressRange> NamespaceManager::first_overlap(
    const AddressSet &body_value,
    std::optional<std::int64_t> except_namespace) const {
    for (const auto &entry : ranges_.entries()) {
        if (except_namespace && entry.value == *except_namespace) continue;
        for (const auto &candidate : body_value.ranges()) {
            if (const auto overlap = entry.range.intersection(candidate)) return overlap;
        }
    }
    return std::nullopt;
}

void NamespaceManager::set_body(std::int64_t namespace_id,
                                const AddressSet &body_value) {
    if (!valid_namespace(namespace_id)) {
        throw std::out_of_range("namespace does not exist");
    }
    const auto count = body_value.address_count();
    if (!count.fits_uint64() ||
        count.to_uint64() > static_cast<std::uint64_t>(
                                std::numeric_limits<std::int32_t>::max())) {
        throw std::invalid_argument(
            "namespace body exceeds Ghidra signed-int address-count limit");
    }
    for (const auto &range : body_value.ranges()) {
        if (!range.min_address().is_memory_address()) {
            throw std::invalid_argument("namespace body requires memory addresses");
        }
    }

    const auto old_body = direct_body(namespace_id);
    for (const auto &range : old_body.ranges()) {
        ranges_.clear(range.min_address(), range.max_address());
    }
    if (const auto overlap = first_overlap(body_value)) {
        for (const auto &range : old_body.ranges()) {
            ranges_.paint(range.min_address(), range.max_address(), namespace_id);
        }
        throw std::invalid_argument(
            "namespace body overlaps existing namespace range " +
            overlap->to_string());
    }
    for (const auto &range : body_value.ranges()) {
        ranges_.paint(range.min_address(), range.max_address(), namespace_id);
    }
}

AddressSet NamespaceManager::remove_body(std::int64_t namespace_id) {
    const auto old_body = direct_body(namespace_id);
    for (const auto &range : old_body.ranges()) {
        ranges_.clear(range.min_address(), range.max_address());
    }
    return old_body;
}

std::int64_t NamespaceManager::namespace_containing(
    const Address &address) const {
    const auto value = ranges_.value_at(address);
    return value && valid_namespace(*value) ? *value : global_namespace_id;
}

std::vector<std::int64_t> NamespaceManager::overlapping_namespaces(
    const AddressSet &body_value) const {
    std::vector<std::int64_t> result;
    std::set<std::int64_t> seen;
    for (const auto &entry : ranges_.entries()) {
        if (seen.contains(entry.value)) continue;
        if (std::ranges::any_of(body_value.ranges(), [&](const AddressRange &range) {
                return entry.range.intersects(range);
            })) {
            seen.insert(entry.value);
            if (valid_namespace(entry.value)) result.push_back(entry.value);
        }
    }
    return result;
}

void NamespaceManager::delete_address_range(const Address &start,
                                            const Address &end) {
    ranges_.clear(start, end);
}

void NamespaceManager::move_address_range(const Address &from,
                                          const Address &to,
                                          std::uint64_t length) {
    if (length == 0 || length >
                           static_cast<std::uint64_t>(
                               std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("namespace move length is invalid");
    }
    const auto end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    const AddressRange source(from, end);
    std::vector<AddressRangeValue> moved;
    for (const auto &entry : ranges_.entries()) {
        const auto intersection = entry.range.intersection(source);
        if (!intersection) continue;
        const auto start_delta = intersection->min_address().subtract(from);
        const auto end_delta = intersection->max_address().subtract(from);
        moved.push_back({AddressRange(to.add_no_wrap(start_delta),
                                      to.add_no_wrap(end_delta)),
                         entry.value});
    }
    ranges_.clear(from, end);
    for (const auto &entry : moved) {
        ranges_.paint(entry.range.min_address(), entry.range.max_address(), entry.value);
    }
}

void NamespaceManager::invalidate_cache() {
    ranges_.invalidate_cache();
}

} // namespace llmghidra::program
