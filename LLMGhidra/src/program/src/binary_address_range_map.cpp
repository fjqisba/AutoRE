#include "llmghidra/program/binary_address_range_map.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr std::size_t to_column = 0;
constexpr std::size_t value_column = 1;

[[nodiscard]] bool adjacent(const Address &left, const Address &right) noexcept {
    return left.is_valid() && right.is_valid() && left.same_space(right) &&
           left.space()->is_successor(left, right);
}

} // namespace

std::shared_ptr<db::Schema> BinaryAddressRangeMap::current_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::BinaryField>());
    return std::make_shared<db::Schema>(
        schema_version,
        std::make_unique<db::IntegerField>(db::FieldType::int64),
        "From", std::move(fields), std::vector<std::string>{"To", "Value"});
}

BinaryAddressRangeMap::BinaryAddressRangeMap(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    ProgramOpenMode mode,
    std::string map_name)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode),
      table_name_("Range Map - " + std::move(map_name)) {
    if (!database_) {
        throw std::invalid_argument("binary address range map requires a database");
    }
    table_ = database_->get_table(table_name_);
    validate_table();
}

void BinaryAddressRangeMap::validate_table() const {
    if (!table_) return;
    if (!table_->schema().equals(*current_schema()) ||
        !table_->indexed_columns().empty()) {
        throw std::runtime_error(
            "unsupported Ghidra binary address range-map schema");
    }
}

bool BinaryAddressRangeMap::has_table() const noexcept {
    return static_cast<bool>(table_);
}

bool BinaryAddressRangeMap::empty() const {
    return !table_ || table_->record_count() == 0;
}

std::vector<BinaryAddressRangeValue>
BinaryAddressRangeMap::load_entries() const {
    std::vector<BinaryAddressRangeValue> result;
    if (!table_) return result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (!row) continue;
        const auto start = address_map_->decode(std::bit_cast<std::uint64_t>(
            row->key().as_integer()));
        const auto end = address_map_->decode(std::bit_cast<std::uint64_t>(
            row->field(to_column).as_integer()));
        const auto value = row->field(value_column).as_bytes();
        if (!start.is_valid() || !end.is_valid() || !start.same_space(end) ||
            !value) {
            throw std::runtime_error(
                "Ghidra binary address range-map contains an invalid record");
        }
        if (start <= end) {
            result.push_back({AddressRange(start, end), *value});
        }
        else {
            result.push_back(
                {AddressRange(start, start.space()->max_address()), *value});
            result.push_back(
                {AddressRange(end.space()->min_address(), end), *value});
        }
    }
    normalize(result);
    return result;
}

void BinaryAddressRangeMap::normalize(
    std::vector<BinaryAddressRangeValue> &values) {
    std::ranges::sort(values, [](const auto &left, const auto &right) {
        return left.range < right.range;
    });
    std::vector<BinaryAddressRangeValue> normalized;
    normalized.reserve(values.size());
    for (auto &candidate : values) {
        if (normalized.empty()) {
            normalized.push_back(std::move(candidate));
            continue;
        }
        auto &current = normalized.back();
        if (current.range.intersects(candidate.range)) {
            if (current.value != candidate.value) {
                throw std::runtime_error(
                    "binary address range-map contains overlapping values");
            }
            current.range = AddressRange(
                current.range.min_address(),
                std::max(current.range.max_address(),
                         candidate.range.max_address()));
        }
        else if (current.value == candidate.value &&
                 adjacent(current.range.max_address(),
                          candidate.range.min_address())) {
            current.range = AddressRange(current.range.min_address(),
                                         candidate.range.max_address());
        }
        else {
            normalized.push_back(std::move(candidate));
        }
    }
    values = std::move(normalized);
}

std::vector<BinaryAddressRangeValue> BinaryAddressRangeMap::entries() const {
    return load_entries();
}

std::optional<std::vector<std::uint8_t>> BinaryAddressRangeMap::value_at(
    const Address &address) const {
    for (const auto &entry : load_entries()) {
        if (entry.range.contains(address)) return entry.value;
    }
    return std::nullopt;
}

std::optional<AddressRange> BinaryAddressRangeMap::range_containing(
    const Address &address) const {
    for (const auto &entry : load_entries()) {
        if (entry.range.contains(address)) return entry.range;
    }
    return std::nullopt;
}

std::shared_ptr<db::Table> BinaryAddressRangeMap::require_table() {
    if (!table_) {
        table_ = database_->create_table(table_name_, current_schema());
    }
    return table_;
}

void BinaryAddressRangeMap::store_entries(
    std::vector<BinaryAddressRangeValue> values) {
    normalize(values);
    auto table = require_table();
    table->delete_all();

    std::set<std::size_t> consumed;
    for (std::size_t first = 0; first < values.size(); ++first) {
        if (consumed.contains(first) ||
            values[first].range.min_address() !=
                values[first].range.space()->min_address()) {
            continue;
        }
        for (std::size_t last = values.size(); last-- > first + 1;) {
            if (consumed.contains(last) ||
                values[last].value != values[first].value ||
                !values[last].range.space()->equivalent(
                    *values[first].range.space()) ||
                values[last].range.max_address() !=
                    values[last].range.space()->max_address()) {
                continue;
            }
            auto row = current_schema()->create_record(std::bit_cast<std::int64_t>(
                address_map_->key(values[last].range.min_address(), true)));
            row->set_integer(to_column, std::bit_cast<std::int64_t>(
                address_map_->key(values[first].range.max_address(), true)));
            row->set_bytes(value_column, values[first].value);
            table->put_record(*row);
            consumed.insert(first);
            consumed.insert(last);
            break;
        }
    }
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (consumed.contains(index)) continue;
        auto row = current_schema()->create_record(std::bit_cast<std::int64_t>(
            address_map_->key(values[index].range.min_address(), true)));
        row->set_integer(to_column, std::bit_cast<std::int64_t>(
            address_map_->key(values[index].range.max_address(), true)));
        row->set_bytes(value_column, values[index].value);
        table->put_record(*row);
    }
}

void BinaryAddressRangeMap::paint(const Address &start,
                                  const Address &end,
                                  std::vector<std::uint8_t> value) {
    require_mutation();
    if (!start.same_space(end) || start > end || value.empty()) {
        throw std::invalid_argument(
            "binary address range-map paint range or value is invalid");
    }
    std::vector<BinaryAddressRangeValue> result;
    const AddressRange painted(start, end);
    for (const auto &entry : load_entries()) {
        if (!entry.range.intersects(painted)) {
            result.push_back(entry);
            continue;
        }
        if (entry.range.min_address() < start) {
            if (const auto left_end = start.previous()) {
                result.push_back(
                    {AddressRange(entry.range.min_address(), *left_end),
                     entry.value});
            }
        }
        if (entry.range.max_address() > end) {
            if (const auto right_start = end.next()) {
                result.push_back(
                    {AddressRange(*right_start, entry.range.max_address()),
                     entry.value});
            }
        }
    }
    result.push_back({painted, std::move(value)});
    store_entries(std::move(result));
}

void BinaryAddressRangeMap::clear(const Address &start, const Address &end) {
    require_mutation();
    if (!start.same_space(end) || start > end) {
        throw std::invalid_argument(
            "binary address range-map clear range is invalid");
    }
    if (!table_) return;
    std::vector<BinaryAddressRangeValue> result;
    const AddressRange cleared(start, end);
    for (const auto &entry : load_entries()) {
        if (!entry.range.intersects(cleared)) {
            result.push_back(entry);
            continue;
        }
        if (entry.range.min_address() < start) {
            if (const auto left_end = start.previous()) {
                result.push_back(
                    {AddressRange(entry.range.min_address(), *left_end),
                     entry.value});
            }
        }
        if (entry.range.max_address() > end) {
            if (const auto right_start = end.next()) {
                result.push_back(
                    {AddressRange(*right_start, entry.range.max_address()),
                     entry.value});
            }
        }
    }
    store_entries(std::move(result));
}

void BinaryAddressRangeMap::move_address_range(
    const Address &from,
    const Address &to,
    std::uint64_t length) {
    require_mutation();
    if (length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument(
            "binary address range-map move length is invalid");
    }
    if (!table_) return;
    const auto end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    (void)to.add_no_wrap(static_cast<std::int64_t>(length - 1));
    const AddressRange source(from, end);
    std::vector<BinaryAddressRangeValue> moved;
    for (const auto &entry : load_entries()) {
        const auto intersection = entry.range.intersection(source);
        if (!intersection) continue;
        moved.push_back({
            AddressRange(
                to.add_no_wrap(intersection->min_address().subtract(from)),
                to.add_no_wrap(intersection->max_address().subtract(from))),
            entry.value});
    }
    clear(from, end);
    for (auto &entry : moved) {
        paint(entry.range.min_address(), entry.range.max_address(),
              std::move(entry.value));
    }
}

void BinaryAddressRangeMap::dispose() {
    require_mutation();
    if (!table_) return;
    if (!database_->delete_table(table_name_)) {
        throw std::runtime_error(
            "failed to delete Ghidra binary address range-map table");
    }
    table_.reset();
}

void BinaryAddressRangeMap::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

void BinaryAddressRangeMap::invalidate_cache() {
    table_ = database_->get_table(table_name_);
    validate_table();
}

} // namespace llmghidra::program
