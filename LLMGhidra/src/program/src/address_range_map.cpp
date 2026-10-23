#include "llmghidra/program/address_range_map.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <bit>
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

std::shared_ptr<db::Schema> AddressRangeMap::current_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    return std::make_shared<db::Schema>(
        schema_version,
        std::make_unique<db::IntegerField>(db::FieldType::int64),
        "From", std::move(fields), std::vector<std::string>{"To", "Value"});
}

AddressRangeMap::AddressRangeMap(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    ProgramOpenMode mode,
    std::string map_name,
    bool indexed)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode),
      table_name_("Range Map - " + std::move(map_name)), indexed_(indexed) {
    if (!database_) throw std::invalid_argument("address range map requires a database");
    table_ = database_->get_table(table_name_);
    validate_table();
}

void AddressRangeMap::validate_table() const {
    if (!table_) return;
    if (!table_->schema().equals(*current_schema())) {
        throw std::runtime_error("unsupported Ghidra address range-map schema");
    }
    const auto indexed_columns = table_->indexed_columns();
    const bool exact_index_contract =
        indexed_ ? indexed_columns.size() == 1 &&
                       indexed_columns.front() == value_column
                 : indexed_columns.empty();
    if (!exact_index_contract) {
        throw std::runtime_error("Ghidra address range-map index contract mismatch");
    }
}

bool AddressRangeMap::has_table() const noexcept {
    return static_cast<bool>(table_);
}

std::vector<AddressRangeValue> AddressRangeMap::load_entries() const {
    std::vector<AddressRangeValue> result;
    if (!table_) return result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (!row) continue;
        const auto start = address_map_->decode(std::bit_cast<std::uint64_t>(
            row->key().as_integer()));
        const auto end = address_map_->decode(std::bit_cast<std::uint64_t>(
            row->field(to_column).as_integer()));
        if (!start.is_valid() || !end.is_valid() || !start.same_space(end)) {
            throw std::runtime_error("Ghidra address range-map contains invalid endpoints");
        }
        const auto value = row->field(value_column).as_integer();
        if (start <= end) {
            result.push_back({AddressRange(start, end), value});
        }
        else {
            // AddressRangeMapDB stores a boundary-spanning logical range as a
            // single record whose decoded end precedes its decoded start.
            result.push_back(
                {AddressRange(start, start.space()->max_address()), value});
            result.push_back(
                {AddressRange(end.space()->min_address(), end), value});
        }
    }
    normalize(result);
    return result;
}

void AddressRangeMap::normalize(std::vector<AddressRangeValue> &values) {
    std::ranges::sort(values, [](const auto &left, const auto &right) {
        return left.range < right.range;
    });
    std::vector<AddressRangeValue> normalized;
    normalized.reserve(values.size());
    for (auto &candidate : values) {
        if (normalized.empty()) {
            normalized.push_back(std::move(candidate));
            continue;
        }
        auto &current = normalized.back();
        if (current.range.intersects(candidate.range)) {
            if (current.value != candidate.value) {
                throw std::runtime_error("address range-map contains overlapping values");
            }
            current.range = AddressRange(
                current.range.min_address(),
                std::max(current.range.max_address(), candidate.range.max_address()));
        }
        else if (current.value == candidate.value &&
                 adjacent(current.range.max_address(), candidate.range.min_address())) {
            current.range = AddressRange(current.range.min_address(),
                                         candidate.range.max_address());
        }
        else {
            normalized.push_back(std::move(candidate));
        }
    }
    values = std::move(normalized);
}

std::vector<AddressRangeValue> AddressRangeMap::entries() const {
    return load_entries();
}

std::optional<std::int64_t> AddressRangeMap::value_at(
    const Address &address) const {
    for (const auto &entry : load_entries()) {
        if (entry.range.contains(address)) return entry.value;
    }
    return std::nullopt;
}

std::vector<AddressRange> AddressRangeMap::ranges(
    const Address &start,
    const Address &end) const {
    if (!start.same_space(end) || start > end) {
        throw std::invalid_argument("address range-map query is invalid");
    }
    std::vector<AddressRange> result;
    const AddressRange query(start, end);
    for (const auto &entry : load_entries()) {
        if (const auto intersection = entry.range.intersection(query)) {
            result.push_back(*intersection);
        }
    }
    return result;
}

AddressSet AddressRangeMap::address_set(std::int64_t value) const {
    AddressSet result;
    for (const auto &entry : load_entries()) {
        if (entry.value == value) result.add(entry.range);
    }
    return result;
}

std::shared_ptr<db::Table> AddressRangeMap::require_table() {
    if (!table_) {
        table_ = database_->create_table(
            table_name_, current_schema(), indexed_ ? std::vector<std::size_t>{value_column}
                                                    : std::vector<std::size_t>{});
    }
    return table_;
}

void AddressRangeMap::store_entries(std::vector<AddressRangeValue> values) {
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
            if (consumed.contains(last) || values[last].value != values[first].value ||
                !values[last].range.space()->equivalent(*values[first].range.space()) ||
                values[last].range.max_address() !=
                    values[last].range.space()->max_address()) {
                continue;
            }
            const auto start_key = address_map_->key(
                values[last].range.min_address(), true);
            const auto end_key = address_map_->key(
                values[first].range.max_address(), true);
            auto row = current_schema()->create_record(
                std::bit_cast<std::int64_t>(start_key));
            row->set_integer(to_column, std::bit_cast<std::int64_t>(end_key));
            row->set_integer(value_column, values[first].value);
            table->put_record(*row);
            consumed.insert(first);
            consumed.insert(last);
            break;
        }
    }

    for (std::size_t index = 0; index < values.size(); ++index) {
        if (consumed.contains(index)) continue;
        const auto start_key = address_map_->key(
            values[index].range.min_address(), true);
        const auto end_key = address_map_->key(
            values[index].range.max_address(), true);
        auto row = current_schema()->create_record(
            std::bit_cast<std::int64_t>(start_key));
        row->set_integer(to_column, std::bit_cast<std::int64_t>(end_key));
        row->set_integer(value_column, values[index].value);
        table->put_record(*row);
    }
}

void AddressRangeMap::paint(const Address &start,
                            const Address &end,
                            std::int64_t value) {
    require_mutation();
    if (!start.same_space(end) || start > end) {
        throw std::invalid_argument("address range-map paint range is invalid");
    }
    std::vector<AddressRangeValue> result;
    const AddressRange painted(start, end);
    for (const auto &entry : load_entries()) {
        if (!entry.range.intersects(painted)) {
            result.push_back(entry);
            continue;
        }
        if (entry.range.min_address() < start) {
            if (const auto left_end = start.previous()) {
                result.push_back(
                    {AddressRange(entry.range.min_address(), *left_end), entry.value});
            }
        }
        if (entry.range.max_address() > end) {
            if (const auto right_start = end.next()) {
                result.push_back(
                    {AddressRange(*right_start, entry.range.max_address()), entry.value});
            }
        }
    }
    result.push_back({painted, value});
    store_entries(std::move(result));
}

void AddressRangeMap::clear(const Address &start, const Address &end) {
    require_mutation();
    if (!start.same_space(end) || start > end) {
        throw std::invalid_argument("address range-map clear range is invalid");
    }
    if (!table_) return;
    std::vector<AddressRangeValue> result;
    const AddressRange cleared(start, end);
    for (const auto &entry : load_entries()) {
        if (!entry.range.intersects(cleared)) {
            result.push_back(entry);
            continue;
        }
        if (entry.range.min_address() < start) {
            if (const auto left_end = start.previous()) {
                result.push_back(
                    {AddressRange(entry.range.min_address(), *left_end), entry.value});
            }
        }
        if (entry.range.max_address() > end) {
            if (const auto right_start = end.next()) {
                result.push_back(
                    {AddressRange(*right_start, entry.range.max_address()), entry.value});
            }
        }
    }
    store_entries(std::move(result));
}

void AddressRangeMap::clear_all() {
    require_mutation();
    if (table_) table_->delete_all();
}

void AddressRangeMap::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

void AddressRangeMap::invalidate_cache() {
    table_ = database_->get_table(table_name_);
    validate_table();
}

} // namespace llmghidra::program
