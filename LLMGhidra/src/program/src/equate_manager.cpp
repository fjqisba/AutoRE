#include "llmghidra/program/equate_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

using F = db::FieldType;
constexpr const char *equate_table_name = "Equates";
constexpr const char *reference_table_name = "Equate References";
constexpr const char *scratch_reference_name = "__LLMGHIDRA_EQUATE_REFERENCES";

[[nodiscard]] std::vector<std::unique_ptr<db::Field>> fields(
    std::initializer_list<F> types) {
    std::vector<std::unique_ptr<db::Field>> result;
    result.reserve(types.size());
    for (const auto type : types) result.push_back(db::make_field(type));
    return result;
}

[[nodiscard]] std::shared_ptr<db::Schema> schema(
    int version, std::initializer_list<F> types,
    std::vector<std::string> names) {
    return std::make_shared<db::Schema>(
        version, db::make_field(F::int64), "Key", fields(types),
        std::move(names));
}

[[nodiscard]] std::uint64_t unsigned_key(std::int64_t value) noexcept {
    return std::bit_cast<std::uint64_t>(value);
}

[[nodiscard]] std::int64_t signed_key(std::uint64_t value) noexcept {
    return std::bit_cast<std::int64_t>(value);
}

} // namespace

std::shared_ptr<db::Schema> EquateManager::equate_schema() {
    return schema(0, {F::string, F::int64},
                  {"Equate Name", "Equate Value"});
}

std::shared_ptr<db::Schema> EquateManager::reference_schema() {
    return schema(1, {F::int64, F::int64, F::int16, F::int64},
                  {"Equate ID", "Equate Reference", "Operand Index",
                   "Varnode Hash"});
}

std::shared_ptr<db::Schema> EquateManager::legacy_reference_schema() {
    return schema(0, {F::int64, F::int64, F::int16},
                  {"Equate ID", "Equate Reference", "Operand Index"});
}

EquateManager::EquateManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map, ProgramOpenMode mode, bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) throw std::invalid_argument("equate manager requires a database");
    if (create) create_tables();
    else open_tables();
    std::set<std::int64_t> equate_ids;
    std::set<std::string> equate_names;
    for (const auto &equate : all()) {
        if (!equate_ids.insert(equate.id).second ||
            !equate_names.insert(equate.name).second) {
            throw std::runtime_error("equate identity or name is duplicated");
        }
    }
    for (const auto &reference : references()) {
        if (!equate_ids.contains(reference.equate_id)) {
            throw std::runtime_error("equate reference has no owning equate");
        }
    }
}

void EquateManager::create_tables() {
    equate_table_ = database_->create_table(
        equate_table_name, equate_schema(), {0});
    reference_table_ = database_->create_table(
        reference_table_name, reference_schema(), {0, 1});
}

void EquateManager::open_tables() {
    equate_table_ = database_->get_table(equate_table_name);
    auto source = database_->get_table(reference_table_name);
    if (!equate_table_ || !equate_table_->schema().equals(*equate_schema()) ||
        !source) {
        throw std::runtime_error("unsupported Ghidra Equate table family");
    }
    const bool current = source->schema().equals(*reference_schema());
    const bool legacy = source->schema().equals(*legacy_reference_schema());
    if (!current && !legacy) {
        throw std::runtime_error("unsupported Ghidra Equate References schema");
    }
    const bool rekey = address_map_->upgraded();
    if (!legacy && !rekey) {
        reference_table_ = std::move(source);
        return;
    }
    if (mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra Equate References table requires upgrade");
    }

    auto &scratch = database_->scratch_database();
    if (scratch.get_table(scratch_reference_name) &&
        !scratch.delete_table(scratch_reference_name)) {
        throw std::runtime_error("failed to reset equate-reference staging table");
    }
    auto staged = scratch.create_table(
        scratch_reference_name, reference_schema(), {0, 1});
    auto iterator = source->iterator();
    while (iterator->has_next()) {
        const auto old = iterator->next();
        auto record = reference_schema()->create_record(
            old->key().as_integer());
        record->set_integer(0, old->field(0).as_integer());
        auto address_key = old->field(1).as_integer();
        if (rekey) {
            const auto address = address_map_->factory()->decode_old_index(
                unsigned_key(address_key));
            address_key = signed_key(address_map_->key(address, true));
        }
        record->set_integer(1, address_key);
        record->set_integer(2, old->field(2).as_integer());
        record->set_integer(3, legacy ? 0 : old->field(3).as_integer());
        staged->put_record(*record);
    }
    if (mode_ == ProgramOpenMode::upgrade) {
        if (!database_->delete_table(reference_table_name)) {
            throw std::runtime_error("failed to replace Equate References table");
        }
        reference_table_ = database_->create_table(
            reference_table_name, reference_schema(), {0, 1});
        iterator = staged->iterator();
        while (iterator->has_next()) {
            reference_table_->put_record(*iterator->next());
        }
    }
    else {
        reference_table_ = std::move(staged);
    }
}

void EquateManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

Equate EquateManager::decode_equate(const db::Record &record) const {
    const auto name = record.field(0).as_string().value_or(std::string{});
    if (name.empty()) throw std::runtime_error("equate has an empty name");
    return {record.key().as_integer(), name, record.field(1).as_integer()};
}

EquateReference EquateManager::decode_reference(const db::Record &record) const {
    const auto address = address_map_->decode(
        unsigned_key(record.field(1).as_integer()));
    const auto operand = record.field(2).as_integer();
    if (!address.is_valid() || operand < std::numeric_limits<std::int16_t>::min() ||
        operand > std::numeric_limits<std::int16_t>::max()) {
        throw std::runtime_error("equate reference is invalid");
    }
    return {record.key().as_integer(), record.field(0).as_integer(), address,
            static_cast<std::int16_t>(operand), record.field(3).as_integer()};
}

Equate EquateManager::create(std::string name, std::int64_t value) {
    require_mutation();
    if (name.empty()) throw std::invalid_argument("equate name must not be empty");
    if (by_name(name)) throw std::invalid_argument("equate name already exists");
    auto record = equate_schema()->create_record(equate_table_->next_long_key());
    record->set_string(0, std::move(name));
    record->set_integer(1, value);
    equate_table_->put_record(*record);
    return decode_equate(*record);
}

std::optional<Equate> EquateManager::by_id(std::int64_t id) const {
    const auto record = equate_table_->record(id);
    return record ? std::optional<Equate>(decode_equate(*record)) : std::nullopt;
}

std::optional<Equate> EquateManager::by_name(const std::string &name) const {
    auto iterator = equate_table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (record->field(0).as_string() == std::optional<std::string>(name)) {
            return decode_equate(*record);
        }
    }
    return std::nullopt;
}

std::vector<Equate> EquateManager::all() const {
    std::vector<Equate> result;
    auto iterator = equate_table_->iterator();
    while (iterator->has_next()) result.push_back(decode_equate(*iterator->next()));
    return result;
}

void EquateManager::rename(std::int64_t id, std::string name) {
    require_mutation();
    if (name.empty()) throw std::invalid_argument("equate name must not be empty");
    if (const auto existing = by_name(name); existing && existing->id != id) {
        throw std::invalid_argument("equate name already exists");
    }
    auto record = equate_table_->record(id);
    if (!record) throw std::out_of_range("equate does not exist");
    record->set_string(0, std::move(name));
    equate_table_->put_record(*record);
}

bool EquateManager::remove(std::int64_t id) {
    require_mutation();
    if (!by_id(id)) return false;
    std::vector<std::int64_t> reference_ids;
    for (const auto &reference : references(id)) {
        reference_ids.push_back(reference.id);
    }
    for (const auto reference_id : reference_ids) {
        (void)reference_table_->delete_record(reference_id);
    }
    return equate_table_->delete_record(id);
}

EquateReference EquateManager::add_reference(
    std::int64_t equate_id, const Address &address,
    std::int16_t operand_index, std::int64_t varnode_hash) {
    require_mutation();
    if (!by_id(equate_id)) throw std::out_of_range("equate does not exist");
    const auto key = address_map_->key(address, true);
    std::vector<std::int64_t> replaced;
    for (const auto &reference : references_at(address)) {
        const bool same_varnode = varnode_hash != 0 &&
                                  reference.varnode_hash == varnode_hash;
        const bool same_operand = varnode_hash == 0 &&
                                  reference.varnode_hash == 0 &&
                                  reference.operand_index == operand_index;
        if (same_varnode || same_operand) replaced.push_back(reference.id);
    }
    for (const auto id : replaced) (void)reference_table_->delete_record(id);
    auto record = reference_schema()->create_record(
        reference_table_->next_long_key());
    record->set_integer(0, equate_id);
    record->set_integer(1, signed_key(key));
    record->set_integer(2, operand_index);
    record->set_integer(3, varnode_hash);
    reference_table_->put_record(*record);
    return decode_reference(*record);
}

std::vector<EquateReference> EquateManager::references(
    std::optional<std::int64_t> equate_id) const {
    std::vector<EquateReference> result;
    auto iterator = reference_table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!equate_id || record->field(0).as_integer() == *equate_id) {
            result.push_back(decode_reference(*record));
        }
    }
    return result;
}

std::vector<EquateReference> EquateManager::references_at(
    const Address &address) const {
    std::vector<EquateReference> result;
    for (const auto &reference : references()) {
        if (reference.address == address) result.push_back(reference);
    }
    return result;
}

std::size_t EquateManager::reference_count(std::int64_t equate_id) const {
    return static_cast<std::size_t>(std::ranges::count_if(
        references(), [&](const EquateReference &reference) {
            return reference.equate_id == equate_id;
        }));
}

void EquateManager::remove_orphan(std::int64_t equate_id) {
    if (reference_count(equate_id) == 0) {
        (void)equate_table_->delete_record(equate_id);
    }
}

bool EquateManager::remove_reference(
    std::int64_t reference_id, bool remove_orphan_equate) {
    require_mutation();
    const auto record = reference_table_->record(reference_id);
    if (!record) return false;
    const auto equate_id = record->field(0).as_integer();
    const bool removed = reference_table_->delete_record(reference_id);
    if (removed && remove_orphan_equate) remove_orphan(equate_id);
    return removed;
}

void EquateManager::delete_address_range(
    const Address &start, const Address &end) {
    require_mutation();
    if (!start.same_space(end) || end < start) {
        throw std::invalid_argument("invalid equate-reference address range");
    }
    std::vector<std::pair<std::int64_t, std::int64_t>> doomed;
    for (const auto &reference : references()) {
        if (reference.address.same_space(start) &&
            !(reference.address < start) && !(end < reference.address)) {
            doomed.emplace_back(reference.id, reference.equate_id);
        }
    }
    std::set<std::int64_t> affected;
    for (const auto &[reference_id, equate_id] : doomed) {
        (void)reference_table_->delete_record(reference_id);
        affected.insert(equate_id);
    }
    for (const auto equate_id : affected) remove_orphan(equate_id);
}

void EquateManager::move_address_range(
    const Address &from, const Address &to, std::uint64_t length) {
    require_mutation();
    if (length == 0 || length - 1 > static_cast<std::uint64_t>(
                                    std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("invalid equate-reference move length");
    }
    const auto end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    (void)to.add_no_wrap(static_cast<std::int64_t>(length - 1));
    auto iterator = reference_table_->iterator();
    std::vector<std::unique_ptr<db::Record>> moved;
    while (iterator->has_next()) {
        auto record = iterator->next();
        const auto address = address_map_->decode(
            unsigned_key(record->field(1).as_integer()));
        if (address.same_space(from) && !(address < from) && !(end < address)) {
            const auto displacement = address.subtract(from);
            record->set_integer(1, signed_key(address_map_->key(
                to.add_no_wrap(displacement), true)));
            moved.push_back(std::move(record));
        }
    }
    for (const auto &record : moved) reference_table_->put_record(*record);
}

void EquateManager::invalidate_cache() {
    if (mode_ == ProgramOpenMode::read_only) return;
    equate_table_ = database_->get_table(equate_table_name);
    reference_table_ = database_->get_table(reference_table_name);
    if (!equate_table_ || !reference_table_) {
        throw std::runtime_error("Equate table family disappeared");
    }
}

} // namespace llmghidra::program
