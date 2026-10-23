#include "llmghidra/program/reference_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/address_space.hpp"

#include <algorithm>
#include <bit>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr std::size_t ref_count_column = 0;
constexpr std::size_t ref_data_column = 1;
constexpr std::size_t ref_level_column = 2;

constexpr std::size_t big_address_column = 0;
constexpr std::size_t big_flags_column = 1;
constexpr std::size_t big_type_column = 2;
constexpr std::size_t big_operand_column = 3;
constexpr std::size_t big_symbol_column = 4;
constexpr std::size_t big_offset_column = 5;

constexpr std::uint8_t source_low_bit = 0x01;
constexpr std::uint8_t primary_bit = 0x02;
constexpr std::uint8_t offset_bit = 0x04;
constexpr std::uint8_t symbol_bit = 0x08;
constexpr std::uint8_t shift_bit = 0x10;
constexpr std::uint8_t source_high_bits = 0x60;
constexpr std::uint64_t address_type_shift = 60;
constexpr std::uint64_t address_namespace_mask = 0x0fffffffULL;

[[nodiscard]] std::uint64_t unsigned_key(const db::Record &record) noexcept {
    return std::bit_cast<std::uint64_t>(record.key().as_integer());
}

[[nodiscard]] std::int64_t signed_key(std::uint64_t value) noexcept {
    return std::bit_cast<std::int64_t>(value);
}

[[nodiscard]] std::int64_t read_i64(const std::vector<std::uint8_t> &bytes,
                                    std::size_t &offset) {
    if (bytes.size() - std::min(bytes.size(), offset) < 8) {
        throw std::runtime_error("truncated Ghidra reference payload");
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value = (value << 8) | bytes[offset++];
    }
    return std::bit_cast<std::int64_t>(value);
}

void append_i64(std::vector<std::uint8_t> &bytes, std::int64_t value) {
    const auto encoded = std::bit_cast<std::uint64_t>(value);
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes.push_back(static_cast<std::uint8_t>(encoded >> shift));
    }
}

[[nodiscard]] bool same_identity(const Reference &left,
                                 const Reference &right) noexcept {
    return left.from == right.from && left.to == right.to &&
           left.operand_index == right.operand_index;
}

[[nodiscard]] bool address_in_range(const Address &value,
                                    const Address &start,
                                    std::uint64_t length) noexcept {
    return length != 0 && value.is_valid() && start.is_valid() &&
           value.same_space(start) && value.offset() >= start.offset() &&
           value.offset() - start.offset() < length;
}

} // namespace

bool ReferenceType::is_call(std::int8_t value) noexcept {
    switch (value) {
    case unconditional_call:
    case conditional_call:
    case computed_call:
    case call_terminator:
    case conditional_computed_call:
    case conditional_call_terminator:
    case computed_call_terminator:
    case call_override_unconditional:
    case callother_override_call:
        return true;
    default:
        return false;
    }
}

bool ReferenceType::is_flow(std::int8_t value) noexcept {
    return value >= invalid && value <= callother_override_jump;
}

bool ReferenceType::is_data(std::int8_t value) noexcept {
    return value >= data;
}

bool ReferenceType::is_indirect(std::int8_t value) noexcept {
    return value == indirection || value == read_indirect ||
           value == write_indirect || value == read_write_indirect ||
           value == data_indirect;
}

std::int8_t ReferenceType::reference_level(std::int8_t value) noexcept {
    if (value == external) return 5;
    if (is_call(value)) return 3;
    if (is_data(value) || is_indirect(value)) return 1;
    if (is_flow(value)) return 2;
    return 0;
}

std::shared_ptr<db::Schema> ReferenceManager::from_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::BinaryField>());
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "From Address", std::move(fields),
        std::vector<std::string>{"Number of Refs", "Ref Data"});
}

std::shared_ptr<db::Schema> ReferenceManager::to_schema(int version) {
    if (version != 0 && version != 1) {
        throw std::invalid_argument("unsupported TO REFS schema version");
    }
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::BinaryField>());
    std::vector<std::string> names{"Number of Refs", "Ref Data"};
    if (version == 1) {
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
        names.emplace_back("Ref Level");
    }
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "To Address", std::move(fields), std::move(names));
}

std::shared_ptr<db::Schema> ReferenceManager::big_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    return std::make_shared<db::Schema>(
        1, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "RefID", std::move(fields),
        std::vector<std::string>{"Address", "Flags", "Type", "OpIndex",
                                 "SymbolID", "Offset"});
}

std::shared_ptr<db::Schema> ReferenceManager::shared_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int16));
    fields.push_back(std::make_unique<db::BooleanField>());
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int16));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::BooleanField>());
    fields.push_back(std::make_unique<db::BooleanField>());
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "Key",
        std::move(fields),
        std::vector<std::string>{"From Address", "To Address", "Op Index",
                                 "User Defined", "Ref Type", "Symbol ID",
                                 "Base Address", "Is Offset", "Is Primary"});
}

std::shared_ptr<db::Schema> ReferenceManager::stack_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int16));
    fields.push_back(std::make_unique<db::BooleanField>());
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int16));
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64), "Key",
        std::move(fields),
        std::vector<std::string>{"From Address", "Op Index", "User Defined",
                                 "Stack Offset"});
}

ReferenceManager::ReferenceManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    ProgramOpenMode mode,
    bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) {
        throw std::invalid_argument("reference manager requires a database");
    }
    if (create) {
        from_table_ = database_->create_table(from_table_name, from_schema());
        to_table_ = database_->create_table(to_table_name, to_schema(1));
        current_storage_ = true;
        return;
    }

    bind_existing_tables();
    legacy_namespace_keys_ =
        current_storage_ && contains_legacy_namespace_keys();
    const bool adapter_upgrade_required =
        !current_storage_ || to_schema_version_ != 1 || address_map_->upgraded() ||
        legacy_namespace_keys_;
    const bool supplemental_upgrade_required =
        static_cast<bool>(database_->get_table(legacy_stack_table_name)) ||
        static_cast<bool>(database_->get_table(
            legacy_external_entries_table_name));
    if ((adapter_upgrade_required || supplemental_upgrade_required) &&
        mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra References storage requires upgrade");
    }
    if (adapter_upgrade_required && mode_ == ProgramOpenMode::upgrade) {
        upgrade_storage();
    }
    if (mode_ == ProgramOpenMode::upgrade) {
        upgrade_legacy_stack_and_entries();
        if (shared_table_) {
            if (!database_->delete_table(legacy_shared_table_name)) {
                throw std::runtime_error(
                    "failed to delete obsolete Memory References table");
            }
            shared_table_.reset();
        }
    }
    else if (mode_ == ProgramOpenMode::read_only) {
        load_read_only_legacy_supplements();
    }
}

void ReferenceManager::bind_existing_tables() {
    from_table_ = database_->get_table(from_table_name);
    to_table_ = database_->get_table(to_table_name);
    shared_table_ = database_->get_table(legacy_shared_table_name);

    if (from_table_ || to_table_) {
        if (!from_table_ || !to_table_) {
            throw std::runtime_error(
                "Ghidra References has only one current directional table");
        }
        current_storage_ = true;
        validate_current_tables();
        return;
    }
    if (!shared_table_) {
        throw std::runtime_error("missing Ghidra References tables");
    }
    if (!shared_table_->schema().equals(*shared_schema())) {
        throw std::runtime_error("unsupported legacy Memory References table");
    }
    const auto indexes = shared_table_->indexed_columns();
    if (indexes != std::vector<std::size_t>{0, 1}) {
        throw std::runtime_error(
            "legacy Memory References index contract mismatch");
    }
    current_storage_ = false;
}

void ReferenceManager::validate_current_tables() {
    if (!from_table_->schema().equals(*from_schema())) {
        throw std::runtime_error("unsupported FROM REFS table");
    }
    to_schema_version_ = to_table_->schema().version();
    if ((to_schema_version_ != 0 && to_schema_version_ != 1) ||
        !to_table_->schema().equals(*to_schema(to_schema_version_))) {
        throw std::runtime_error("unsupported TO REFS table");
    }
}

void ReferenceManager::upgrade_storage() {
    require_mutation();
    const auto references = current_storage_ ? all_from_records()
                                             : shared_records();
    replace_current_tables(references);
    legacy_namespace_keys_ = false;
    if (shared_table_) {
        if (!database_->delete_table(legacy_shared_table_name)) {
            throw std::runtime_error(
                "failed to delete legacy Memory References table");
        }
        shared_table_.reset();
    }
}

std::vector<Reference> ReferenceManager::shared_records() const {
    if (!shared_table_) return {};
    std::vector<Reference> result;
    result.reserve(static_cast<std::size_t>(shared_table_->record_count()));
    auto iterator = shared_table_->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (!row) continue;
        const Address from = address_map_->decode(std::bit_cast<std::uint64_t>(
            row->field(0).as_integer()));
        const Address to = address_map_->decode(std::bit_cast<std::uint64_t>(
            row->field(1).as_integer()));
        if (!from.is_valid() || !to.is_valid()) {
            throw std::runtime_error(
                "legacy Memory References contains an undecodable address");
        }
        Reference reference;
        reference.from = from;
        reference.to = to;
        reference.operand_index =
            static_cast<std::int32_t>(row->field(2).as_integer());
        reference.source = row->field(3).as_boolean()
                               ? SourceType::user_defined
                               : SourceType::default_source;
        reference.type =
            static_cast<std::int8_t>(row->field(4).as_integer());
        reference.symbol_id = row->field(5).as_integer();
        reference.primary = row->field(8).as_boolean();
        // The fixed upstream shared-table adapters intentionally discarded
        // obsolete Base Address/Is Offset state during this conversion.
        result.push_back(std::move(reference));
    }
    return result;
}

std::vector<Reference> ReferenceManager::all_from_records() const {
    if (!current_storage_) return shared_records();
    std::vector<Reference> result;
    auto iterator = from_table_->iterator();
    while (iterator->has_next()) {
        const auto parent = iterator->next();
        if (!parent) continue;
        auto list = read_parent_list(*parent, true, 0);
        result.insert(result.end(),
                      std::make_move_iterator(list.begin()),
                      std::make_move_iterator(list.end()));
    }
    return result;
}

std::vector<Reference> ReferenceManager::read_parent_list(
    const db::Record &parent,
    bool from_list,
    int parent_version) const {
    (void)parent_version;
    const auto key = unsigned_key(parent);
    const Address owner = address_map_->decode(key);
    if (!owner.is_valid()) {
        throw std::runtime_error(
            "reference parent contains an undecodable address key");
    }
    const auto raw_count = parent.field(ref_count_column).as_integer();
    if (raw_count < 0 ||
        static_cast<std::uint64_t>(raw_count) >
            std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("reference parent has an invalid count");
    }
    const auto count = static_cast<std::size_t>(raw_count);
    const auto payload = parent.field(ref_data_column).as_bytes();
    return payload ? decode_inline(owner, *payload, count, from_list)
                   : decode_big(key, owner, count, from_list);
}

std::vector<Reference> ReferenceManager::decode_inline(
    const Address &owner,
    const std::vector<std::uint8_t> &bytes,
    std::size_t expected_count,
    bool from_list) const {
    std::vector<Reference> result;
    result.reserve(expected_count);
    std::size_t offset = 0;
    for (std::size_t index = 0; index < expected_count; ++index) {
        const auto related_key = std::bit_cast<std::uint64_t>(
            read_i64(bytes, offset));
        if (bytes.size() - std::min(bytes.size(), offset) < 3) {
            throw std::runtime_error("truncated Ghidra reference payload");
        }
        const std::uint8_t flags = bytes[offset++];
        const auto type = static_cast<std::int8_t>(bytes[offset++]);
        const auto operand = static_cast<std::int8_t>(bytes[offset++]);
        std::int64_t symbol_id = -1;
        if ((flags & symbol_bit) != 0) symbol_id = read_i64(bytes, offset);
        std::int64_t offset_or_shift = 0;
        if ((flags & (offset_bit | shift_bit)) != 0) {
            offset_or_shift = read_i64(bytes, offset);
        }
        const Address related = address_map_->decode(related_key);
        if (!related.is_valid()) {
            throw std::runtime_error(
                "reference payload contains an undecodable address key");
        }
        Reference reference;
        reference.from = from_list ? owner : related;
        reference.to = from_list ? related : owner;
        reference.type = type;
        reference.operand_index = operand;
        reference.symbol_id = symbol_id;
        reference.primary = (flags & primary_bit) != 0;
        reference.source = decode_source(flags);
        reference.offset_reference = (flags & offset_bit) != 0;
        reference.shifted_reference = (flags & shift_bit) != 0;
        reference.offset_or_shift = offset_or_shift;
        result.push_back(std::move(reference));
    }
    if (offset != bytes.size()) {
        throw std::runtime_error(
            "reference payload count does not consume its encoded data");
    }
    return result;
}

std::vector<Reference> ReferenceManager::decode_big(
    std::uint64_t parent_key,
    const Address &owner,
    std::size_t expected_count,
    bool from_list) const {
    const auto name = big_table_name(parent_key, from_list);
    const auto table = database_->get_table(name);
    if (!table || !table->schema().equals(*big_schema()) ||
        table->indexed_columns() != std::vector<std::size_t>{0}) {
        throw std::runtime_error("missing or incompatible Ghidra " + name);
    }
    if (static_cast<std::size_t>(table->record_count()) != expected_count) {
        throw std::runtime_error(name + " count disagrees with its parent");
    }
    std::vector<Reference> result;
    result.reserve(expected_count);
    auto iterator = table->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (!row) continue;
        const Address related = address_map_->decode(std::bit_cast<std::uint64_t>(
            row->field(big_address_column).as_integer()));
        if (!related.is_valid()) {
            throw std::runtime_error(
                "BigRefList contains an undecodable address key");
        }
        const auto flags = static_cast<std::uint8_t>(
            row->field(big_flags_column).as_integer());
        Reference reference;
        reference.from = from_list ? owner : related;
        reference.to = from_list ? related : owner;
        reference.type = static_cast<std::int8_t>(
            row->field(big_type_column).as_integer());
        reference.operand_index = static_cast<std::int8_t>(
            row->field(big_operand_column).as_integer());
        reference.symbol_id = (flags & symbol_bit) != 0
                                  ? row->field(big_symbol_column).as_integer()
                                  : -1;
        reference.primary = (flags & primary_bit) != 0;
        reference.source = decode_source(flags);
        reference.offset_reference = (flags & offset_bit) != 0;
        reference.shifted_reference = (flags & shift_bit) != 0;
        reference.offset_or_shift =
            (reference.offset_reference || reference.shifted_reference)
                ? row->field(big_offset_column).as_integer()
                : 0;
        result.push_back(std::move(reference));
    }
    return result;
}

std::vector<Reference> ReferenceManager::references_from(
    const Address &address) const {
    std::vector<Reference> result;
    if (current_storage_) {
        const auto key = address_key(address, false);
        if (key != PersistentAddressMap::invalid_key) {
            if (const auto parent = from_table_->record(signed_key(key))) {
                result = read_parent_list(*parent, true, 0);
            }
        }
    }
    else {
        for (auto &reference : shared_records()) {
            if (reference.from == address) result.push_back(std::move(reference));
        }
    }
    for (const auto &reference : read_only_legacy_supplements_) {
        if (reference.from == address) result.push_back(reference);
    }
    return result;
}

std::vector<Reference> ReferenceManager::references_to(
    const Address &address) const {
    if (address.is_stack_address() || address.is_register_address()) return {};
    std::vector<Reference> result;
    if (current_storage_) {
        const auto key = address_key(address, false);
        if (key != PersistentAddressMap::invalid_key) {
            if (const auto parent = to_table_->record(signed_key(key))) {
                result = read_parent_list(*parent, false, to_schema_version_);
            }
        }
        if (result.empty() && legacy_namespace_keys_) {
            for (auto &reference : all_from_records()) {
                if (reference.to == address) {
                    result.push_back(std::move(reference));
                }
            }
        }
    }
    else {
        for (auto &reference : shared_records()) {
            if (reference.to == address) result.push_back(std::move(reference));
        }
    }
    for (const auto &reference : read_only_legacy_supplements_) {
        if (reference.to == address && !reference.to.is_stack_address() &&
            !reference.to.is_register_address()) {
            result.push_back(reference);
        }
    }
    return result;
}

std::optional<Reference> ReferenceManager::reference(
    const Address &from,
    const Address &to,
    std::int32_t operand_index) const {
    const auto references = references_from(from);
    const auto match = std::ranges::find_if(references, [&](const auto &value) {
        return value.to == to && value.operand_index == operand_index;
    });
    return match == references.end() ? std::nullopt
                                     : std::optional<Reference>(*match);
}

std::vector<Address> ReferenceManager::from_addresses() const {
    std::set<Address> unique;
    if (current_storage_) {
        auto iterator = from_table_->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            if (!row) continue;
            const auto address = address_map_->decode(unsigned_key(*row));
            if (address.is_valid()) unique.insert(address);
        }
    }
    else {
        for (const auto &reference : shared_records()) unique.insert(reference.from);
    }
    for (const auto &reference : read_only_legacy_supplements_) {
        unique.insert(reference.from);
    }
    return {unique.begin(), unique.end()};
}

std::vector<Address> ReferenceManager::to_addresses() const {
    std::set<Address> unique;
    if (current_storage_) {
        auto iterator = to_table_->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            if (!row) continue;
            const auto address = address_map_->decode(unsigned_key(*row));
            if (address.is_valid()) unique.insert(address);
        }
    }
    else {
        for (const auto &reference : shared_records()) {
            if (!reference.to.is_stack_address() &&
                !reference.to.is_register_address()) {
                unique.insert(reference.to);
            }
        }
    }
    for (const auto &reference : read_only_legacy_supplements_) {
        if (!reference.to.is_stack_address() &&
            !reference.to.is_register_address()) {
            unique.insert(reference.to);
        }
    }
    return {unique.begin(), unique.end()};
}

std::size_t ReferenceManager::size() const {
    if (!current_storage_) {
        return shared_records().size() + read_only_legacy_supplements_.size();
    }
    std::size_t count = 0;
    auto iterator = from_table_->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (!row) continue;
        const auto value = row->field(ref_count_column).as_integer();
        if (value < 0) throw std::runtime_error("FROM REFS has a negative count");
        count += static_cast<std::size_t>(value);
    }
    return count + read_only_legacy_supplements_.size();
}

Reference ReferenceManager::add(Reference value) {
    require_mutation();
    validate_reference(value);
    auto references = all_from_records();
    const auto previous = std::ranges::find_if(
        references, [&](const auto &existing) {
            return same_identity(existing, value);
        });
    if (previous != references.end()) {
        const bool compatible =
            previous->offset_reference == value.offset_reference &&
            previous->shifted_reference == value.shifted_reference &&
            (!(value.offset_reference || value.shifted_reference) ||
             previous->offset_or_shift == value.offset_or_shift);
        if (compatible) {
            value.type = combine_type(value.type, previous->type);
            if (value.type == previous->type) return *previous;
        }
        value.primary = previous->primary;
    }
    references.erase(std::remove_if(references.begin(), references.end(),
                                    [&](const auto &existing) {
                                        return same_identity(existing, value);
                                    }),
                     references.end());
    const bool has_operand_reference = std::ranges::any_of(
        references, [&](const auto &existing) {
            return existing.from == value.from &&
                   existing.operand_index == value.operand_index;
        });
    if (value.from.is_memory_address() && !has_operand_reference) {
        value.primary = true;
    }
    if (value.primary) {
        for (auto &existing : references) {
            if (existing.from == value.from &&
                existing.operand_index == value.operand_index) {
                existing.primary = false;
            }
        }
    }
    references.push_back(value);
    rewrite_all(references);
    return value;
}

bool ReferenceManager::remove(const Address &from,
                              const Address &to,
                              std::int32_t operand_index) {
    require_mutation();
    auto references = all_from_records();
    const auto old_size = references.size();
    references.erase(std::remove_if(references.begin(), references.end(),
                                    [&](const auto &value) {
                                        return value.from == from &&
                                               value.to == to &&
                                               value.operand_index == operand_index;
                                    }),
                     references.end());
    if (references.size() == old_size) return false;
    rewrite_all(references);
    return true;
}

std::size_t ReferenceManager::remove_all_from(const Address &from) {
    require_mutation();
    auto references = all_from_records();
    const auto old_size = references.size();
    references.erase(std::remove_if(references.begin(), references.end(),
                                    [&](const auto &value) {
                                        return value.from == from;
                                    }),
                     references.end());
    const auto removed = old_size - references.size();
    if (removed != 0) rewrite_all(references);
    return removed;
}

std::size_t ReferenceManager::remove_all_to(const Address &to) {
    require_mutation();
    auto references = all_from_records();
    const auto old_size = references.size();
    references.erase(std::remove_if(references.begin(), references.end(),
                                    [&](const auto &value) {
                                        return value.to == to;
                                    }),
                     references.end());
    const auto removed = old_size - references.size();
    if (removed != 0) rewrite_all(references);
    return removed;
}

std::size_t ReferenceManager::remove_references_from_range(
    const Address &start,
    const Address &end) {
    require_mutation();
    if (!start.is_valid() || !end.is_valid() || !start.same_space(end) ||
        end < start) {
        throw std::invalid_argument("invalid reference removal range");
    }
    auto references = all_from_records();
    const auto old_size = references.size();
    references.erase(std::remove_if(references.begin(), references.end(),
                                    [&](const auto &value) {
                                        return value.from.same_space(start) &&
                                               value.from >= start && value.from <= end;
                                    }),
                     references.end());
    const auto removed = old_size - references.size();
    if (removed != 0) rewrite_all(references);
    return removed;
}

bool ReferenceManager::set_primary(const Address &from,
                                   const Address &to,
                                   std::int32_t operand_index,
                                   bool primary) {
    require_mutation();
    auto references = all_from_records();
    auto selected = std::ranges::find_if(references, [&](const auto &value) {
        return value.from == from && value.to == to &&
               value.operand_index == operand_index;
    });
    if (selected == references.end() || selected->primary == primary) return false;
    if (primary) {
        for (auto &value : references) {
            if (value.from == from && value.operand_index == operand_index) {
                value.primary = false;
            }
        }
    }
    selected->primary = primary;
    rewrite_all(references);
    return true;
}

bool ReferenceManager::set_symbol_id(const Address &from,
                                     const Address &to,
                                     std::int32_t operand_index,
                                     std::int64_t symbol_id) {
    require_mutation();
    auto references = all_from_records();
    auto selected = std::ranges::find_if(references, [&](const auto &value) {
        return value.from == from && value.to == to &&
               value.operand_index == operand_index;
    });
    if (selected == references.end() || selected->symbol_id == symbol_id) return false;
    selected->symbol_id = symbol_id;
    rewrite_all(references);
    return true;
}

std::size_t ReferenceManager::remove_symbol_associations(
    std::int64_t symbol_id) {
    require_mutation();
    if (symbol_id < 0) return 0;
    auto references = all_from_records();
    std::size_t changed = 0;
    for (auto &reference : references) {
        if (reference.symbol_id == symbol_id) {
            reference.symbol_id = -1;
            ++changed;
        }
    }
    if (changed != 0) rewrite_all(references);
    return changed;
}

bool ReferenceManager::update_type(const Address &from,
                                   const Address &to,
                                   std::int32_t operand_index,
                                   std::int8_t type) {
    require_mutation();
    auto references = all_from_records();
    auto selected = std::ranges::find_if(references, [&](const auto &value) {
        return value.from == from && value.to == to &&
               value.operand_index == operand_index;
    });
    if (selected == references.end() || selected->type == type) return false;
    selected->type = type;
    rewrite_all(references);
    return true;
}

std::size_t ReferenceManager::move_references_to(const Address &old_to,
                                                 const Address &new_to) {
    require_mutation();
    if (!new_to.is_valid()) {
        throw std::invalid_argument("new reference destination is invalid");
    }
    auto references = all_from_records();
    std::size_t changed = 0;
    for (auto &value : references) {
        if (value.to != old_to) continue;
        value.to = new_to;
        value.symbol_id = -1;
        value.offset_reference = false;
        value.shifted_reference = false;
        value.offset_or_shift = 0;
        ++changed;
    }
    if (changed != 0) rewrite_all(references);
    return changed;
}

std::size_t ReferenceManager::move_references_from(const Address &old_from,
                                                   const Address &new_from) {
    require_mutation();
    if (!new_from.is_memory_address() &&
        !new_from.is_external_entry_address()) {
        throw std::invalid_argument("new reference source is invalid");
    }
    auto references = all_from_records();
    std::size_t changed = 0;
    for (auto &value : references) {
        if (value.from == old_from) {
            value.from = new_from;
            ++changed;
        }
    }
    if (changed != 0) rewrite_all(references);
    return changed;
}

void ReferenceManager::normalize_address_encodings() {
    require_mutation();
    rewrite_all(all_from_records());
}

void ReferenceManager::move_address_range(const Address &from,
                                          const Address &to,
                                          std::uint64_t length) {
    require_mutation();
    if (!from.is_memory_address() || !to.is_memory_address() || length == 0) {
        throw std::invalid_argument(
            "reference range move requires non-empty memory ranges");
    }
    auto references = all_from_records();
    std::erase_if(references, [&](Reference &value) {
        if (!address_in_range(value.from, from, length)) return false;
        if (value.source == SourceType::default_source) return true;
        value.from = to.add_no_wrap(static_cast<std::int64_t>(
            value.from.offset() - from.offset()));
        if (address_in_range(value.to, from, length)) {
            value.to = to.add_no_wrap(static_cast<std::int64_t>(
                value.to.offset() - from.offset()));
        }
        return false;
    });
    rewrite_all(references);
}

bool ReferenceManager::is_external_entry_point(const Address &address) const {
    if (!address.is_memory_address()) return false;
    return reference(Address::external_entry_address(), address, -1).has_value();
}

void ReferenceManager::add_external_entry_point(const Address &address) {
    if (!address.is_memory_address()) {
        throw std::invalid_argument("entry point must be a memory address");
    }
    if (is_external_entry_point(address)) return;
    Reference reference;
    reference.from = Address::external_entry_address();
    reference.to = address;
    reference.type = ReferenceType::external;
    reference.operand_index = -1;
    reference.source = SourceType::default_source;
    (void)add(std::move(reference));
}

bool ReferenceManager::remove_external_entry_point(const Address &address) {
    return remove(Address::external_entry_address(), address, -1);
}

std::int8_t ReferenceManager::reference_level(const Address &address) const {
    if (!current_storage_ || to_schema_version_ == 0) {
        std::int8_t level = 0;
        for (const auto &reference : references_to(address)) {
            level = std::max(level,
                             ReferenceType::reference_level(reference.type));
        }
        return level;
    }
    const auto key = address_key(address, false);
    if (key == PersistentAddressMap::invalid_key) return 0;
    const auto parent = to_table_->record(signed_key(key));
    return parent ? static_cast<std::int8_t>(
                        parent->field(ref_level_column).as_integer())
                  : 0;
}

void ReferenceManager::replace_current_tables(
    const std::vector<Reference> &references) {
    if (from_table_) delete_big_tables_for(from_table_, true);
    if (to_table_) delete_big_tables_for(to_table_, false);
    if (database_->get_table(from_table_name) &&
        !database_->delete_table(from_table_name)) {
        throw std::runtime_error("failed to replace FROM REFS table");
    }
    if (database_->get_table(to_table_name) &&
        !database_->delete_table(to_table_name)) {
        throw std::runtime_error("failed to replace TO REFS table");
    }
    from_table_ = database_->create_table(from_table_name, from_schema());
    to_table_ = database_->create_table(to_table_name, to_schema(1));
    current_storage_ = true;
    legacy_namespace_keys_ = false;
    to_schema_version_ = 1;
    write_grouped(references);
}

void ReferenceManager::rewrite_all(const std::vector<Reference> &references) {
    require_mutation();
    replace_current_tables(references);
}

void ReferenceManager::write_grouped(
    const std::vector<Reference> &references) {
    std::map<Address, std::vector<Reference>> from_groups;
    std::map<Address, std::vector<Reference>> to_groups;
    for (const auto &reference : references) {
        validate_reference(reference);
        from_groups[reference.from].push_back(reference);
        if (!reference.to.is_stack_address() &&
            !reference.to.is_register_address()) {
            to_groups[reference.to].push_back(reference);
        }
    }
    for (const auto &[owner, list] : from_groups) write_list(owner, list, true);
    for (const auto &[owner, list] : to_groups) write_list(owner, list, false);
}

void ReferenceManager::write_list(const Address &owner,
                                  const std::vector<Reference> &references,
                                  bool from_list) {
    if (references.empty()) return;
    if (references.size() >
        static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        throw std::overflow_error(
            "reference list exceeds Ghidra int32 count storage");
    }
    const auto key = address_key(owner, true);
    if (key == PersistentAddressMap::invalid_key) {
        throw std::runtime_error("failed to encode reference-list owner");
    }
    const auto parent_schema = from_list ? from_schema() : to_schema(1);
    auto parent = parent_schema->create_record(signed_key(key));
    parent->set_integer(ref_count_column,
                        static_cast<std::int64_t>(references.size()));
    std::int8_t level = -1;
    if (!from_list) {
        for (const auto &reference : references) {
            level = std::max(level,
                             ReferenceType::reference_level(reference.type));
        }
        parent->set_integer(ref_level_column, level);
    }

    if (references.size() < big_reference_threshold) {
        std::vector<std::uint8_t> bytes;
        for (const auto &reference : references) {
            auto encoded = encode_inline_reference(reference, from_list);
            bytes.insert(bytes.end(), encoded.begin(), encoded.end());
        }
        parent->set_bytes(ref_data_column, std::move(bytes));
    }
    else {
        parent->set_null(ref_data_column);
        const auto name = big_table_name(key, from_list);
        if (database_->get_table(name) && !database_->delete_table(name)) {
            throw std::runtime_error("failed to replace Ghidra " + name);
        }
        const auto table = database_->create_table(name, big_schema(), {0});
        for (std::size_t index = 0; index < references.size(); ++index) {
            const auto &reference = references[index];
            auto row = big_schema()->create_record(
                static_cast<std::int64_t>(index));
            const Address &related = from_list ? reference.to : reference.from;
            const auto related_key = address_key(related, true);
            if (related_key == PersistentAddressMap::invalid_key) {
                throw std::runtime_error(
                    "failed to encode BigRefList related address");
            }
            row->set_integer(big_address_column,
                             signed_key(related_key));
            row->set_integer(big_flags_column, encode_flags(reference));
            row->set_integer(big_type_column, reference.type);
            row->set_integer(big_operand_column,
                             static_cast<std::int8_t>(reference.operand_index));
            row->set_integer(big_symbol_column, reference.symbol_id);
            row->set_integer(big_offset_column, reference.offset_or_shift);
            table->put_record(*row);
        }
    }
    (from_list ? from_table_ : to_table_)->put_record(*parent);
}

void ReferenceManager::remove_list_storage(const Address &owner,
                                           bool from_list) {
    auto table = from_list ? from_table_ : to_table_;
    const auto key = address_key(owner, false);
    if (key == PersistentAddressMap::invalid_key) return;
    const auto parent = table->record(signed_key(key));
    if (!parent) return;
    if (!parent->field(ref_data_column).as_bytes()) {
        const auto name = big_table_name(key, from_list);
        if (database_->get_table(name) && !database_->delete_table(name)) {
            throw std::runtime_error("failed to remove Ghidra " + name);
        }
    }
    (void)table->delete_record(signed_key(key));
}

void ReferenceManager::delete_big_tables_for(
    const std::shared_ptr<db::Table> &parent,
    bool from_list) {
    if (!parent) return;
    std::vector<std::string> names;
    auto iterator = parent->iterator();
    while (iterator->has_next()) {
        const auto row = iterator->next();
        if (row && !row->field(ref_data_column).as_bytes()) {
            names.push_back(big_table_name(unsigned_key(*row), from_list));
        }
    }
    for (const auto &name : names) {
        if (database_->get_table(name) && !database_->delete_table(name)) {
            throw std::runtime_error("failed to delete Ghidra " + name);
        }
    }
}

std::vector<std::uint8_t> ReferenceManager::encode_inline_reference(
    const Reference &reference,
    bool from_list) const {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(11 + (reference.symbol_id >= 0 ? 8 : 0) +
                  (reference.offset_reference || reference.shifted_reference
                       ? 8
                       : 0));
    const Address &related = from_list ? reference.to : reference.from;
    const auto related_key = address_key(related, true);
    if (related_key == PersistentAddressMap::invalid_key) {
        throw std::runtime_error(
            "failed to encode inline reference related address");
    }
    append_i64(bytes, signed_key(related_key));
    bytes.push_back(encode_flags(reference));
    bytes.push_back(static_cast<std::uint8_t>(reference.type));
    bytes.push_back(static_cast<std::uint8_t>(reference.operand_index));
    if (reference.symbol_id >= 0) append_i64(bytes, reference.symbol_id);
    if (reference.offset_reference || reference.shifted_reference) {
        append_i64(bytes, reference.offset_or_shift);
    }
    return bytes;
}

std::string ReferenceManager::big_table_name(std::uint64_t parent_key,
                                             bool from_list) {
    std::ostringstream name;
    if (from_list) name << "From";
    name << "BigRefList_" << std::hex << std::nouppercase << parent_key;
    return name.str();
}

std::uint64_t ReferenceManager::address_key(const Address &address,
                                            bool create) const {
    return address_map_->key(address, create);
}

std::uint8_t ReferenceManager::encode_flags(const Reference &reference) {
    std::uint8_t source_id = 0;
    switch (reference.source) {
    case SourceType::default_source:
        source_id = 0;
        break;
    case SourceType::analysis:
        source_id = 2;
        break;
    default:
        source_id = static_cast<std::uint8_t>(reference.source);
        break;
    }
    if (source_id > 7) {
        throw std::invalid_argument("reference SourceType exceeds flag storage");
    }
    std::uint8_t flags = static_cast<std::uint8_t>(
        (source_id & 1U) | ((source_id >> 1U) << 5U));
    if (reference.primary) flags |= primary_bit;
    if (reference.offset_reference) flags |= offset_bit;
    if (reference.symbol_id >= 0) flags |= symbol_bit;
    if (reference.shifted_reference) flags |= shift_bit;
    return flags;
}

SourceType ReferenceManager::decode_source(std::uint8_t flags) {
    const std::uint8_t source_id = static_cast<std::uint8_t>(
        (flags & source_low_bit) | ((flags & source_high_bits) >> 4U));
    switch (source_id) {
    case 0:
        return SourceType::default_source;
    case 1:
        return SourceType::user_defined;
    case 2:
        return SourceType::analysis;
    case 3:
        return SourceType::imported;
    case 4:
        return SourceType::ai;
    default:
        throw std::runtime_error("undefined SourceType in reference flags");
    }
}

bool ReferenceManager::contains_legacy_namespace_keys() const {
    const auto legacy_key = [](std::uint64_t key) noexcept {
        const auto type = key >> address_type_shift;
        const auto namespace_id =
            (key >> 32U) & address_namespace_mask;
        return (type == 3 || type == 4 || type == 5) &&
               namespace_id != 0;
    };
    const auto inspect = [&](const std::shared_ptr<db::Table> &parent,
                             bool from_list) {
        auto iterator = parent->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            if (!row) continue;
            if (legacy_key(unsigned_key(*row))) return true;
            const auto raw_count = row->field(ref_count_column).as_integer();
            if (raw_count < 0) {
                throw std::runtime_error(
                    "reference parent has an invalid count");
            }
            const auto payload = row->field(ref_data_column).as_bytes();
            if (!payload) {
                const auto table = database_->get_table(
                    big_table_name(unsigned_key(*row), from_list));
                if (!table || !table->schema().equals(*big_schema())) {
                    throw std::runtime_error(
                        "missing BigRefList during namespace-key scan");
                }
                auto big_iterator = table->iterator();
                while (big_iterator->has_next()) {
                    const auto reference = big_iterator->next();
                    if (reference && legacy_key(std::bit_cast<std::uint64_t>(
                                         reference->field(big_address_column)
                                             .as_integer()))) {
                        return true;
                    }
                }
                continue;
            }
            std::size_t offset = 0;
            for (std::int64_t index = 0; index < raw_count; ++index) {
                const auto related_key = std::bit_cast<std::uint64_t>(
                    read_i64(*payload, offset));
                if (legacy_key(related_key)) return true;
                if (payload->size() - std::min(payload->size(), offset) < 3) {
                    throw std::runtime_error(
                        "truncated reference during namespace-key scan");
                }
                const auto flags = (*payload)[offset++];
                offset += 2;
                if ((flags & symbol_bit) != 0) {
                    (void)read_i64(*payload, offset);
                }
                if ((flags & (offset_bit | shift_bit)) != 0) {
                    (void)read_i64(*payload, offset);
                }
            }
            if (offset != payload->size()) {
                throw std::runtime_error(
                    "reference count mismatch during namespace-key scan");
            }
        }
        return false;
    };
    return inspect(from_table_, true) || inspect(to_table_, false);
}

std::int8_t ReferenceManager::combine_type(std::int8_t incoming,
                                           std::int8_t existing) noexcept {
    if (incoming == existing) return existing;
    if (ReferenceType::is_flow(incoming)) return incoming;
    if (ReferenceType::is_flow(existing)) return existing;
    if (incoming == ReferenceType::data &&
        ReferenceType::is_data(existing)) {
        return existing;
    }
    if (incoming == ReferenceType::data_indirect &&
        ReferenceType::is_indirect(existing)) {
        return existing;
    }
    if (incoming == ReferenceType::read &&
        (existing == ReferenceType::write ||
         existing == ReferenceType::read_write)) {
        return ReferenceType::read_write;
    }
    if (incoming == ReferenceType::write &&
        (existing == ReferenceType::read ||
         existing == ReferenceType::read_write)) {
        return ReferenceType::read_write;
    }
    if (incoming == ReferenceType::read_indirect &&
        (existing == ReferenceType::write_indirect ||
         existing == ReferenceType::read_write_indirect)) {
        return ReferenceType::read_write_indirect;
    }
    if (incoming == ReferenceType::write_indirect &&
        (existing == ReferenceType::read_indirect ||
         existing == ReferenceType::read_write_indirect)) {
        return ReferenceType::read_write_indirect;
    }
    return incoming;
}

void ReferenceManager::validate_reference(const Reference &reference) {
    if ((!reference.from.is_memory_address() &&
         !reference.from.is_external_entry_address()) ||
        !reference.to.is_valid()) {
        throw std::invalid_argument("invalid reference address pair");
    }
    if (reference.operand_index < -1 ||
        reference.operand_index > std::numeric_limits<std::int8_t>::max()) {
        throw std::invalid_argument("reference operand index does not fit Ghidra byte storage");
    }
    if (reference.offset_reference && reference.shifted_reference) {
        throw std::invalid_argument(
            "reference cannot be both offset and shifted");
    }
    if (reference.from.is_external_entry_address() &&
        (!reference.to.is_memory_address() ||
         reference.type != ReferenceType::external ||
         reference.operand_index != -1)) {
        throw std::invalid_argument("invalid external-entry reference");
    }
}

void ReferenceManager::upgrade_legacy_stack_and_entries() {
    require_mutation();
    auto stack = database_->get_table(legacy_stack_table_name);
    auto entries = database_->get_table(legacy_external_entries_table_name);
    if (!stack && !entries) return;

    auto references = all_from_records();
    const auto append_unique = [&](Reference reference) {
        if (!std::ranges::any_of(references, [&](const auto &existing) {
                return same_identity(existing, reference);
            })) {
            references.push_back(std::move(reference));
        }
    };

    if (stack) {
        if (!stack->schema().equals(*stack_schema())) {
            throw std::runtime_error("unsupported legacy Stack References table");
        }
        const auto stack_space = address_map_->factory()->stack_space();
        if (!stack_space) {
            throw std::runtime_error(
                "legacy Stack References requires a native stack space");
        }
        auto iterator = stack->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            if (!row) continue;
            Reference reference;
            reference.from = address_map_->decode(std::bit_cast<std::uint64_t>(
                row->field(0).as_integer()));
            reference.to = stack_space->address_signed(
                static_cast<std::int16_t>(row->field(3).as_integer()));
            reference.type = ReferenceType::read;
            reference.operand_index =
                static_cast<std::int32_t>(row->field(1).as_integer());
            reference.source = row->field(2).as_boolean()
                                   ? SourceType::user_defined
                                   : SourceType::analysis;
            validate_reference(reference);
            append_unique(std::move(reference));
        }
    }
    if (entries) {
        auto iterator = entries->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            if (!row) continue;
            Reference reference;
            reference.from = Address::external_entry_address();
            reference.to = address_map_->decode(unsigned_key(*row));
            reference.type = ReferenceType::external;
            reference.operand_index = -1;
            reference.source = SourceType::default_source;
            validate_reference(reference);
            append_unique(std::move(reference));
        }
    }

    replace_current_tables(references);
    if (stack && !database_->delete_table(legacy_stack_table_name)) {
        throw std::runtime_error(
            "failed to delete legacy Stack References table");
    }
    if (entries &&
        !database_->delete_table(legacy_external_entries_table_name)) {
        throw std::runtime_error(
            "failed to delete legacy External Entries table");
    }
}

void ReferenceManager::load_read_only_legacy_supplements() {
    read_only_legacy_supplements_.clear();
    const auto stack = database_->get_table(legacy_stack_table_name);
    if (stack) {
        if (!stack->schema().equals(*stack_schema())) {
            throw std::runtime_error("unsupported legacy Stack References table");
        }
        const auto stack_space = address_map_->factory()->stack_space();
        if (!stack_space) {
            throw std::runtime_error(
                "legacy Stack References requires a native stack space");
        }
        auto iterator = stack->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            if (!row) continue;
            Reference reference;
            reference.from = address_map_->decode(std::bit_cast<std::uint64_t>(
                row->field(0).as_integer()));
            reference.to = stack_space->address_signed(
                static_cast<std::int16_t>(row->field(3).as_integer()));
            reference.type = ReferenceType::read;
            reference.operand_index =
                static_cast<std::int32_t>(row->field(1).as_integer());
            reference.source = row->field(2).as_boolean()
                                   ? SourceType::user_defined
                                   : SourceType::analysis;
            validate_reference(reference);
            read_only_legacy_supplements_.push_back(std::move(reference));
        }
    }
    const auto entries =
        database_->get_table(legacy_external_entries_table_name);
    if (entries) {
        auto iterator = entries->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            if (!row) continue;
            Reference reference;
            reference.from = Address::external_entry_address();
            reference.to = address_map_->decode(unsigned_key(*row));
            reference.type = ReferenceType::external;
            reference.operand_index = -1;
            reference.source = SourceType::default_source;
            validate_reference(reference);
            read_only_legacy_supplements_.push_back(std::move(reference));
        }
    }
}

void ReferenceManager::invalidate_cache() {
    bind_existing_tables();
    legacy_namespace_keys_ =
        current_storage_ && contains_legacy_namespace_keys();
    if (mode_ == ProgramOpenMode::read_only) {
        load_read_only_legacy_supplements();
    }
}

void ReferenceManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

} // namespace llmghidra::program
