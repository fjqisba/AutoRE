#include "llmghidra/program/listing_manager.hpp"

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
constexpr const char *data_table_name = "Data";
constexpr const char *instruction_table_name = "Instructions";
constexpr const char *prototype_table_name = "Prototypes";
constexpr const char *context_table_name = "ContextTable";
constexpr const char *scratch_data_name = "__LLMGHIDRA_LISTING_DATA";
constexpr const char *scratch_instruction_name = "__LLMGHIDRA_LISTING_INSTRUCTIONS";
constexpr const char *scratch_prototype_name = "__LLMGHIDRA_LISTING_PROTOTYPES";
constexpr const char *scratch_context_name = "__LLMGHIDRA_LISTING_CONTEXT";
constexpr std::uint8_t length_override_mask = 0x70;
constexpr std::uint8_t length_override_shift = 4;

[[nodiscard]] std::vector<std::unique_ptr<db::Field>> fields(
    std::initializer_list<F> types) {
    std::vector<std::unique_ptr<db::Field>> result;
    result.reserve(types.size());
    for (const auto type : types) result.push_back(db::make_field(type));
    return result;
}

[[nodiscard]] std::shared_ptr<db::Schema> schema(
    int version, std::string key_name, std::initializer_list<F> types,
    std::vector<std::string> names) {
    return std::make_shared<db::Schema>(
        version, db::make_field(F::int64), std::move(key_name), fields(types),
        std::move(names));
}

[[nodiscard]] std::uint64_t unsigned_key(std::int64_t value) noexcept {
    return std::bit_cast<std::uint64_t>(value);
}

[[nodiscard]] std::int64_t signed_key(std::uint64_t value) noexcept {
    return std::bit_cast<std::int64_t>(value);
}

[[nodiscard]] const db::BinaryField &binary_field(
    const db::Record &record, std::size_t column) {
    const auto *field = dynamic_cast<const db::BinaryField *>(&record.field(column));
    if (!field) throw std::runtime_error("prototype record has non-binary bytes");
    return *field;
}

[[nodiscard]] std::string converted_legacy_context(std::string value) {
    // V0 stored comma-separated signed 32-bit words. Preserve zero and already
    // decimal values here; non-trivial V0 conversion is completed below by the
    // same two's-complement decimal path used for every legacy row.
    if (value.find(',') == std::string::npos) return value.empty() ? "0" : value;
    std::vector<std::uint8_t> bytes;
    std::size_t cursor = 0;
    while (cursor <= value.size()) {
        const auto comma = value.find(',', cursor);
        const auto end = comma == std::string::npos ? value.size() : comma;
        const auto token = value.substr(cursor, end - cursor);
        if (token.empty()) throw std::runtime_error("invalid legacy context value");
        std::size_t parsed = 0;
        const auto word = std::stoll(token, &parsed, 10);
        if (parsed != token.size() ||
            word < std::numeric_limits<std::int32_t>::min() ||
            word > std::numeric_limits<std::int32_t>::max()) {
            throw std::runtime_error("invalid legacy context word");
        }
        const auto encoded = static_cast<std::uint32_t>(
            static_cast<std::int32_t>(word));
        bytes.push_back(static_cast<std::uint8_t>(encoded >> 24));
        bytes.push_back(static_cast<std::uint8_t>(encoded >> 16));
        bytes.push_back(static_cast<std::uint8_t>(encoded >> 8));
        bytes.push_back(static_cast<std::uint8_t>(encoded));
        if (comma == std::string::npos) break;
        cursor = comma + 1;
    }
    const bool negative = !bytes.empty() && (bytes.front() & 0x80U) != 0;
    if (negative) {
        for (auto &byte : bytes) byte = static_cast<std::uint8_t>(~byte);
        for (auto position = bytes.rbegin(); position != bytes.rend(); ++position) {
            *position = static_cast<std::uint8_t>(*position + 1U);
            if (*position != 0) break;
        }
    }
    std::vector<std::uint32_t> decimal{0};
    for (const auto byte : bytes) {
        std::uint64_t carry = byte;
        for (auto &part : decimal) {
            const auto next = static_cast<std::uint64_t>(part) * 256U + carry;
            part = static_cast<std::uint32_t>(next % 1'000'000'000U);
            carry = next / 1'000'000'000U;
        }
        if (carry != 0) decimal.push_back(static_cast<std::uint32_t>(carry));
    }
    std::string result = negative ? "-" : "";
    result += std::to_string(decimal.back());
    for (auto position = decimal.rbegin() + 1; position != decimal.rend(); ++position) {
        auto part = std::to_string(*position);
        result.append(9 - part.size(), '0');
        result += part;
    }
    return result;
}

} // namespace

std::shared_ptr<db::Schema> ListingManager::data_schema() {
    return schema(0, "Address", {F::int64}, {"Data Type ID"});
}

std::shared_ptr<db::Schema> ListingManager::instruction_schema() {
    return schema(1, "Address", {F::int32, F::byte}, {"Proto ID", "Flags"});
}

std::shared_ptr<db::Schema> ListingManager::legacy_instruction_schema() {
    return schema(0, "Address", {F::int32}, {"Proto ID"});
}

std::shared_ptr<db::Schema> ListingManager::prototype_schema() {
    return schema(1, "Keys", {F::binary, F::int64, F::boolean},
                  {"Bytes", "Address", "InDelaySlot"});
}

std::shared_ptr<db::Schema> ListingManager::legacy_prototype_schema() {
    return schema(0, "Keys", {F::binary, F::int64}, {"Bytes", "Address"});
}

std::shared_ptr<db::Schema> ListingManager::context_schema() {
    return schema(1, "Keys", {F::string}, {"Register Context"});
}

std::shared_ptr<db::Schema> ListingManager::legacy_context_schema() {
    return schema(0, "Keys", {F::string}, {"Register Context"});
}

ListingManager::ListingManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map, ProgramOpenMode mode, bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) throw std::invalid_argument("listing manager requires a database");
    if (create) create_tables();
    else open_tables();
    validate_tables();
}

void ListingManager::create_tables() {
    data_table_ = database_->create_table(data_table_name, data_schema());
    instruction_table_ = database_->create_table(
        instruction_table_name, instruction_schema());
    prototype_table_ = database_->create_table(
        prototype_table_name, prototype_schema());
    context_table_ = database_->create_table(context_table_name, context_schema());
}

void ListingManager::open_tables() {
    open_code_unit_tables();
    open_prototype_tables();
}

void ListingManager::open_code_unit_tables() {
    auto source_data = database_->get_table(data_table_name);
    auto source_instructions = database_->get_table(instruction_table_name);
    if (!source_data || !source_data->schema().equals(*data_schema()) ||
        !source_instructions) {
        throw std::runtime_error("unsupported Ghidra Listing code-unit table family");
    }
    const bool current_instructions =
        source_instructions->schema().equals(*instruction_schema());
    const bool legacy_instructions =
        source_instructions->schema().equals(*legacy_instruction_schema());
    if (!current_instructions && !legacy_instructions) {
        throw std::runtime_error("unsupported Ghidra Instructions schema");
    }
    const bool rekey = address_map_->upgraded();
    if (!rekey && current_instructions) {
        data_table_ = std::move(source_data);
        instruction_table_ = std::move(source_instructions);
        return;
    }
    if (mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra Listing code-unit tables require upgrade");
    }

    auto &scratch = database_->scratch_database();
    for (const auto *name : {scratch_data_name, scratch_instruction_name}) {
        if (scratch.get_table(name) && !scratch.delete_table(name)) {
            throw std::runtime_error("failed to reset Listing staging table");
        }
    }
    auto staged_data = scratch.create_table(scratch_data_name, data_schema());
    auto staged_instructions = scratch.create_table(
        scratch_instruction_name, instruction_schema());

    auto iterator = source_data->iterator();
    while (iterator->has_next()) {
        const auto old = iterator->next();
        auto record = data_schema()->create_record(old->key().as_integer());
        if (rekey) {
            const auto address = address_map_->factory()->decode_old_index(
                unsigned_key(old->key().as_integer()));
            record = data_schema()->create_record(
                signed_key(address_map_->key(address, true)));
        }
        record->set_integer(0, old->field(0).as_integer());
        staged_data->put_record(*record);
    }
    iterator = source_instructions->iterator();
    while (iterator->has_next()) {
        const auto old = iterator->next();
        auto key = old->key().as_integer();
        if (rekey) {
            const auto address = address_map_->factory()->decode_old_index(
                unsigned_key(key));
            key = signed_key(address_map_->key(address, true));
        }
        auto record = instruction_schema()->create_record(key);
        record->set_integer(0, old->field(0).as_integer());
        record->set_integer(1, legacy_instructions ? 0
                                                   : old->field(1).as_integer());
        staged_instructions->put_record(*record);
    }

    if (mode_ == ProgramOpenMode::upgrade) {
        if (!database_->delete_table(data_table_name) ||
            !database_->delete_table(instruction_table_name)) {
            throw std::runtime_error("failed to replace Listing code-unit tables");
        }
        data_table_ = database_->create_table(data_table_name, data_schema());
        instruction_table_ = database_->create_table(
            instruction_table_name, instruction_schema());
        iterator = staged_data->iterator();
        while (iterator->has_next()) data_table_->put_record(*iterator->next());
        iterator = staged_instructions->iterator();
        while (iterator->has_next()) {
            instruction_table_->put_record(*iterator->next());
        }
    }
    else {
        data_table_ = std::move(staged_data);
        instruction_table_ = std::move(staged_instructions);
    }
}

void ListingManager::open_prototype_tables() {
    auto source_prototypes = database_->get_table(prototype_table_name);
    auto source_context = database_->get_table(context_table_name);
    if (!source_prototypes) {
        throw std::runtime_error("Ghidra Prototypes table is missing");
    }
    const bool current_prototypes =
        source_prototypes->schema().equals(*prototype_schema());
    const bool legacy_prototypes =
        source_prototypes->schema().equals(*legacy_prototype_schema());
    if (!current_prototypes && !legacy_prototypes) {
        throw std::runtime_error("unsupported Ghidra Prototypes schema");
    }
    const bool current_context = source_context &&
        source_context->schema().equals(*context_schema());
    const bool legacy_context = source_context &&
        source_context->schema().equals(*legacy_context_schema());
    if (source_context && !current_context && !legacy_context) {
        throw std::runtime_error("unsupported Ghidra ContextTable schema");
    }
    const bool rekey = address_map_->upgraded();
    if (current_prototypes && current_context && !rekey) {
        prototype_table_ = std::move(source_prototypes);
        context_table_ = std::move(source_context);
        return;
    }
    if (mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra prototype tables require upgrade");
    }

    auto &scratch = database_->scratch_database();
    for (const auto *name : {scratch_prototype_name, scratch_context_name}) {
        if (scratch.get_table(name) && !scratch.delete_table(name)) {
            throw std::runtime_error("failed to reset prototype staging table");
        }
    }
    auto staged_prototypes = scratch.create_table(
        scratch_prototype_name, prototype_schema());
    auto staged_context = scratch.create_table(
        scratch_context_name, context_schema());
    std::set<std::int64_t> prototype_keys;
    auto iterator = source_prototypes->iterator();
    while (iterator->has_next()) {
        const auto old = iterator->next();
        auto key = old->key().as_integer();
        if (legacy_prototypes && key < 0) {
            if (key == std::numeric_limits<std::int64_t>::min()) {
                throw std::runtime_error("legacy prototype key cannot be normalized");
            }
            key = -key;
        }
        if (key < 0 || key > std::numeric_limits<std::int32_t>::max() ||
            !prototype_keys.insert(key).second) {
            throw std::runtime_error("prototype ID is invalid or duplicated");
        }
        auto address_key = old->field(1).as_integer();
        if (rekey) {
            const auto address = address_map_->factory()->decode_old_index(
                unsigned_key(address_key));
            address_key = signed_key(address_map_->key(address, true));
        }
        auto record = prototype_schema()->create_record(key);
        record->set_field(0, binary_field(*old, 0).clone());
        record->set_integer(1, address_key);
        record->set_boolean(2, legacy_prototypes
                                   ? false
                                   : old->field(2).as_boolean());
        staged_prototypes->put_record(*record);
    }
    if (source_context) {
        iterator = source_context->iterator();
        while (iterator->has_next()) {
            const auto old = iterator->next();
            auto key = old->key().as_integer();
            if (legacy_prototypes && key < 0) key = -key;
            if (!prototype_keys.contains(key)) {
                throw std::runtime_error("ContextTable references a missing prototype");
            }
            auto record = context_schema()->create_record(key);
            const auto value = old->field(0).as_string().value_or("0");
            record->set_string(0, legacy_context
                                      ? converted_legacy_context(value)
                                      : value);
            staged_context->put_record(*record);
        }
    }

    if (mode_ == ProgramOpenMode::upgrade) {
        if (!database_->delete_table(prototype_table_name)) {
            throw std::runtime_error("failed to replace Prototypes table");
        }
        if (source_context && !database_->delete_table(context_table_name)) {
            throw std::runtime_error("failed to replace ContextTable");
        }
        prototype_table_ = database_->create_table(
            prototype_table_name, prototype_schema());
        context_table_ = database_->create_table(
            context_table_name, context_schema());
        iterator = staged_prototypes->iterator();
        while (iterator->has_next()) {
            prototype_table_->put_record(*iterator->next());
        }
        iterator = staged_context->iterator();
        while (iterator->has_next()) context_table_->put_record(*iterator->next());
    }
    else {
        prototype_table_ = std::move(staged_prototypes);
        context_table_ = std::move(staged_context);
    }
}

void ListingManager::validate_tables() const {
    if (!data_table_ || !instruction_table_ || !prototype_table_ ||
        !context_table_ || !data_table_->schema().equals(*data_schema()) ||
        !instruction_table_->schema().equals(*instruction_schema()) ||
        !prototype_table_->schema().equals(*prototype_schema()) ||
        !context_table_->schema().equals(*context_schema())) {
        throw std::runtime_error("Listing table family is incomplete or inconsistent");
    }
    std::set<std::int32_t> prototype_ids;
    for (const auto &value : prototypes()) {
        if (!prototype_ids.insert(value.id).second || value.bytes.empty() ||
            !value.source_address.is_memory_address()) {
            throw std::runtime_error("instruction prototype is invalid or duplicated");
        }
    }
    for (const auto &value : instructions()) {
        if (!prototype_ids.contains(value.prototype_id)) {
            throw std::runtime_error("instruction references a missing prototype");
        }
    }
    std::set<Address> starts;
    for (const auto &value : instructions()) {
        if (!starts.insert(value.address).second) {
            throw std::runtime_error("multiple code units share an address");
        }
    }
    for (const auto &value : defined_data()) {
        if (!starts.insert(value.address).second) {
            throw std::runtime_error("multiple code units share an address");
        }
    }
    struct UnitRange {
        Address start;
        Address end;
    };
    std::vector<UnitRange> ranges;
    for (const auto &value : instructions()) {
        ranges.push_back({value.address, value.address.add_no_wrap(
            static_cast<std::int64_t>(value.length - 1))});
    }
    for (const auto &value : defined_data()) {
        ranges.push_back({value.address, value.address.add_no_wrap(
            static_cast<std::int64_t>(value.length - 1))});
    }
    for (std::size_t left = 0; left < ranges.size(); ++left) {
        for (std::size_t right = left + 1; right < ranges.size(); ++right) {
            if (!ranges[left].start.same_space(ranges[right].start)) continue;
            if (!(ranges[left].end < ranges[right].start ||
                  ranges[right].end < ranges[left].start)) {
                throw std::runtime_error("persisted code-unit ranges overlap");
            }
        }
    }
    auto iterator = context_table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        const auto key = record->key().as_integer();
        if (key < 0 || key > std::numeric_limits<std::int32_t>::max() ||
            !prototype_ids.contains(static_cast<std::int32_t>(key))) {
            throw std::runtime_error("ContextTable references a missing prototype");
        }
        const auto value = record->field(0).as_string();
        if (!value || value->empty()) {
            throw std::runtime_error("ContextTable contains an empty value");
        }
    }
}

void ListingManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

void ListingManager::set_data_type_length_resolver(
    DataTypeLengthResolver resolver) {
    data_type_length_resolver_ = std::move(resolver);
    (void)defined_data();
}

void ListingManager::set_available_length_resolver(
    AvailableLengthResolver resolver) {
    available_length_resolver_ = std::move(resolver);
    validate_tables();
}

Address ListingManager::decode_address_key(std::int64_t key) const {
    const auto result = address_map_->decode(unsigned_key(key));
    if (!result.is_memory_address()) {
        throw std::runtime_error("Listing record has an invalid address key");
    }
    return result;
}

std::uint64_t ListingManager::data_length(
    std::int64_t data_type_id, const Address &address) const {
    if (data_type_length_resolver_) {
        const auto resolved = data_type_length_resolver_(data_type_id, address);
        if (resolved > 0) return static_cast<std::uint64_t>(resolved);
    }
    std::uint64_t available = available_length_resolver_
                                  ? available_length_resolver_(address)
                                  : 1;
    if (available == 0) available = 1;
    std::optional<std::uint64_t> next_distance;
    const auto consider = [&](const std::shared_ptr<db::Table> &table) {
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            const auto candidate = decode_address_key(
                iterator->next()->key().as_integer());
            if (!candidate.same_space(address) || !(address < candidate)) continue;
            const auto distance = static_cast<std::uint64_t>(
                candidate.subtract(address));
            if (!next_distance || distance < *next_distance) {
                next_distance = distance;
            }
        }
    };
    consider(data_table_);
    consider(instruction_table_);
    if (next_distance) available = std::min(available, *next_distance);
    return std::max<std::uint64_t>(available, 1);
}

InstructionPrototypeRecord ListingManager::decode_prototype(
    const db::Record &record) const {
    const auto id = record.key().as_integer();
    const auto bytes = binary_field(record, 0).as_bytes();
    if (id < 0 || id > std::numeric_limits<std::int32_t>::max() ||
        !bytes || bytes->empty()) {
        throw std::runtime_error("instruction prototype record is invalid");
    }
    std::optional<std::string> context;
    if (const auto context_record = context_table_->record(id)) {
        context = context_record->field(0).as_string();
    }
    return {static_cast<std::int32_t>(id), *bytes,
            decode_address_key(record.field(1).as_integer()),
            record.field(2).as_boolean(), std::move(context)};
}

InstructionRecord ListingManager::decode_instruction(
    const db::Record &record) const {
    const auto prototype_id = record.field(0).as_integer();
    const auto flags_value = record.field(1).as_integer();
    if (prototype_id < 0 ||
        prototype_id > std::numeric_limits<std::int32_t>::max() ||
        flags_value < 0 || flags_value > std::numeric_limits<std::uint8_t>::max()) {
        throw std::runtime_error("instruction record is invalid");
    }
    const auto value = prototype(static_cast<std::int32_t>(prototype_id));
    if (!value) throw std::runtime_error("instruction prototype is missing");
    auto length = static_cast<std::uint32_t>(value->bytes.size());
    const auto flags = static_cast<std::uint8_t>(flags_value);
    const auto override_length = static_cast<std::uint32_t>(
        (flags & length_override_mask) >> length_override_shift);
    if (override_length != 0 && override_length < length) length = override_length;
    return {decode_address_key(record.key().as_integer()),
            static_cast<std::int32_t>(prototype_id), flags, length};
}

DefinedDataRecord ListingManager::decode_data(const db::Record &record) const {
    const auto address = decode_address_key(record.key().as_integer());
    const auto data_type_id = record.field(0).as_integer();
    return {address, data_type_id, data_length(data_type_id, address)};
}

std::optional<InstructionPrototypeRecord> ListingManager::prototype(
    std::int32_t id) const {
    const auto record = prototype_table_->record(id);
    return record ? std::optional<InstructionPrototypeRecord>(
                        decode_prototype(*record))
                  : std::nullopt;
}

std::vector<InstructionPrototypeRecord> ListingManager::prototypes() const {
    std::vector<InstructionPrototypeRecord> result;
    auto iterator = prototype_table_->iterator();
    while (iterator->has_next()) {
        result.push_back(decode_prototype(*iterator->next()));
    }
    return result;
}

InstructionPrototypeRecord ListingManager::create_prototype(
    std::span<const std::uint8_t> bytes, const Address &source_address,
    bool in_delay_slot, std::optional<std::string> base_context_value) {
    require_mutation();
    if (bytes.empty() || !source_address.is_memory_address()) {
        throw std::invalid_argument("instruction prototype requires bytes and memory address");
    }
    const auto id = prototype_table_->next_long_key();
    if (id < 0 || id > std::numeric_limits<std::int32_t>::max()) {
        throw std::overflow_error("instruction prototype IDs are exhausted");
    }
    auto record = prototype_schema()->create_record(id);
    record->set_bytes(0, std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
    record->set_integer(1, signed_key(address_map_->key(source_address, true)));
    record->set_boolean(2, in_delay_slot);
    prototype_table_->put_record(*record);
    if (base_context_value) {
        if (base_context_value->empty()) base_context_value = "0";
        auto context = context_schema()->create_record(id);
        context->set_string(0, std::move(base_context_value));
        context_table_->put_record(*context);
    }
    return decode_prototype(*record);
}

void ListingManager::clear_prototypes() {
    require_mutation();
    if (instruction_table_->record_count() != 0) {
        throw std::logic_error("instruction prototypes are still referenced");
    }
    prototype_table_->delete_all();
    context_table_->delete_all();
}

std::vector<InstructionRecord> ListingManager::instructions() const {
    std::vector<InstructionRecord> result;
    auto iterator = instruction_table_->iterator();
    while (iterator->has_next()) {
        result.push_back(decode_instruction(*iterator->next()));
    }
    std::ranges::sort(result, {}, &InstructionRecord::address);
    return result;
}

std::vector<DefinedDataRecord> ListingManager::defined_data() const {
    std::vector<DefinedDataRecord> result;
    auto iterator = data_table_->iterator();
    while (iterator->has_next()) result.push_back(decode_data(*iterator->next()));
    std::ranges::sort(result, {}, &DefinedDataRecord::address);
    return result;
}

std::optional<InstructionRecord> ListingManager::instruction_at(
    const Address &address) const {
    const auto key = address_map_->key(address, false);
    if (key == PersistentAddressMap::invalid_key) return std::nullopt;
    const auto record = instruction_table_->record(signed_key(key));
    return record ? std::optional<InstructionRecord>(decode_instruction(*record))
                  : std::nullopt;
}

std::optional<DefinedDataRecord> ListingManager::data_at(
    const Address &address) const {
    const auto key = address_map_->key(address, false);
    if (key == PersistentAddressMap::invalid_key) return std::nullopt;
    const auto record = data_table_->record(signed_key(key));
    return record ? std::optional<DefinedDataRecord>(decode_data(*record))
                  : std::nullopt;
}

void ListingManager::require_unoccupied(
    const Address &start, std::uint64_t length,
    std::optional<Address> ignored_start) const {
    if (!start.is_memory_address() || length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("invalid code-unit range");
    }
    const auto end = start.add_no_wrap(static_cast<std::int64_t>(length - 1));
    const auto conflicts = [&](const Address &candidate_start,
                               std::uint64_t candidate_length) {
        if (ignored_start && candidate_start == *ignored_start) return false;
        if (!candidate_start.same_space(start)) return false;
        const auto candidate_end = candidate_start.add_no_wrap(
            static_cast<std::int64_t>(candidate_length - 1));
        return !(end < candidate_start || candidate_end < start);
    };
    for (const auto &value : instructions()) {
        if (conflicts(value.address, value.length)) {
            throw std::invalid_argument("code-unit range overlaps an instruction");
        }
    }
    for (const auto &value : defined_data()) {
        if (conflicts(value.address, value.length)) {
            throw std::invalid_argument("code-unit range overlaps defined data");
        }
    }
}

InstructionRecord ListingManager::create_instruction(
    const Address &address, std::int32_t prototype_id, std::uint8_t flags) {
    require_mutation();
    const auto proto = prototype(prototype_id);
    if (!proto) throw std::out_of_range("instruction prototype does not exist");
    auto length = static_cast<std::uint32_t>(proto->bytes.size());
    const auto override_length = static_cast<std::uint32_t>(
        (flags & length_override_mask) >> length_override_shift);
    if (override_length != 0 && override_length < length) length = override_length;
    require_unoccupied(address, length);
    const auto key = signed_key(address_map_->key(address, true));
    auto record = instruction_schema()->create_record(key);
    record->set_integer(0, prototype_id);
    record->set_integer(1, flags);
    instruction_table_->put_record(*record);
    return decode_instruction(*record);
}

DefinedDataRecord ListingManager::create_data(
    const Address &address, std::int64_t data_type_id) {
    require_mutation();
    const auto length = data_length(data_type_id, address);
    require_unoccupied(address, length);
    auto record = data_schema()->create_record(
        signed_key(address_map_->key(address, true)));
    record->set_integer(0, data_type_id);
    data_table_->put_record(*record);
    return decode_data(*record);
}

void ListingManager::set_instruction_flags(
    const Address &address, std::uint8_t flags) {
    require_mutation();
    const auto key = address_map_->key(address, false);
    if (key == PersistentAddressMap::invalid_key) {
        throw std::out_of_range("instruction does not exist");
    }
    auto record = instruction_table_->record(signed_key(key));
    if (!record) throw std::out_of_range("instruction does not exist");
    const auto previous = decode_instruction(*record);
    record->set_integer(1, flags);
    const auto updated = decode_instruction(*record);
    if (updated.length > previous.length) {
        require_unoccupied(address, updated.length, address);
    }
    instruction_table_->put_record(*record);
}

bool ListingManager::remove_instruction(const Address &address) {
    require_mutation();
    const auto key = address_map_->key(address, false);
    return key != PersistentAddressMap::invalid_key &&
           instruction_table_->delete_record(signed_key(key));
}

bool ListingManager::remove_data(const Address &address) {
    require_mutation();
    const auto key = address_map_->key(address, false);
    return key != PersistentAddressMap::invalid_key &&
           data_table_->delete_record(signed_key(key));
}

void ListingManager::delete_address_range(
    const Address &start, const Address &end) {
    require_mutation();
    if (!start.same_space(end) || end < start) {
        throw std::invalid_argument("invalid Listing delete range");
    }
    std::vector<Address> instruction_starts;
    std::vector<Address> data_starts;
    const auto intersects = [&](const Address &unit_start, std::uint64_t length) {
        if (!unit_start.same_space(start)) return false;
        const auto unit_end = unit_start.add_no_wrap(
            static_cast<std::int64_t>(length - 1));
        return !(unit_end < start || end < unit_start);
    };
    for (const auto &value : instructions()) {
        if (intersects(value.address, value.length)) {
            instruction_starts.push_back(value.address);
        }
    }
    for (const auto &value : defined_data()) {
        if (intersects(value.address, value.length)) data_starts.push_back(value.address);
    }
    for (const auto &address : instruction_starts) (void)remove_instruction(address);
    for (const auto &address : data_starts) (void)remove_data(address);
}

void ListingManager::move_address_range(
    const Address &from, const Address &to, std::uint64_t length) {
    require_mutation();
    if (length == 0 || length - 1 > static_cast<std::uint64_t>(
                                    std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("invalid Listing move length");
    }
    const auto from_end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    (void)to.add_no_wrap(static_cast<std::int64_t>(length - 1));
    std::vector<std::pair<std::unique_ptr<db::Record>, Address>> instruction_rows;
    std::vector<std::pair<std::unique_ptr<db::Record>, Address>> data_rows;
    const auto collect = [&](const std::shared_ptr<db::Table> &table,
                             auto &rows) {
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            const auto address = decode_address_key(record->key().as_integer());
            if (address.same_space(from) && !(address < from) &&
                !(from_end < address)) {
                rows.emplace_back(std::move(record), address);
            }
        }
    };
    collect(instruction_table_, instruction_rows);
    collect(data_table_, data_rows);

    std::set<Address> moving_starts;
    for (const auto &[record, address] : instruction_rows) moving_starts.insert(address);
    for (const auto &[record, address] : data_rows) moving_starts.insert(address);
    const auto ensure_destination = [&](const Address &old_address,
                                        std::uint64_t unit_length) {
        const auto destination = to.add_no_wrap(old_address.subtract(from));
        for (const auto &value : instructions()) {
            if (!moving_starts.contains(value.address)) {
                const auto value_end = value.address.add_no_wrap(
                    static_cast<std::int64_t>(value.length - 1));
                const auto destination_end = destination.add_no_wrap(
                    static_cast<std::int64_t>(unit_length - 1));
                if (value.address.same_space(destination) &&
                    !(destination_end < value.address || value_end < destination)) {
                    throw std::invalid_argument("Listing move destination conflicts");
                }
            }
        }
        for (const auto &value : defined_data()) {
            if (!moving_starts.contains(value.address)) {
                const auto value_end = value.address.add_no_wrap(
                    static_cast<std::int64_t>(value.length - 1));
                const auto destination_end = destination.add_no_wrap(
                    static_cast<std::int64_t>(unit_length - 1));
                if (value.address.same_space(destination) &&
                    !(destination_end < value.address || value_end < destination)) {
                    throw std::invalid_argument("Listing move destination conflicts");
                }
            }
        }
    };
    for (const auto &[record, address] : instruction_rows) {
        ensure_destination(address, decode_instruction(*record).length);
    }
    for (const auto &[record, address] : data_rows) {
        ensure_destination(address, decode_data(*record).length);
    }

    for (const auto &[record, address] : instruction_rows) {
        (void)instruction_table_->delete_record(record->key().as_integer());
    }
    for (const auto &[record, address] : data_rows) {
        (void)data_table_->delete_record(record->key().as_integer());
    }
    for (auto &[record, address] : instruction_rows) {
        const auto destination = to.add_no_wrap(address.subtract(from));
        record->set_key(signed_key(address_map_->key(destination, true)));
        instruction_table_->put_record(*record);
    }
    for (auto &[record, address] : data_rows) {
        const auto destination = to.add_no_wrap(address.subtract(from));
        record->set_key(signed_key(address_map_->key(destination, true)));
        data_table_->put_record(*record);
    }
}

std::size_t ListingManager::replace_data_type(
    std::int64_t replaced_id, std::int64_t replacement_id) {
    require_mutation();
    std::size_t count = 0;
    auto iterator = data_table_->iterator();
    std::vector<std::unique_ptr<db::Record>> changed;
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (record->field(0).as_integer() == replaced_id) {
            record->set_integer(0, replacement_id);
            changed.push_back(std::move(record));
        }
    }
    for (const auto &record : changed) {
        data_table_->put_record(*record);
        ++count;
    }
    return count;
}

void ListingManager::invalidate_cache() {
    if (mode_ == ProgramOpenMode::read_only) return;
    data_table_ = database_->get_table(data_table_name);
    instruction_table_ = database_->get_table(instruction_table_name);
    prototype_table_ = database_->get_table(prototype_table_name);
    context_table_ = database_->get_table(context_table_name);
    validate_tables();
}

} // namespace llmghidra::program
