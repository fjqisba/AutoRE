#include "llmghidra/program/relocation_manager.hpp"

#include "llmghidra/db/binary_coded_field.hpp"
#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/memory_manager.hpp"

#include <algorithm>
#include <bit>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr std::size_t address_column = 0;
constexpr std::size_t flags_column = 1;
constexpr std::size_t type_column = 2;
constexpr std::size_t values_column = 3;
constexpr std::size_t bytes_column = 4;
constexpr std::size_t symbol_name_column = 5;
constexpr std::uint8_t status_mask = 0x07;
// Preserve the fixed upstream V6 decoder, including its observable four-bit
// length mask despite accepting a five-bit input range.
constexpr std::uint8_t length_mask = 0x0f;
constexpr unsigned length_shift = 3;
constexpr const char *scratch_table_name = "__LLMGHIDRA_RELOCATIONS_V6";

[[nodiscard]] bool status_has_bytes(RelocationStatus status) noexcept {
    return status == RelocationStatus::unknown ||
           status == RelocationStatus::applied ||
           status == RelocationStatus::applied_other;
}

} // namespace

std::shared_ptr<db::Schema> RelocationManager::current_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    fields.push_back(std::make_unique<db::BinaryField>());
    fields.push_back(std::make_unique<db::BinaryField>());
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        schema_version,
        std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Index", std::move(fields),
        std::vector<std::string>{"Address", "Status", "Type", "Values",
                                 "Bytes", "Symbol Name"});
}

std::shared_ptr<db::Schema> RelocationManager::legacy_schema(int version) {
    std::vector<std::unique_ptr<db::Field>> fields;
    std::vector<std::string> names;
    std::string key_name = version <= 4 ? "Address" : "Index";
    switch (version) {
    case 1:
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        names = {"Type"};
        break;
    case 2:
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        names = {"Type", "Values"};
        break;
    case 3:
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        fields.push_back(std::make_unique<db::BinaryField>());
        fields.push_back(std::make_unique<db::BinaryField>());
        names = {"Type", "Values", "Bytes"};
        break;
    case 4:
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        fields.push_back(std::make_unique<db::BinaryField>());
        fields.push_back(std::make_unique<db::BinaryField>());
        fields.push_back(std::make_unique<db::StringField>());
        names = {"Type", "Values", "Bytes", "Symbol Name"};
        break;
    case 5:
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
        fields.push_back(std::make_unique<db::BinaryField>());
        fields.push_back(std::make_unique<db::BinaryField>());
        fields.push_back(std::make_unique<db::StringField>());
        names = {"Address", "Type", "Values", "Bytes", "Symbol Name"};
        break;
    default:
        throw std::invalid_argument("unsupported legacy Relocations version");
    }
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        std::move(key_name), std::move(fields), std::move(names));
}

RelocationManager::RelocationManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    MemoryManager &memory,
    ProgramOpenMode mode,
    bool create,
    std::uint32_t default_pointer_size)
    : database_(std::move(database)), address_map_(&address_map),
      memory_(&memory), mode_(mode),
      default_original_byte_length_(default_pointer_size > 4 ? 8 : 4) {
    if (!database_) {
        throw std::invalid_argument("relocation manager requires a database");
    }
    if (create) {
        table_ = database_->get_table(table_name);
        if (table_) throw std::runtime_error("Relocations table already exists");
        table_ = database_->create_table(table_name, current_schema(),
                                         {address_column});
        source_schema_version_ = schema_version;
    }
    else open_or_upgrade_table();
    validate_table();
}

void RelocationManager::open_or_upgrade_table() {
    table_ = database_->get_table(table_name);
    if (!table_) {
        if (mode_ == ProgramOpenMode::update) {
            throw std::runtime_error(
                "Ghidra Relocations table is missing in update mode");
        }
        if (mode_ == ProgramOpenMode::upgrade) {
            table_ = database_->create_table(table_name, current_schema(),
                                             {address_column});
        }
        source_schema_version_ = schema_version;
        return;
    }

    source_schema_version_ = table_->schema().version();
    if (source_schema_version_ < 1 || source_schema_version_ > schema_version) {
        throw std::runtime_error("unsupported Ghidra Relocations schema version");
    }
    const auto expected = source_schema_version_ == schema_version
                              ? current_schema()
                              : legacy_schema(source_schema_version_);
    if (!table_->schema().equals(*expected)) {
        throw std::runtime_error("unsupported Ghidra Relocations schema");
    }
    const auto indexed = table_->indexed_columns();
    const bool address_index_expected = source_schema_version_ >= 5;
    if ((address_index_expected &&
         (indexed.size() != 1 || indexed.front() != address_column)) ||
        (!address_index_expected && !indexed.empty())) {
        throw std::runtime_error("Ghidra Relocations index contract mismatch");
    }

    const bool rekey_current = source_schema_version_ == schema_version &&
                               address_map_->upgraded();
    if (source_schema_version_ == schema_version && !rekey_current) return;
    if (mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra Relocations table requires upgrade");
    }
    if (mode_ == ProgramOpenMode::read_only) return;
    stage_current_table(source_schema_version_, rekey_current);
}

void RelocationManager::stage_current_table(int source_version,
                                            bool rekey_current) {
    if (mode_ != ProgramOpenMode::upgrade) {
        throw std::logic_error("Relocations staging requires upgrade mode");
    }
    if (source_version == schema_version && !rekey_current) {
        throw std::logic_error(
            "current Relocations table has no migration to stage");
    }
    auto &scratch = database_->scratch_database();
    if (scratch.get_table(scratch_table_name) &&
        !scratch.delete_table(scratch_table_name)) {
        throw std::runtime_error("failed to reset Relocations staging table");
    }
    auto staged = scratch.create_table(
        scratch_table_name, current_schema(), {address_column});
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto source = iterator->next();
        auto translated = translate_source_record(
            *source, source_version, *staged);
        staged->put_record(*translated);
    }

    if (!database_->delete_table(table_name)) {
        throw std::runtime_error("failed to replace Relocations table");
    }
    table_ = database_->create_table(table_name, current_schema(),
                                     {address_column});
    iterator = staged->iterator();
    while (iterator->has_next()) table_->put_record(*iterator->next());
    source_schema_version_ = schema_version;
}

void RelocationManager::validate_table() const {
    if (!table_) return;
    const auto expected = source_schema_version_ == schema_version
                              ? current_schema()
                              : legacy_schema(source_schema_version_);
    if (!table_->schema().equals(*expected)) {
        throw std::runtime_error("unsupported Ghidra Relocations schema");
    }
    const auto indexed = table_->indexed_columns();
    const bool address_index_expected = source_schema_version_ >= 5;
    if ((address_index_expected &&
         (indexed.size() != 1 || indexed.front() != address_column)) ||
        (!address_index_expected && !indexed.empty())) {
        throw std::runtime_error("Ghidra Relocations index contract mismatch");
    }
}

std::uint8_t RelocationManager::encode_flags(
    RelocationStatus status,
    std::uint8_t byte_length) {
    if (static_cast<std::uint8_t>(status) >
            static_cast<std::uint8_t>(RelocationStatus::applied_other) ||
        byte_length > maximum_deferred_byte_length) {
        throw std::invalid_argument("relocation status or byte length is invalid");
    }
    return static_cast<std::uint8_t>(
        (static_cast<std::uint8_t>(status) & status_mask) |
        (byte_length << length_shift));
}

void RelocationManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

Address RelocationManager::decode_source_address(
    const db::Record &record, int source_version) const {
    const auto encoded = std::bit_cast<std::uint64_t>(
        source_version <= 4 ? record.key().as_integer()
                            : record.field(0).as_integer());
    const auto address = source_version <= 5 ||
                                 (source_version == schema_version &&
                                  address_map_->upgraded())
                             ? address_map_->factory()->decode_old_index(encoded)
                             : address_map_->decode(encoded);
    if (!address.is_memory_address()) {
        throw std::runtime_error(
            "Relocations record has an invalid encoded address");
    }
    return address;
}

std::unique_ptr<db::Record> RelocationManager::translate_source_record(
    const db::Record &record, int source_version,
    db::Table &destination) const {
    const auto address = decode_source_address(record, source_version);
    auto translated = current_schema()->create_record(
        destination.next_long_key());
    translated->set_integer(
        address_column,
        std::bit_cast<std::int64_t>(address_map_->key(address, true)));

    if (source_version == schema_version) {
        translated->set_integer(flags_column,
                                record.field(flags_column).as_integer());
        translated->set_integer(type_column,
                                record.field(type_column).as_integer());
        translated->set_bytes(values_column,
                              record.field(values_column).as_bytes());
        translated->set_bytes(bytes_column,
                              record.field(bytes_column).as_bytes());
        translated->set_string(symbol_name_column,
                               record.field(symbol_name_column).as_string());
        return translated;
    }

    translated->set_integer(
        flags_column, encode_flags(RelocationStatus::unknown, 0));
    switch (source_version) {
    case 1:
        translated->set_integer(type_column, record.field(0).as_integer());
        translated->set_null(values_column);
        translated->set_null(bytes_column);
        translated->set_null(symbol_name_column);
        break;
    case 2: {
        translated->set_integer(type_column, record.field(0).as_integer());
        const auto coded = db::BinaryCodedField::from_int64_array(
            std::vector<std::int64_t>{record.field(1).as_integer()});
        translated->set_bytes(values_column, coded.as_bytes());
        translated->set_null(bytes_column);
        translated->set_null(symbol_name_column);
        break;
    }
    case 3:
        translated->set_integer(type_column, record.field(0).as_integer());
        translated->set_bytes(values_column, record.field(1).as_bytes());
        translated->set_bytes(bytes_column, record.field(2).as_bytes());
        translated->set_null(symbol_name_column);
        break;
    case 4:
        translated->set_integer(type_column, record.field(0).as_integer());
        translated->set_bytes(values_column, record.field(1).as_bytes());
        translated->set_bytes(bytes_column, record.field(2).as_bytes());
        translated->set_string(symbol_name_column,
                               record.field(3).as_string());
        break;
    case 5:
        translated->set_integer(type_column, record.field(1).as_integer());
        translated->set_bytes(values_column, record.field(2).as_bytes());
        translated->set_bytes(bytes_column, record.field(3).as_bytes());
        translated->set_string(symbol_name_column,
                               record.field(4).as_string());
        break;
    default:
        throw std::logic_error("unsupported Relocations source schema");
    }
    return translated;
}

Relocation RelocationManager::decode_legacy(const db::Record &record) const {
    Relocation result;
    result.id = record.key().as_integer();
    result.address = decode_source_address(record, source_schema_version_);
    result.status = RelocationStatus::unknown;
    result.deferred_byte_length = 0;
    switch (source_schema_version_) {
    case 1:
        result.type = static_cast<std::int32_t>(record.field(0).as_integer());
        break;
    case 2:
        result.type = static_cast<std::int32_t>(record.field(0).as_integer());
        result.values = std::vector<std::int64_t>{record.field(1).as_integer()};
        break;
    case 3:
        result.type = static_cast<std::int32_t>(record.field(0).as_integer());
        result.values = db::BinaryCodedField(
            db::BinaryField(record.field(1).as_bytes())).int64_array();
        result.original_bytes = record.field(2).as_bytes();
        break;
    case 4:
        result.type = static_cast<std::int32_t>(record.field(0).as_integer());
        result.values = db::BinaryCodedField(
            db::BinaryField(record.field(1).as_bytes())).int64_array();
        result.original_bytes = record.field(2).as_bytes();
        result.symbol_name = record.field(3).as_string();
        break;
    case 5:
        result.type = static_cast<std::int32_t>(record.field(1).as_integer());
        result.values = db::BinaryCodedField(
            db::BinaryField(record.field(2).as_bytes())).int64_array();
        result.original_bytes = record.field(3).as_bytes();
        result.symbol_name = record.field(4).as_string();
        break;
    default:
        throw std::logic_error("record is not from a legacy Relocations table");
    }
    result.original_bytes = resolve_original_bytes(result);
    return result;
}

Relocation RelocationManager::decode(const db::Record &record) const {
    Relocation result;
    result.id = record.key().as_integer();
    result.address = address_map_->decode(std::bit_cast<std::uint64_t>(
        record.field(address_column).as_integer()));
    if (!result.address.is_memory_address()) {
        throw std::runtime_error("Relocations record has an invalid address");
    }
    const auto flags = static_cast<std::uint8_t>(
        record.field(flags_column).as_integer());
    const auto stored_status = flags & status_mask;
    result.status = stored_status <=
                            static_cast<std::uint8_t>(
                                RelocationStatus::applied_other)
        ? static_cast<RelocationStatus>(stored_status)
        : RelocationStatus::unknown;
    result.deferred_byte_length =
        static_cast<std::uint8_t>((flags >> length_shift) & length_mask);
    result.type = static_cast<std::int32_t>(
        record.field(type_column).as_integer());
    db::BinaryField values_field(record.field(values_column).as_bytes());
    result.values = db::BinaryCodedField(values_field).int64_array();
    result.original_bytes = record.field(bytes_column).as_bytes();
    result.symbol_name = record.field(symbol_name_column).as_string();
    result.original_bytes = resolve_original_bytes(result);
    return result;
}

std::optional<std::vector<std::uint8_t>>
RelocationManager::resolve_original_bytes(const Relocation &relocation) const {
    if (relocation.original_bytes || !status_has_bytes(relocation.status)) {
        return relocation.original_bytes;
    }
    std::size_t length = relocation.deferred_byte_length;
    if (length == 0) length = default_original_byte_length_;
    return original_file_bytes(relocation.address, length);
}

std::vector<std::uint8_t> RelocationManager::original_file_bytes(
    const Address &address, std::size_t length) const {
    std::vector<std::uint8_t> result(length, 0);
    Address current = address;
    for (std::size_t index = 0; index < length; ++index) {
        const auto source = memory_->address_source_info(current);
        if (!source) return result;
        result[index] = source->original_value.value_or(0);
        if (index + 1 != length) {
            const auto next = current.next();
            if (!next) break;
            current = *next;
        }
    }
    return result;
}

Relocation RelocationManager::add(
    const Address &address,
    RelocationStatus status,
    std::int32_t type,
    std::optional<std::vector<std::int64_t>> values,
    std::optional<std::vector<std::uint8_t>> original_bytes,
    std::optional<std::string> symbol_name) {
    require_mutation();
    if (!address.is_memory_address()) {
        throw std::invalid_argument("relocation requires a memory address");
    }
    if (!table_) {
        table_ = database_->create_table(table_name, current_schema(),
                                         {address_column});
    }
    auto record = current_schema()->create_record(table_->next_long_key());
    record->set_integer(address_column, std::bit_cast<std::int64_t>(
        address_map_->key(address, true)));
    record->set_integer(flags_column, encode_flags(status, 0));
    record->set_integer(type_column, type);
    auto coded = db::BinaryCodedField::from_int64_array(values);
    record->set_bytes(values_column, coded.as_bytes());
    record->set_bytes(bytes_column, original_bytes);
    record->set_string(symbol_name_column, symbol_name);
    table_->put_record(*record);
    return decode(*record);
}

Relocation RelocationManager::add_with_deferred_bytes(
    const Address &address,
    RelocationStatus status,
    std::int32_t type,
    std::optional<std::vector<std::int64_t>> values,
    std::uint8_t byte_length,
    std::optional<std::string> symbol_name) {
    require_mutation();
    if (!address.is_memory_address()) {
        throw std::invalid_argument("relocation requires a memory address");
    }
    if (!table_) {
        table_ = database_->create_table(table_name, current_schema(),
                                         {address_column});
    }
    auto record = current_schema()->create_record(table_->next_long_key());
    record->set_integer(address_column, std::bit_cast<std::int64_t>(
        address_map_->key(address, true)));
    record->set_integer(flags_column, encode_flags(status, byte_length));
    record->set_integer(type_column, type);
    auto coded = db::BinaryCodedField::from_int64_array(values);
    record->set_bytes(values_column, coded.as_bytes());
    record->set_null(bytes_column);
    record->set_string(symbol_name_column, symbol_name);
    table_->put_record(*record);
    return decode(*record);
}

std::vector<Relocation> RelocationManager::all() const {
    std::vector<Relocation> result;
    if (!table_) return result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        if (auto record = iterator->next()) {
            result.push_back(source_schema_version_ == schema_version
                                 ? decode(*record)
                                 : decode_legacy(*record));
        }
    }
    std::ranges::sort(result, [](const Relocation &left,
                                const Relocation &right) {
        if (left.address != right.address) return left.address < right.address;
        return left.id < right.id;
    });
    return result;
}

std::vector<Relocation> RelocationManager::at(const Address &address) const {
    auto result = all();
    std::erase_if(result, [&](const Relocation &value) {
        return value.address != address;
    });
    return result;
}

std::vector<Relocation> RelocationManager::in(const AddressSet &set) const {
    auto result = all();
    std::erase_if(result, [&](const Relocation &value) {
        return !set.contains(value.address);
    });
    return result;
}

std::optional<Address> RelocationManager::address_after(
    const Address &address) const {
    for (const auto &value : all()) {
        if (value.address > address) return value.address;
    }
    return std::nullopt;
}

bool RelocationManager::has_relocation(const Address &address) const {
    return !at(address).empty();
}

std::size_t RelocationManager::size() const {
    return table_ ? static_cast<std::size_t>(table_->record_count()) : 0;
}

bool RelocationManager::relocatable(
    std::optional<bool> program_property) const {
    return program_property.value_or(size() != 0);
}

std::size_t RelocationManager::readable_current_bytes(
    const Address &address, std::span<std::uint8_t> destination) const {
    Address cursor = address;
    for (std::size_t index = 0; index < destination.size(); ++index) {
        try {
            destination[index] = memory_->read_byte(cursor);
        }
        catch (const MemoryAccessError &) {
            if (index == 0) {
                throw std::runtime_error(
                    "loaded relocation address is unexpectedly unreadable");
            }
            return index;
        }
        if (index + 1 != destination.size()) {
            const auto next = cursor.next();
            if (!next) return index + 1;
            cursor = *next;
        }
    }
    return destination.size();
}

std::uint8_t RelocationManager::infer_pre_v6_byte_length(
    const std::vector<std::shared_ptr<db::Record>> &records,
    std::size_t index, std::uint32_t default_pointer_size) const {
    const auto address = address_map_->decode(std::bit_cast<std::uint64_t>(
        records[index]->field(address_column).as_integer()));
    std::size_t length = default_pointer_size > 4 ? 8 : 4;
    if (index + 1 < records.size()) {
        const auto next = address_map_->decode(std::bit_cast<std::uint64_t>(
            records[index + 1]->field(address_column).as_integer()));
        if (next.same_space(address)) {
            const auto distance = next.subtract(address);
            if (distance < 0) {
                throw std::runtime_error(
                    "Relocations address ordering is inconsistent");
            }
            length = std::min(
                length, static_cast<std::size_t>(distance));
        }
    }
    if (length == 0) return 0;

    while (length != 0) {
        try {
            (void)address.add_no_wrap(static_cast<std::int64_t>(length - 1));
            break;
        }
        catch (const AddressError &) {
            --length;
        }
    }
    if (length == 0) return 0;

    const auto original = original_file_bytes(address, length);
    std::vector<std::uint8_t> current(length, 0);
    length = readable_current_bytes(address, current);
    while (length != 0 && original[length - 1] == current[length - 1]) {
        --length;
    }
    return static_cast<std::uint8_t>(length);
}

void RelocationManager::refine_pre_v6_statuses(
    std::uint32_t default_pointer_size) {
    if (mode_ != ProgramOpenMode::upgrade) {
        throw std::logic_error(
            "pre-V6 Relocations refinement requires upgrade mode");
    }
    require_mutation();
    if (!table_) return;
    if (source_schema_version_ != schema_version ||
        !table_->schema().equals(*current_schema())) {
        throw std::logic_error(
            "pre-V6 Relocations refinement requires a staged V6 table");
    }

    std::vector<std::shared_ptr<db::Record>> records;
    records.reserve(static_cast<std::size_t>(table_->record_count()));
    auto iterator = table_->iterator();
    while (iterator->has_next()) records.push_back(iterator->next());
    std::ranges::sort(records, [&](const auto &left, const auto &right) {
        const auto left_address = address_map_->decode(
            std::bit_cast<std::uint64_t>(
                left->field(address_column).as_integer()));
        const auto right_address = address_map_->decode(
            std::bit_cast<std::uint64_t>(
                right->field(address_column).as_integer()));
        if (left_address != right_address) return left_address < right_address;
        return left->key().as_integer() < right->key().as_integer();
    });

    for (std::size_t index = 0; index < records.size(); ++index) {
        auto &record = records[index];
        const auto address = address_map_->decode(
            std::bit_cast<std::uint64_t>(
                record->field(address_column).as_integer()));
        const auto block = memory_->block_containing(address);
        const bool loaded_and_initialized =
            address.is_loaded_memory_address() && block && block->initialized();
        const auto stored_bytes = record->field(bytes_column).as_bytes();
        const auto type = static_cast<std::int32_t>(
            record->field(type_column).as_integer());
        RelocationStatus status = RelocationStatus::unknown;
        std::uint8_t byte_length = 0;
        if (!loaded_and_initialized) {
            status = RelocationStatus::failure;
        }
        else if (stored_bytes) {
            status = type == 0 ? RelocationStatus::applied_other
                               : RelocationStatus::applied;
        }
        else {
            byte_length = infer_pre_v6_byte_length(
                records, index, default_pointer_size);
            if (byte_length != 0) {
                status = type == 0 ? RelocationStatus::applied_other
                                   : RelocationStatus::applied;
            }
        }
        record->set_integer(flags_column, encode_flags(status, byte_length));
        table_->put_record(*record);
    }
}

void RelocationManager::invalidate_cache() {
    table_ = database_->get_table(table_name);
    source_schema_version_ = table_ ? table_->schema().version()
                                    : schema_version;
    validate_table();
}

} // namespace llmghidra::program
