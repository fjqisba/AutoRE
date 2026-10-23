#include "llmghidra/program/memory_manager.hpp"

#include "llmghidra/db/binary_coded_field.hpp"
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

[[nodiscard]] std::vector<std::unique_ptr<db::Field>> fields(
    std::initializer_list<F> types) {
    std::vector<std::unique_ptr<db::Field>> result;
    result.reserve(types.size());
    for (const auto type : types) result.push_back(db::make_field(type));
    return result;
}

[[nodiscard]] std::shared_ptr<db::Schema> schema(
    int version, std::string key_name,
    std::initializer_list<F> types,
    std::vector<std::string> names) {
    return std::make_shared<db::Schema>(
        version, db::make_field(F::int64), std::move(key_name), fields(types),
        std::move(names));
}

[[nodiscard]] bool schema_matches(
    const db::Table &table, int version, std::string key_name,
    std::initializer_list<F> types, std::vector<std::string> names) {
    return table.schema().equals(
        *schema(version, std::move(key_name), types, std::move(names)));
}

[[nodiscard]] std::shared_ptr<db::ChainedBuffer> shared_buffer(
    std::unique_ptr<db::ChainedBuffer> value) {
    return std::shared_ptr<db::ChainedBuffer>(std::move(value));
}

[[nodiscard]] const db::BinaryField &binary_field(const db::Record &record,
                                                   std::size_t column) {
    const auto *field = dynamic_cast<const db::BinaryField *>(&record.field(column));
    if (!field) throw std::runtime_error("File Bytes record has a non-binary buffer list");
    return *field;
}

[[nodiscard]] std::int64_t signed_key(std::uint64_t value) noexcept {
    return std::bit_cast<std::int64_t>(value);
}

[[nodiscard]] std::uint64_t unsigned_key(std::int64_t value) noexcept {
    return std::bit_cast<std::uint64_t>(value);
}

enum class LegacyMemorySchema {
    current,
    v0,
    v1,
    v2,
};

class ActiveAddressGuard final {
public:
    ActiveAddressGuard(std::vector<Address> &active, Address address)
        : active_(&active) {
        active_->push_back(std::move(address));
    }
    ~ActiveAddressGuard() { active_->pop_back(); }
    ActiveAddressGuard(const ActiveAddressGuard &) = delete;
    ActiveAddressGuard &operator=(const ActiveAddressGuard &) = delete;

private:
    std::vector<Address> *active_;
};

} // namespace

struct MemoryManager::FileBytesState {
    FileBytesInfo info;
    std::vector<std::shared_ptr<db::ChainedBuffer>> original;
    std::vector<std::shared_ptr<db::ChainedBuffer>> layered;
};

ByteMappingScheme ByteMappingScheme::decode(std::int32_t encoded) {
    if (encoded == 0) return {};
    ByteMappingScheme result{
        static_cast<std::uint8_t>((encoded >> 7U) & 0x7f),
        static_cast<std::uint8_t>(encoded & 0x7f)};
    (void)result.encode();
    return result;
}

std::int32_t ByteMappingScheme::encode() const {
    if (mapped_bytes == 0 || source_bytes == 0 || mapped_bytes > 0x7f ||
        source_bytes > 0x7f || mapped_bytes > source_bytes) {
        throw std::invalid_argument("invalid byte mapping ratio");
    }
    if (mapped_bytes == 1 && source_bytes == 1) return 0;
    return (static_cast<std::int32_t>(mapped_bytes) << 7U) |
           static_cast<std::int32_t>(source_bytes);
}

std::uint64_t ByteMappingScheme::source_offset(
    std::uint64_t mapped_offset) const {
    (void)encode();
    const auto groups = mapped_offset / mapped_bytes;
    const auto remainder = mapped_offset % mapped_bytes;
    if (groups >
        (std::numeric_limits<std::uint64_t>::max() - remainder) /
            source_bytes) {
        throw std::overflow_error("byte-mapped source offset overflows");
    }
    return static_cast<std::uint64_t>(source_bytes) * groups + remainder;
}

Address MemoryBlock::end() const {
    if (length == 0 || length - 1 >
                           static_cast<std::uint64_t>(
                               std::numeric_limits<std::int64_t>::max())) {
        throw AddressOverflowError("memory block length cannot be represented");
    }
    return start.add_no_wrap(static_cast<std::int64_t>(length - 1));
}

bool MemoryBlock::contains(const Address &address) const noexcept {
    if (length == 0 || !start.same_space(address) || address < start) return false;
    try {
        return static_cast<std::uint64_t>(address.subtract(start)) < length;
    }
    catch (...) {
        return false;
    }
}

bool MemoryBlock::initialized() const noexcept {
    return std::ranges::all_of(sub_blocks, [](const MemorySubBlock &sub) {
        return sub.type == MemorySubBlockType::buffer ||
               sub.type == MemorySubBlockType::file_bytes;
    });
}

bool MemoryBlock::mapped() const noexcept {
    return sub_blocks.size() == 1 &&
           (sub_blocks.front().type == MemorySubBlockType::bit_mapped ||
            sub_blocks.front().type == MemorySubBlockType::byte_mapped);
}

MemoryBlockType MemoryBlock::type() const noexcept {
    if (!mapped()) return MemoryBlockType::default_block;
    return sub_blocks.front().type == MemorySubBlockType::bit_mapped
               ? MemoryBlockType::bit_mapped
               : MemoryBlockType::byte_mapped;
}

std::shared_ptr<db::Schema> MemoryManager::block_schema() {
    return schema(3, "Key",
                  {F::string, F::string, F::string, F::byte, F::int64,
                   F::int64, F::int32},
                  {"Name", "Comments", "Source Name", "Flags",
                   "Start Address", "Length", "Segment"});
}

std::shared_ptr<db::Schema> MemoryManager::sub_block_schema() {
    return schema(3, "Key",
                  {F::int64, F::byte, F::int64, F::int64, F::int32,
                   F::int64},
                  {"Parent ID", "Type", "Length", "Starting Offset",
                   "Source ID", "Source Address/Offset"});
}

std::shared_ptr<db::Schema> MemoryManager::file_bytes_schema() {
    return schema(0, "Key",
                  {F::string, F::int64, F::int64, F::binary, F::binary},
                  {"Filename", "Offset", "Size", "Chain Buffer IDs",
                   "Layered Chain Buffer IDs"});
}

MemoryManager::MemoryManager(std::shared_ptr<db::DatabaseHandle> database,
                             PersistentAddressMap &address_map,
                             ProgramOpenMode mode,
                             bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) throw std::invalid_argument("memory manager requires a database");
    if (create) create_tables();
    else open_tables();
    validate_tables();
}

void MemoryManager::create_tables() {
    block_table_ = database_->create_table("Memory Blocks", block_schema());
    sub_block_table_ = database_->create_table("Sub Memory Blocks", sub_block_schema());
    file_bytes_table_ = database_->create_table("File Bytes", file_bytes_schema());
}

void MemoryManager::open_tables() {
    auto current_blocks = database_->get_table("Memory Blocks");
    auto current_sub_blocks = database_->get_table("Sub Memory Blocks");
    auto old_blocks = database_->get_table("Memory Block");
    LegacyMemorySchema legacy{};

    if (current_blocks && current_blocks->schema().equals(*block_schema()) &&
        current_sub_blocks &&
        current_sub_blocks->schema().equals(*sub_block_schema())) {
        legacy = LegacyMemorySchema::current;
    }
    else if (current_blocks && !current_sub_blocks &&
             schema_matches(
                 *current_blocks, 2, "Key",
                 {F::string, F::string, F::string, F::byte, F::int64,
                  F::int16, F::int64, F::int64, F::int32, F::int32},
                 {"Name", "Comments", "Source Name", "Permissions",
                  "Start Address", "Block Type", "Overlay Address", "Length",
                  "Chain Buffer ID", "Segment"})) {
        legacy = LegacyMemorySchema::v2;
    }
    else if (old_blocks && !current_blocks && !current_sub_blocks &&
             schema_matches(
                 *old_blocks, 0, "Key",
                 {F::string, F::int32, F::string, F::string, F::string,
                  F::int64, F::boolean, F::boolean, F::boolean, F::int64,
                  F::int64, F::int16, F::int64, F::int64},
                 {"Name", "Chain Buffer ID", "Comments", "Description",
                  "Source Name", "Source Offset", "Is Read", "Is Write",
                  "Is Execute", "Start Address", "Length", "Block Type",
                  "Base Address", "Source Block ID"})) {
        legacy = LegacyMemorySchema::v0;
    }
    else if (old_blocks && !current_blocks && !current_sub_blocks &&
             schema_matches(
                 *old_blocks, 1, "Key",
                 {F::string, F::int32, F::string, F::string, F::string,
                  F::int64, F::boolean, F::boolean, F::boolean, F::int64,
                  F::int64, F::int16, F::int64, F::int64, F::int32},
                 {"Name", "Chain Buffer ID", "Comments", "Description",
                  "Source Name", "Source Offset", "Is Read", "Is Write",
                  "Is Execute", "Start Address", "Length", "Block Type",
                  "Base Address", "Source Block ID", "Segment"})) {
        legacy = LegacyMemorySchema::v1;
    }
    else {
        throw std::runtime_error("unsupported Ghidra MemoryMapDB schema family");
    }

    auto file_table = database_->get_table("File Bytes");
    const bool missing_file_bytes = !file_table;
    if (file_table && !file_table->schema().equals(*file_bytes_schema())) {
        throw std::runtime_error("unsupported Ghidra File Bytes schema");
    }
    if (missing_file_bytes && legacy == LegacyMemorySchema::current) {
        auto iterator = current_sub_blocks->iterator();
        while (iterator->has_next()) {
            const auto record = iterator->next();
            if (record->field(1).as_integer() ==
                static_cast<std::uint8_t>(MemorySubBlockType::file_bytes)) {
                throw std::runtime_error(
                    "File Bytes table is missing while memory still references it");
            }
        }
    }
    const bool rekey_current_addresses =
        legacy == LegacyMemorySchema::current && address_map_->upgraded();
    const bool migration_required = legacy != LegacyMemorySchema::current ||
                                    missing_file_bytes ||
                                    rekey_current_addresses;
    if (migration_required && mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra memory tables require upgrade");
    }
    if (!migration_required) {
        block_table_ = std::move(current_blocks);
        sub_block_table_ = std::move(current_sub_blocks);
        file_bytes_table_ = std::move(file_table);
        return;
    }

    auto &scratch = database_->scratch_database();
    for (const auto *name : {"__LLMGHIDRA_MEMORY_BLOCKS",
                             "__LLMGHIDRA_MEMORY_SUB_BLOCKS",
                             "__LLMGHIDRA_FILE_BYTES"}) {
        if (scratch.get_table(name) && !scratch.delete_table(name)) {
            throw std::runtime_error("failed to reset memory staging table");
        }
    }
    auto staged_blocks = scratch.create_table(
        "__LLMGHIDRA_MEMORY_BLOCKS", block_schema());
    auto staged_sub_blocks = scratch.create_table(
        "__LLMGHIDRA_MEMORY_SUB_BLOCKS", sub_block_schema());
    std::shared_ptr<db::Table> staged_file_bytes;
    if (missing_file_bytes) {
        staged_file_bytes = scratch.create_table(
            "__LLMGHIDRA_FILE_BYTES", file_bytes_schema());
    }

    if (legacy == LegacyMemorySchema::current) {
        auto iterator = current_blocks->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (rekey_current_addresses) {
                const auto address = address_map_->decode(
                    unsigned_key(record->field(4).as_integer()));
                if (!address.is_valid()) {
                    throw std::runtime_error(
                        "memory block start cannot be rekeyed after AddressMap upgrade");
                }
                record->set_integer(
                    4, signed_key(address_map_->key(address, true)));
            }
            staged_blocks->put_record(*record);
        }
        iterator = current_sub_blocks->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            const auto type = record->field(1).as_integer();
            if (rekey_current_addresses &&
                (type == static_cast<std::uint8_t>(MemorySubBlockType::bit_mapped) ||
                 type == static_cast<std::uint8_t>(MemorySubBlockType::byte_mapped))) {
                const auto address = address_map_->decode(
                    unsigned_key(record->field(5).as_integer()));
                if (!address.is_valid()) {
                    throw std::runtime_error(
                        "mapped memory source cannot be rekeyed after AddressMap upgrade");
                }
                record->set_integer(
                    5, signed_key(address_map_->key(address, true)));
            }
            staged_sub_blocks->put_record(*record);
        }
    }
    else {
        auto source_table = legacy == LegacyMemorySchema::v2
                                ? current_blocks
                                : old_blocks;
        std::int64_t next_key = 0;
        auto iterator = source_table->iterator();
        while (iterator->has_next()) {
            auto old = iterator->next();
            auto block = block_schema()->create_record(next_key);
            auto sub = sub_block_schema()->create_record(next_key);
            std::int64_t length{};
            std::int64_t buffer_id{};
            std::int64_t type{};
            std::int64_t mapped_key{};
            std::int32_t segment{};
            if (legacy == LegacyMemorySchema::v2) {
                block->set_string(0, old->field(0).as_string());
                block->set_string(1, old->field(1).as_string());
                block->set_string(2, old->field(2).as_string());
                block->set_integer(3, old->field(3).as_integer());
                block->set_integer(4, old->field(4).as_integer());
                length = old->field(7).as_integer();
                type = old->field(5).as_integer();
                mapped_key = old->field(6).as_integer();
                buffer_id = old->field(8).as_integer();
                segment = static_cast<std::int32_t>(old->field(9).as_integer());
            }
            else {
                block->set_string(0, old->field(0).as_string());
                block->set_string(1, old->field(2).as_string());
                block->set_string(2, old->field(4).as_string());
                std::uint8_t flags = 0;
                if (old->field(6).as_boolean()) flags |= MemoryBlock::read;
                if (old->field(7).as_boolean()) flags |= MemoryBlock::write;
                if (old->field(8).as_boolean()) flags |= MemoryBlock::execute;
                block->set_integer(3, flags);
                auto start = address_map_->factory()->decode_old_index(
                    unsigned_key(old->field(9).as_integer()));
                if (legacy == LegacyMemorySchema::v1 && start.segment()) {
                    segment = static_cast<std::int32_t>(old->field(14).as_integer());
                    if (segment >= 0 && segment <= 0xffff) {
                        start = start.normalize_segment(
                            static_cast<std::uint16_t>(segment));
                    }
                }
                block->set_integer(4, signed_key(address_map_->key(start, false)));
                length = old->field(10).as_integer();
                type = old->field(11).as_integer();
                buffer_id = old->field(1).as_integer();
                if (type == 2 || type == 4) {
                    const auto mapped = address_map_->factory()->decode_old_index(
                        unsigned_key(old->field(12).as_integer()));
                    mapped_key = signed_key(address_map_->key(mapped, false));
                }
            }
            if (length <= 0) {
                throw std::runtime_error("legacy memory block has invalid length");
            }
            block->set_integer(5, length);
            block->set_integer(6, segment);
            sub->set_integer(0, next_key);
            sub->set_integer(2, length);
            sub->set_integer(3, 0);
            switch (type) {
            case 0:
                sub->set_integer(1,
                                 static_cast<std::uint8_t>(MemorySubBlockType::buffer));
                sub->set_integer(4, buffer_id);
                break;
            case 1:
                sub->set_integer(
                    1, static_cast<std::uint8_t>(MemorySubBlockType::uninitialized));
                break;
            case 2:
                sub->set_integer(
                    1, static_cast<std::uint8_t>(MemorySubBlockType::bit_mapped));
                sub->set_integer(5, mapped_key);
                break;
            case 4:
                sub->set_integer(
                    1, static_cast<std::uint8_t>(MemorySubBlockType::byte_mapped));
                sub->set_integer(5, mapped_key);
                break;
            default:
                throw std::runtime_error("legacy memory block has unknown type");
            }
            staged_blocks->put_record(*block);
            staged_sub_blocks->put_record(*sub);
            ++next_key;
        }
    }

    if (mode_ == ProgramOpenMode::upgrade) {
        if (legacy != LegacyMemorySchema::current || rekey_current_addresses) {
            const auto source_name = legacy == LegacyMemorySchema::v2
                                         ? "Memory Blocks"
                                         : "Memory Block";
            if (legacy == LegacyMemorySchema::current) {
                if (!database_->delete_table("Sub Memory Blocks") ||
                    !database_->delete_table("Memory Blocks")) {
                    throw std::runtime_error(
                        "failed to replace rekeyed memory tables");
                }
            }
            else if (!database_->delete_table(source_name)) {
                throw std::runtime_error("failed to remove legacy memory block table");
            }
            block_table_ = database_->create_table("Memory Blocks", block_schema());
            sub_block_table_ = database_->create_table(
                "Sub Memory Blocks", sub_block_schema());
            auto copy = [](const std::shared_ptr<db::Table> &source,
                           const std::shared_ptr<db::Table> &destination) {
                auto iterator = source->iterator();
                while (iterator->has_next()) destination->put_record(*iterator->next());
            };
            copy(staged_blocks, block_table_);
            copy(staged_sub_blocks, sub_block_table_);
        }
        else {
            block_table_ = std::move(current_blocks);
            sub_block_table_ = std::move(current_sub_blocks);
        }
        if (missing_file_bytes) {
            file_bytes_table_ = database_->create_table(
                "File Bytes", file_bytes_schema());
        }
        else {
            file_bytes_table_ = std::move(file_table);
        }
    }
    else {
        block_table_ = legacy == LegacyMemorySchema::current
                           ? std::move(current_blocks)
                           : std::move(staged_blocks);
        sub_block_table_ = legacy == LegacyMemorySchema::current
                               ? std::move(current_sub_blocks)
                               : std::move(staged_sub_blocks);
        file_bytes_table_ = missing_file_bytes ? std::move(staged_file_bytes)
                                               : std::move(file_table);
    }
}

void MemoryManager::validate_tables() const {
    if (!block_table_ || !sub_block_table_ || !file_bytes_table_ ||
        !block_table_->schema().equals(*block_schema()) ||
        !sub_block_table_->schema().equals(*sub_block_schema()) ||
        !file_bytes_table_->schema().equals(*file_bytes_schema())) {
        throw std::runtime_error("memory table family is incomplete or inconsistent");
    }

    const auto decoded_blocks = blocks();
    std::set<std::int64_t> block_ids;
    std::set<std::string> block_names;
    for (const auto &value : decoded_blocks) {
        if (value.name.empty() ||
            (value.flags & ~MemoryBlock::valid_flags) != 0 ||
            !block_ids.insert(value.id).second ||
            !block_names.insert(value.name).second) {
            throw std::runtime_error("memory block metadata is invalid or duplicated");
        }
        (void)value.end();
    }
    for (std::size_t left = 0; left < decoded_blocks.size(); ++left) {
        for (std::size_t right = left + 1;
             right < decoded_blocks.size(); ++right) {
            const auto &first = decoded_blocks[left];
            const auto &second = decoded_blocks[right];
            if (!first.start.same_space(second.start)) continue;
            if (!(first.end() < second.start || second.end() < first.start)) {
                throw std::runtime_error("persisted memory blocks overlap");
            }
        }
    }

    auto sub_iterator = sub_block_table_->iterator();
    while (sub_iterator->has_next()) {
        const auto record = sub_iterator->next();
        if (!block_ids.contains(record->field(0).as_integer())) {
            throw std::runtime_error("orphan memory sub-block record");
        }
    }

    auto file_iterator = file_bytes_table_->iterator();
    while (file_iterator->has_next()) {
        const auto record = file_iterator->next();
        if (!file_bytes_state(record->key().as_integer())) {
            throw std::runtime_error("File Bytes record cannot be opened");
        }
    }

    for (const auto &value : decoded_blocks) {
        for (const auto &sub : value.sub_blocks) {
            switch (sub.type) {
            case MemorySubBlockType::buffer: {
                if (sub.length > static_cast<std::uint64_t>(
                                     maximum_chained_buffer_size)) {
                    throw std::runtime_error(
                        "memory buffer sub-block exceeds chained-buffer limit");
                }
                const auto buffer = database_->open_chained_buffer(sub.source_id);
                if (buffer->size() != sub.length) {
                    throw std::runtime_error(
                        "memory buffer sub-block length differs from backing buffer");
                }
                break;
            }
            case MemorySubBlockType::file_bytes: {
                if (sub.source_address_or_offset < 0) {
                    throw std::runtime_error("File Bytes source offset is negative");
                }
                const auto state = file_bytes_state(sub.source_id);
                const auto offset = static_cast<std::uint64_t>(
                    sub.source_address_or_offset);
                if (!state || offset > state->info.size ||
                    sub.length > state->info.size - offset) {
                    throw std::runtime_error(
                        "memory sub-block references an invalid File Bytes range");
                }
                break;
            }
            case MemorySubBlockType::bit_mapped:
            case MemorySubBlockType::byte_mapped: {
                const auto source = address_map_->decode(
                    unsigned_key(sub.source_address_or_offset));
                if (!source.is_memory_address()) {
                    throw std::runtime_error(
                        "mapped memory sub-block has an invalid source address");
                }
                std::uint64_t last_source_offset{};
                if (sub.type == MemorySubBlockType::bit_mapped) {
                    if (sub.source_id != 0) {
                        throw std::runtime_error(
                            "bit-mapped memory has an unexpected mapping scheme");
                    }
                    last_source_offset = (sub.length - 1) / 8;
                }
                else {
                    last_source_offset = ByteMappingScheme::decode(
                        sub.source_id).source_offset(sub.length - 1);
                }
                if (last_source_offset > static_cast<std::uint64_t>(
                                             std::numeric_limits<std::int64_t>::max())) {
                    throw std::runtime_error(
                        "mapped memory source range cannot be represented");
                }
                (void)source.add_no_wrap(
                    static_cast<std::int64_t>(last_source_offset));
                break;
            }
            case MemorySubBlockType::uninitialized:
                break;
            }
        }
    }
}

void MemoryManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

MemoryBlock MemoryManager::decode_block(const db::Record &record) const {
    const auto length_value = record.field(5).as_integer();
    if (length_value <= 0) throw std::runtime_error("memory block has invalid length");
    const auto flags_value = record.field(3).as_integer();
    if (flags_value < 0 || flags_value > MemoryBlock::valid_flags) {
        throw std::runtime_error("memory block has invalid flags");
    }
    auto start = address_map_->decode(unsigned_key(record.field(4).as_integer()));
    const auto segment = static_cast<std::int32_t>(record.field(6).as_integer());
    if (!start.is_valid()) throw std::runtime_error("memory block has invalid start address");
    if (start.segment() && segment >= 0 && segment <= 0xffff) {
        start = start.normalize_segment(static_cast<std::uint16_t>(segment));
    }
    MemoryBlock result{
        record.key().as_integer(),
        record.field(0).as_string().value_or(std::string{}),
        record.field(1).as_string(), record.field(2).as_string(),
        static_cast<std::uint8_t>(flags_value), start,
        static_cast<std::uint64_t>(length_value), segment, {}};
    auto iterator = sub_block_table_->iterator();
    while (iterator->has_next()) {
        auto sub = iterator->next();
        if (sub->field(0).as_integer() != result.id) continue;
        const auto type_value = sub->field(1).as_integer();
        const auto sub_length = sub->field(2).as_integer();
        const auto sub_offset = sub->field(3).as_integer();
        if (type_value < 0 || type_value > 4 || sub_length <= 0 || sub_offset < 0) {
            throw std::runtime_error("memory sub-block record is invalid");
        }
        result.sub_blocks.push_back(MemorySubBlock{
            sub->key().as_integer(), result.id,
            static_cast<MemorySubBlockType>(type_value),
            static_cast<std::uint64_t>(sub_length),
            static_cast<std::uint64_t>(sub_offset),
            static_cast<std::int32_t>(sub->field(4).as_integer()),
            sub->field(5).as_integer()});
    }
    std::ranges::sort(result.sub_blocks, {}, &MemorySubBlock::starting_offset);
    std::uint64_t expected = 0;
    for (const auto &sub : result.sub_blocks) {
        if (sub.starting_offset != expected || sub.length > result.length - expected) {
            throw std::runtime_error("memory sub-blocks do not exactly partition block");
        }
        expected += sub.length;
    }
    if (expected != result.length) {
        throw std::runtime_error("memory block has incomplete sub-block coverage");
    }
    return result;
}

std::vector<MemoryBlock> MemoryManager::blocks() const {
    std::vector<MemoryBlock> result;
    auto iterator = block_table_->iterator();
    while (iterator->has_next()) result.push_back(decode_block(*iterator->next()));
    std::ranges::sort(result, [](const MemoryBlock &left, const MemoryBlock &right) {
        return left.start < right.start;
    });
    return result;
}

std::optional<MemoryBlock> MemoryManager::block(std::int64_t id) const {
    auto record = block_table_->record(id);
    return record ? std::optional<MemoryBlock>(decode_block(*record)) : std::nullopt;
}

std::optional<MemoryBlock> MemoryManager::block_containing(
    const Address &address) const {
    for (auto &candidate : blocks()) {
        if (candidate.contains(address)) return candidate;
    }
    return std::nullopt;
}

void MemoryManager::require_block_range(
    const Address &start, std::uint64_t length,
    std::optional<std::int64_t> except) const {
    if (!start.is_memory_address() || length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("invalid memory block range");
    }
    const auto end = start.add_no_wrap(static_cast<std::int64_t>(length - 1));
    for (const auto &existing : blocks()) {
        if (except == existing.id || !existing.start.same_space(start)) continue;
        if (!(end < existing.start || existing.end() < start)) {
            throw std::invalid_argument("memory block overlaps an existing block");
        }
    }
}

void MemoryManager::require_unique_block_name(
    const std::string &name, std::optional<std::int64_t> except) const {
    if (name.empty()) throw std::invalid_argument("memory block name is empty");
    for (const auto &existing : blocks()) {
        if (existing.name == name && existing.id != except) {
            throw std::invalid_argument("memory block name is already in use");
        }
    }
}

std::string MemoryManager::unique_split_name(const std::string &base) const {
    std::string candidate = base + ".split";
    std::uint64_t suffix = 1;
    while (std::ranges::any_of(blocks(), [&](const MemoryBlock &existing) {
        return existing.name == candidate;
    })) {
        candidate = base + ".split" + std::to_string(suffix++);
    }
    return candidate;
}

Address MemoryManager::resolve_block_start(
    const std::string &name, const Address &start,
    std::uint64_t length, bool overlay) const {
    if (!start.is_memory_address() || length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("invalid memory block range");
    }
    if (!overlay || (start.space() && start.space()->is_overlay_space())) {
        return start;
    }
    if (!external_overlay_creation_handler_) {
        throw std::logic_error(
            "overlay memory creation is not connected to the program");
    }
    return external_overlay_creation_handler_(name, start, length);
}

void MemoryManager::notify_region_change() const {
    if (external_region_change_handler_) external_region_change_handler_();
}

std::shared_ptr<MemoryManager::FileBytesState>
MemoryManager::file_bytes_state(std::int64_t id) const {
    for (const auto &cached : file_bytes_cache_) {
        if (cached->info.id == id) return cached;
    }
    auto record = file_bytes_table_->record(id);
    if (!record) return {};
    const auto size = record->field(2).as_integer();
    if (size <= 0) throw std::runtime_error("File Bytes record has invalid size");
    if (record->field(1).as_integer() < 0) {
        throw std::runtime_error("File Bytes record has a negative file offset");
    }
    db::BinaryCodedField original_field(binary_field(*record, 3));
    db::BinaryCodedField layered_field(binary_field(*record, 4));
    const auto original_ids = original_field.int32_array();
    const auto layered_ids = layered_field.int32_array();
    if (!original_ids || !layered_ids || original_ids->empty() ||
        original_ids->size() != layered_ids->size()) {
        throw std::runtime_error("File Bytes record has invalid buffer IDs");
    }
    auto state = std::make_shared<FileBytesState>();
    state->info = FileBytesInfo{
        id, record->field(0).as_string().value_or(std::string{}),
        record->field(1).as_integer(), static_cast<std::uint64_t>(size)};
    std::uint64_t total = 0;
    for (std::size_t index = 0; index < original_ids->size(); ++index) {
        auto original = shared_buffer(
            database_->open_chained_buffer(original_ids->at(index)));
        auto layered = shared_buffer(database_->open_layered_chained_buffer(
            layered_ids->at(index), *original));
        if (original->size() != layered->size()) {
            throw std::runtime_error("File Bytes layered buffer length differs");
        }
        if (original->size() > state->info.size - total) {
            throw std::runtime_error("File Bytes buffers exceed persisted size");
        }
        total += original->size();
        state->original.push_back(std::move(original));
        state->layered.push_back(std::move(layered));
    }
    if (total != state->info.size) {
        throw std::runtime_error("File Bytes buffers do not match persisted size");
    }
    file_bytes_cache_.push_back(state);
    return state;
}

FileBytesInfo MemoryManager::create_file_bytes(
    std::string filename, std::int64_t file_offset,
    std::span<const std::uint8_t> bytes) {
    require_mutation();
    if (bytes.empty() || file_offset < 0 ||
        bytes.size() > static_cast<std::size_t>(
                           std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("File Bytes requires non-empty non-negative input");
    }
    std::vector<std::int32_t> original_ids;
    std::vector<std::int32_t> layered_ids;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = std::min<std::size_t>(
            maximum_chained_buffer_size, bytes.size() - offset);
        auto original = database_->create_chained_buffer(
            static_cast<std::int32_t>(count));
        original->put(0, bytes.subspan(offset, count));
        auto layered = database_->create_layered_chained_buffer(
            static_cast<std::int32_t>(count), *original);
        original_ids.push_back(original->id());
        layered_ids.push_back(layered->id());
        offset += count;
    }
    const auto id = file_bytes_table_->next_long_key();
    auto record = file_bytes_schema()->create_record(id);
    record->set_string(0, std::move(filename));
    record->set_integer(1, file_offset);
    record->set_integer(2, static_cast<std::int64_t>(bytes.size()));
    auto originals = db::BinaryCodedField::from_int32_array(original_ids);
    auto layered = db::BinaryCodedField::from_int32_array(layered_ids);
    record->set_field(3, originals.clone());
    record->set_field(4, layered.clone());
    file_bytes_table_->put_record(*record);
    invalidate_caches();
    return FileBytesInfo{id, record->field(0).as_string().value_or(std::string{}),
                         file_offset, bytes.size()};
}

std::vector<FileBytesInfo> MemoryManager::file_bytes() const {
    std::vector<FileBytesInfo> result;
    auto iterator = file_bytes_table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        auto state = file_bytes_state(record->key().as_integer());
        result.push_back(state->info);
    }
    return result;
}

std::vector<std::uint8_t> MemoryManager::read_file_bytes(
    std::int64_t id, std::uint64_t offset, std::size_t length,
    bool original) const {
    const auto state = file_bytes_state(id);
    if (!state || offset > state->info.size ||
        length > state->info.size - offset) {
        throw std::out_of_range("File Bytes read is outside stored range");
    }
    std::vector<std::uint8_t> result(length);
    std::size_t destination = 0;
    std::uint64_t cursor = offset;
    const auto &buffers = original ? state->original : state->layered;
    for (const auto &buffer : buffers) {
        if (destination == length) break;
        if (cursor >= buffer->size()) {
            cursor -= buffer->size();
            continue;
        }
        const auto count = std::min<std::size_t>(
            length - destination, buffer->size() - cursor);
        buffer->get(cursor, std::span<std::uint8_t>(result).subspan(destination, count));
        destination += count;
        cursor = 0;
    }
    return result;
}

void MemoryManager::write_file_bytes(
    std::int64_t id, std::uint64_t offset,
    std::span<const std::uint8_t> bytes) {
    require_mutation();
    const auto state = file_bytes_state(id);
    if (!state || offset > state->info.size ||
        bytes.size() > state->info.size - offset) {
        throw std::out_of_range("File Bytes write is outside stored range");
    }
    std::size_t source = 0;
    std::uint64_t cursor = offset;
    for (const auto &buffer : state->layered) {
        if (source == bytes.size()) break;
        if (cursor >= buffer->size()) {
            cursor -= buffer->size();
            continue;
        }
        const auto count = std::min<std::size_t>(
            bytes.size() - source, buffer->size() - cursor);
        buffer->put(cursor, bytes.subspan(source, count));
        source += count;
        cursor = 0;
    }
}

bool MemoryManager::remove_file_bytes(std::int64_t id) {
    require_mutation();
    auto sub_iterator = sub_block_table_->iterator();
    while (sub_iterator->has_next()) {
        auto sub = sub_iterator->next();
        if (sub->field(1).as_integer() ==
                static_cast<std::uint8_t>(MemorySubBlockType::file_bytes) &&
            sub->field(4).as_integer() == id) {
            throw std::logic_error("File Bytes object is still used by memory");
        }
    }
    auto state = file_bytes_state(id);
    if (!state) return false;
    for (auto &buffer : state->layered) buffer->remove();
    for (auto &buffer : state->original) buffer->remove();
    const bool removed = file_bytes_table_->delete_record(id);
    invalidate_caches();
    return removed;
}

MemoryBlock MemoryManager::create_single_sub_block(
    std::string name, const Address &start, std::uint64_t length,
    std::uint8_t flags, MemorySubBlockType type,
    std::int32_t source_id, std::int64_t source_address_or_offset) {
    require_mutation();
    require_block_range(start, length);
    require_unique_block_name(name);
    if (name.empty() || (flags & ~MemoryBlock::valid_flags) != 0 ||
        length > static_cast<std::uint64_t>(
                     std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("invalid memory block attributes");
    }
    const auto block_id = block_table_->next_long_key();
    auto block = block_schema()->create_record(block_id);
    block->set_string(0, std::move(name));
    block->set_integer(3, flags);
    block->set_integer(4, signed_key(address_map_->key(start, true)));
    block->set_integer(5, static_cast<std::int64_t>(length));
    block->set_integer(6, start.segment().value_or(0));
    auto sub = sub_block_schema()->create_record(sub_block_table_->next_long_key());
    sub->set_integer(0, block_id);
    sub->set_integer(1, static_cast<std::uint8_t>(type));
    sub->set_integer(2, static_cast<std::int64_t>(length));
    sub->set_integer(3, 0);
    sub->set_integer(4, source_id);
    sub->set_integer(5, source_address_or_offset);
    sub_block_table_->put_record(*sub);
    block_table_->put_record(*block);
    auto result = decode_block(*block);
    notify_region_change();
    return result;
}

MemoryBlock MemoryManager::create_initialized_block(
    std::string name, const Address &start,
    std::span<const std::uint8_t> bytes, std::uint8_t flags,
    bool overlay) {
    require_mutation();
    if (bytes.empty() || name.empty() ||
        (flags & ~MemoryBlock::valid_flags) != 0) {
        throw std::invalid_argument("invalid initialized memory block");
    }
    require_unique_block_name(name);
    const auto block_start = resolve_block_start(
        name, start, static_cast<std::uint64_t>(bytes.size()), overlay);
    require_block_range(block_start, bytes.size());
    const auto block_id = block_table_->next_long_key();
    auto block = block_schema()->create_record(block_id);
    block->set_string(0, std::move(name));
    block->set_integer(3, flags);
    block->set_integer(4, signed_key(address_map_->key(block_start, true)));
    block->set_integer(5, static_cast<std::int64_t>(bytes.size()));
    block->set_integer(6, block_start.segment().value_or(0));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = std::min<std::size_t>(
            maximum_chained_buffer_size, bytes.size() - offset);
        auto buffer = database_->create_chained_buffer(
            static_cast<std::int32_t>(count));
        buffer->put(0, bytes.subspan(offset, count));
        auto sub = sub_block_schema()->create_record(
            sub_block_table_->next_long_key());
        sub->set_integer(0, block_id);
        sub->set_integer(1,
                         static_cast<std::uint8_t>(MemorySubBlockType::buffer));
        sub->set_integer(2, static_cast<std::int64_t>(count));
        sub->set_integer(3, static_cast<std::int64_t>(offset));
        sub->set_integer(4, buffer->id());
        sub_block_table_->put_record(*sub);
        offset += count;
    }
    block_table_->put_record(*block);
    auto result = decode_block(*block);
    notify_region_change();
    return result;
}

MemoryBlock MemoryManager::create_uninitialized_block(
    std::string name, const Address &start,
    std::uint64_t length, std::uint8_t flags, bool overlay) {
    require_mutation();
    if (name.empty() || length == 0 ||
        length > static_cast<std::uint64_t>(
                     std::numeric_limits<std::int64_t>::max()) ||
        (flags & ~MemoryBlock::valid_flags) != 0) {
        throw std::invalid_argument("invalid uninitialized memory block");
    }
    require_unique_block_name(name);
    const auto block_start = resolve_block_start(name, start, length, overlay);
    return create_single_sub_block(
        std::move(name), block_start, length, flags,
        MemorySubBlockType::uninitialized, 0, 0);
}

MemoryBlock MemoryManager::create_mapped_block(
    MemoryBlockType type, std::string name, const Address &start,
    std::uint64_t length, const Address &mapped_start,
    std::uint8_t flags, ByteMappingScheme scheme, bool overlay) {
    require_mutation();
    if (type == MemoryBlockType::default_block || name.empty() ||
        length == 0 || (flags & ~MemoryBlock::valid_flags) != 0 ||
        !mapped_start.is_memory_address()) {
        throw std::invalid_argument("mapped block requires mapped memory source");
    }
    require_unique_block_name(name);
    const auto sub_type = type == MemoryBlockType::bit_mapped
                              ? MemorySubBlockType::bit_mapped
                              : MemorySubBlockType::byte_mapped;
    const auto encoded_scheme = type == MemoryBlockType::byte_mapped
                                    ? scheme.encode()
                                    : 0;
    const auto last_source_offset = type == MemoryBlockType::bit_mapped
        ? (length - 1) / 8
        : scheme.source_offset(length - 1);
    if (last_source_offset > static_cast<std::uint64_t>(
                                 std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("mapped memory source range overflows");
    }
    (void)mapped_start.add_no_wrap(
        static_cast<std::int64_t>(last_source_offset));
    const auto block_start = resolve_block_start(name, start, length, overlay);
    return create_single_sub_block(
        std::move(name), block_start, length, flags, sub_type, encoded_scheme,
        signed_key(address_map_->key(mapped_start, true)));
}

MemoryBlock MemoryManager::create_file_bytes_block(
    std::string name, const Address &start, std::uint64_t length,
    std::int64_t file_bytes_id, std::uint64_t file_bytes_offset,
    std::uint8_t flags, bool overlay) {
    require_mutation();
    if (name.empty() || length == 0 ||
        length > static_cast<std::uint64_t>(
                     std::numeric_limits<std::int64_t>::max()) ||
        (flags & ~MemoryBlock::valid_flags) != 0) {
        throw std::invalid_argument("invalid File Bytes memory block");
    }
    require_unique_block_name(name);
    const auto state = file_bytes_state(file_bytes_id);
    if (!state || file_bytes_id > std::numeric_limits<std::int32_t>::max() ||
        file_bytes_id < std::numeric_limits<std::int32_t>::min() ||
        file_bytes_offset > state->info.size ||
        length > state->info.size - file_bytes_offset ||
        file_bytes_offset > static_cast<std::uint64_t>(
                                std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("invalid File Bytes memory source range");
    }
    const auto block_start = resolve_block_start(name, start, length, overlay);
    return create_single_sub_block(
        std::move(name), block_start, length, flags,
        MemorySubBlockType::file_bytes,
        static_cast<std::int32_t>(file_bytes_id),
        static_cast<std::int64_t>(file_bytes_offset));
}

void MemoryManager::update_block_metadata(
    std::int64_t id, std::string name, std::optional<std::string> comment,
    std::optional<std::string> source_name, std::uint8_t flags) {
    require_mutation();
    if (name.empty() || (flags & ~MemoryBlock::valid_flags) != 0) {
        throw std::invalid_argument("invalid memory block metadata");
    }
    require_unique_block_name(name, id);
    auto record = block_table_->record(id);
    if (!record) throw std::out_of_range("memory block does not exist");
    record->set_string(0, std::move(name));
    record->set_string(1, std::move(comment));
    record->set_string(2, std::move(source_name));
    record->set_integer(3, flags);
    block_table_->put_record(*record);
}

void MemoryManager::remove_sub_block_storage(const MemorySubBlock &sub) {
    if (sub.type != MemorySubBlockType::buffer) return;
    auto buffer = database_->open_chained_buffer(sub.source_id);
    buffer->remove();
}

MemorySubBlock MemoryManager::split_sub_block(
    const MemorySubBlock &sub, std::uint64_t split_offset,
    std::int64_t new_parent_id, std::uint64_t new_starting_offset) {
    if (split_offset == 0 || split_offset >= sub.length) {
        throw std::invalid_argument("invalid memory sub-block split offset");
    }

    auto old_record = sub_block_table_->record(sub.id);
    if (!old_record) throw std::runtime_error("memory sub-block disappeared");
    old_record->set_integer(2, static_cast<std::int64_t>(split_offset));
    sub_block_table_->put_record(*old_record);

    const auto new_length = sub.length - split_offset;
    auto new_record = sub_block_schema()->create_record(
        sub_block_table_->next_long_key());
    new_record->set_integer(0, new_parent_id);
    new_record->set_integer(1, static_cast<std::uint8_t>(sub.type));
    new_record->set_integer(2, static_cast<std::int64_t>(new_length));
    new_record->set_integer(
        3, static_cast<std::int64_t>(new_starting_offset));
    new_record->set_integer(4, sub.source_id);
    new_record->set_integer(5, sub.source_address_or_offset);

    switch (sub.type) {
    case MemorySubBlockType::buffer: {
        if (split_offset > static_cast<std::uint64_t>(
                               std::numeric_limits<std::int32_t>::max())) {
            throw std::invalid_argument(
                "buffer sub-block split offset is too large");
        }
        auto buffer = database_->open_chained_buffer(sub.source_id);
        auto split = buffer->split(static_cast<std::int32_t>(split_offset));
        new_record->set_integer(4, split->id());
        break;
    }
    case MemorySubBlockType::file_bytes:
        if (sub.source_address_or_offset < 0 ||
            split_offset > static_cast<std::uint64_t>(
                               std::numeric_limits<std::int64_t>::max()) ||
            sub.source_address_or_offset >
                std::numeric_limits<std::int64_t>::max() -
                    static_cast<std::int64_t>(split_offset)) {
            throw std::overflow_error("File Bytes split offset overflows");
        }
        new_record->set_integer(
            5, sub.source_address_or_offset +
                   static_cast<std::int64_t>(split_offset));
        break;
    case MemorySubBlockType::byte_mapped: {
        const auto scheme = ByteMappingScheme::decode(sub.source_id);
        if (scheme.mapped_bytes != 1 || scheme.source_bytes != 1) {
            throw std::invalid_argument(
                "non-1:1 byte-mapped sub-block cannot be split");
        }
        const auto source = address_map_->decode(
            unsigned_key(sub.source_address_or_offset));
        if (!source.is_valid()) {
            throw std::runtime_error("byte-mapped split source is invalid");
        }
        new_record->set_integer(
            5, signed_key(address_map_->key(
                   source.add_no_wrap(static_cast<std::int64_t>(split_offset)),
                   true)));
        break;
    }
    case MemorySubBlockType::uninitialized:
        break;
    case MemorySubBlockType::bit_mapped:
        throw std::invalid_argument("bit-mapped sub-block cannot be split");
    }
    sub_block_table_->put_record(*new_record);
    return MemorySubBlock{
        new_record->key().as_integer(), new_parent_id, sub.type, new_length,
        new_starting_offset,
        static_cast<std::int32_t>(new_record->field(4).as_integer()),
        new_record->field(5).as_integer()};
}

MemoryBlock MemoryManager::split_block(
    std::int64_t id, const Address &split_address) {
    require_mutation();
    auto original = block(id);
    if (!original) throw std::out_of_range("memory block does not exist");
    if (!original->contains(split_address) || split_address == original->start) {
        throw std::invalid_argument(
            "split address must be inside the block after its start");
    }
    if (original->type() == MemoryBlockType::bit_mapped) {
        throw std::invalid_argument("bit-mapped block cannot be split");
    }
    if (original->start.space()->is_overlay_space() &&
        original->start.is_non_loaded_memory_address()) {
        throw std::invalid_argument("OTHER overlay block cannot be split");
    }
    if (original->type() == MemoryBlockType::byte_mapped) {
        const auto scheme = ByteMappingScheme::decode(
            original->sub_blocks.front().source_id);
        if (scheme.mapped_bytes != 1 || scheme.source_bytes != 1) {
            throw std::invalid_argument(
                "non-1:1 byte-mapped block cannot be split");
        }
    }

    const auto split_offset = static_cast<std::uint64_t>(
        split_address.subtract(original->start));
    const auto new_length = original->length - split_offset;
    const auto new_id = block_table_->next_long_key();

    auto old_block_record = block_table_->record(id);
    old_block_record->set_integer(
        5, static_cast<std::int64_t>(split_offset));
    block_table_->put_record(*old_block_record);

    for (const auto &sub : original->sub_blocks) {
        const auto sub_end = sub.starting_offset + sub.length;
        if (sub_end <= split_offset) continue;
        if (sub.starting_offset >= split_offset) {
            auto record = sub_block_table_->record(sub.id);
            if (!record) throw std::runtime_error("memory sub-block disappeared");
            record->set_integer(0, new_id);
            record->set_integer(
                3, static_cast<std::int64_t>(sub.starting_offset - split_offset));
            sub_block_table_->put_record(*record);
            continue;
        }
        (void)split_sub_block(
            sub, split_offset - sub.starting_offset, new_id, 0);
    }

    auto new_block_record = block_schema()->create_record(new_id);
    new_block_record->set_string(0, unique_split_name(original->name));
    new_block_record->set_integer(3, original->flags);
    new_block_record->set_integer(
        4, signed_key(address_map_->key(split_address, true)));
    new_block_record->set_integer(5, static_cast<std::int64_t>(new_length));
    new_block_record->set_integer(6, split_address.segment().value_or(0));
    block_table_->put_record(*new_block_record);
    auto result = decode_block(*new_block_record);
    notify_region_change();
    return result;
}

MemoryBlock MemoryManager::join_blocks(std::int64_t first_id,
                                       std::int64_t second_id) {
    require_mutation();
    if (first_id == second_id) {
        throw std::invalid_argument("cannot join a memory block with itself");
    }
    auto first = block(first_id);
    auto second = block(second_id);
    if (!first || !second) throw std::out_of_range("memory block does not exist");
    if (second->start < first->start) {
        std::swap(first, second);
        std::swap(first_id, second_id);
    }
    if (first->mapped() || second->mapped()) {
        throw std::invalid_argument("mapped blocks cannot be joined");
    }
    if (first->initialized() != second->initialized()) {
        throw std::invalid_argument(
            "joined blocks must both be initialized or uninitialized");
    }
    const auto successor = first->end().next();
    if (!successor || *successor != second->start) {
        throw std::invalid_argument("joined memory blocks are not contiguous");
    }
    if (second->length > static_cast<std::uint64_t>(
                             std::numeric_limits<std::int64_t>::max()) -
                             first->length) {
        throw std::overflow_error("joined memory block length overflows");
    }

    std::optional<std::int64_t> merged_second_sub;
    if (!first->sub_blocks.empty() && !second->sub_blocks.empty()) {
        const auto &left = first->sub_blocks.back();
        const auto &right = second->sub_blocks.front();
        bool merge = false;
        if (left.type == MemorySubBlockType::uninitialized &&
            right.type == MemorySubBlockType::uninitialized) {
            merge = true;
        }
        else if (left.type == MemorySubBlockType::file_bytes &&
                 right.type == MemorySubBlockType::file_bytes &&
                 left.source_id == right.source_id &&
                 left.source_address_or_offset >= 0 &&
                 right.source_address_or_offset >= 0 &&
                 static_cast<std::uint64_t>(left.source_address_or_offset) <=
                     std::numeric_limits<std::uint64_t>::max() - left.length &&
                 static_cast<std::uint64_t>(right.source_address_or_offset) ==
                     static_cast<std::uint64_t>(left.source_address_or_offset) +
                         left.length) {
            merge = true;
        }
        else if (left.type == MemorySubBlockType::buffer &&
                 right.type == MemorySubBlockType::buffer &&
                 right.length <= static_cast<std::uint64_t>(
                                     maximum_chained_buffer_size) -
                                     left.length) {
            auto left_buffer = database_->open_chained_buffer(left.source_id);
            auto right_buffer = database_->open_chained_buffer(right.source_id);
            left_buffer->append(*right_buffer);
            merge = true;
        }
        if (merge) {
            auto left_record = sub_block_table_->record(left.id);
            if (!left_record) {
                throw std::runtime_error("memory sub-block disappeared");
            }
            left_record->set_integer(
                2, static_cast<std::int64_t>(left.length + right.length));
            sub_block_table_->put_record(*left_record);
            if (!sub_block_table_->delete_record(right.id)) {
                throw std::runtime_error(
                    "failed to remove merged memory sub-block");
            }
            merged_second_sub = right.id;
        }
    }

    for (const auto &sub : second->sub_blocks) {
        if (merged_second_sub == sub.id) continue;
        auto record = sub_block_table_->record(sub.id);
        if (!record) throw std::runtime_error("memory sub-block disappeared");
        record->set_integer(0, first_id);
        record->set_integer(
            3, static_cast<std::int64_t>(first->length + sub.starting_offset));
        sub_block_table_->put_record(*record);
    }
    auto first_record = block_table_->record(first_id);
    first_record->set_integer(
        5, static_cast<std::int64_t>(first->length + second->length));
    block_table_->put_record(*first_record);
    if (!block_table_->delete_record(second_id)) {
        throw std::runtime_error("failed to remove joined memory block");
    }
    auto result = decode_block(*first_record);
    notify_region_change();
    return result;
}

MemoryBlock MemoryManager::convert_to_initialized(
    std::int64_t id, std::uint8_t initial_value) {
    require_mutation();
    auto value = block(id);
    if (!value) throw std::out_of_range("memory block does not exist");
    if (value->type() != MemoryBlockType::default_block ||
        value->initialized()) {
        throw std::invalid_argument(
            "only an uninitialized default block can be initialized");
    }
    for (const auto &sub : value->sub_blocks) {
        remove_sub_block_storage(sub);
        if (!sub_block_table_->delete_record(sub.id)) {
            throw std::runtime_error("failed to replace memory sub-block");
        }
    }
    std::uint64_t offset = 0;
    while (offset < value->length) {
        const auto count = static_cast<std::int32_t>(
            std::min<std::uint64_t>(maximum_chained_buffer_size,
                                    value->length - offset));
        auto buffer = database_->create_chained_buffer(count);
        buffer->fill(0, static_cast<std::size_t>(count - 1), initial_value);
        auto sub = sub_block_schema()->create_record(
            sub_block_table_->next_long_key());
        sub->set_integer(0, id);
        sub->set_integer(1,
                         static_cast<std::uint8_t>(MemorySubBlockType::buffer));
        sub->set_integer(2, count);
        sub->set_integer(3, static_cast<std::int64_t>(offset));
        sub->set_integer(4, buffer->id());
        sub_block_table_->put_record(*sub);
        offset += static_cast<std::uint64_t>(count);
    }
    return *block(id);
}

MemoryBlock MemoryManager::convert_to_uninitialized(std::int64_t id) {
    require_mutation();
    auto value = block(id);
    if (!value) throw std::out_of_range("memory block does not exist");
    if (value->type() != MemoryBlockType::default_block ||
        !value->initialized()) {
        throw std::invalid_argument(
            "only an initialized default block can be uninitialized");
    }
    for (const auto &sub : value->sub_blocks) {
        remove_sub_block_storage(sub);
        if (!sub_block_table_->delete_record(sub.id)) {
            throw std::runtime_error("failed to replace memory sub-block");
        }
    }
    auto sub = sub_block_schema()->create_record(
        sub_block_table_->next_long_key());
    sub->set_integer(0, id);
    sub->set_integer(
        1, static_cast<std::uint8_t>(MemorySubBlockType::uninitialized));
    sub->set_integer(2, static_cast<std::int64_t>(value->length));
    sub->set_integer(3, 0);
    sub_block_table_->put_record(*sub);
    return *block(id);
}

void MemoryManager::move_block(std::int64_t id, const Address &new_start) {
    require_mutation();
    auto value = block(id);
    if (!value) throw std::out_of_range("memory block does not exist");
    if (value->start.space()->is_overlay_space() &&
        value->start.is_non_loaded_memory_address()) {
        throw std::invalid_argument("OTHER overlay block cannot be moved");
    }
    require_block_range(new_start, value->length, id);
    const auto old_start = value->start;
    const auto old_overlay_name = old_start.space()->is_overlay_space()
        ? std::optional<std::string>(old_start.space()->name())
        : std::nullopt;
    auto record = block_table_->record(id);
    record->set_integer(4, signed_key(address_map_->key(new_start, true)));
    record->set_integer(6, new_start.segment().value_or(0));
    block_table_->put_record(*record);
    if (external_move_handler_) {
        external_move_handler_(old_start, new_start, value->length);
    }
    notify_region_change();
    if (old_overlay_name && external_overlay_cleanup_handler_) {
        external_overlay_cleanup_handler_(*old_overlay_name);
    }
}

bool MemoryManager::remove_block(std::int64_t id) {
    require_mutation();
    const auto value = block(id);
    if (!value) return false;
    const auto overlay_name = value->start.space()->is_overlay_space()
        ? std::optional<std::string>(value->start.space()->name())
        : std::nullopt;
    if (external_delete_handler_) {
        external_delete_handler_(value->start, value->end());
    }
    for (const auto &sub : value->sub_blocks) {
        remove_sub_block_storage(sub);
        (void)sub_block_table_->delete_record(sub.id);
    }
    const bool removed = block_table_->delete_record(id);
    if (removed) {
        notify_region_change();
        if (overlay_name && external_overlay_cleanup_handler_) {
            external_overlay_cleanup_handler_(*overlay_name);
        }
    }
    return removed;
}

std::vector<MemorySourceInfo> MemoryManager::source_infos(
    std::int64_t block_id) const {
    const auto value = block(block_id);
    if (!value) throw std::out_of_range("memory block does not exist");
    std::vector<MemorySourceInfo> result;
    result.reserve(value->sub_blocks.size());
    for (const auto &sub : value->sub_blocks) {
        const auto minimum = value->start.add_no_wrap(
            static_cast<std::int64_t>(sub.starting_offset));
        const auto maximum = minimum.add_no_wrap(
            static_cast<std::int64_t>(sub.length - 1));
        MemorySourceInfo info{sub.id, minimum, maximum, sub.length, sub.type};
        if (sub.type == MemorySubBlockType::file_bytes) {
            if (sub.source_address_or_offset < 0) {
                throw std::runtime_error("File Bytes source offset is negative");
            }
            const auto state = file_bytes_state(sub.source_id);
            if (!state) throw std::runtime_error("File Bytes source is missing");
            info.file_bytes = state->info;
            info.file_bytes_offset = static_cast<std::uint64_t>(
                sub.source_address_or_offset);
        }
        else if (sub.type == MemorySubBlockType::bit_mapped ||
                 sub.type == MemorySubBlockType::byte_mapped) {
            const auto mapped = address_map_->decode(
                unsigned_key(sub.source_address_or_offset));
            if (!mapped.is_valid()) {
                throw std::runtime_error("mapped memory source is invalid");
            }
            const auto last_offset =
                sub.type == MemorySubBlockType::bit_mapped
                    ? (sub.length - 1) / 8
                    : ByteMappingScheme::decode(sub.source_id)
                          .source_offset(sub.length - 1);
            if (last_offset > static_cast<std::uint64_t>(
                                  std::numeric_limits<std::int64_t>::max())) {
                throw std::runtime_error("mapped memory source range overflows");
            }
            info.mapped_minimum = mapped;
            info.mapped_maximum = mapped.add_no_wrap(
                static_cast<std::int64_t>(last_offset));
            if (sub.type == MemorySubBlockType::byte_mapped) {
                info.byte_mapping_scheme = ByteMappingScheme::decode(sub.source_id);
            }
        }
        result.push_back(std::move(info));
    }
    return result;
}

std::optional<AddressSourceInfo> MemoryManager::address_source_info(
    const Address &address) const {
    const auto containing = block_containing(address);
    if (!containing) return std::nullopt;
    const auto infos = source_infos(containing->id);
    const auto direct = std::ranges::find_if(
        infos, [&](const MemorySourceInfo &info) {
            return address >= info.minimum && address <= info.maximum;
        });
    if (direct == infos.end()) return std::nullopt;

    AddressSourceInfo result{address, *direct};
    auto cursor = address;
    std::vector<Address> visited;
    for (;;) {
        if (std::ranges::find(visited, cursor) != visited.end()) {
            throw MemoryAccessError("cyclic mapped source information");
        }
        visited.push_back(cursor);
        const auto cursor_block = block_containing(cursor);
        if (!cursor_block) break;
        const auto offset = static_cast<std::uint64_t>(
            cursor.subtract(cursor_block->start));
        const auto position = std::ranges::find_if(
            cursor_block->sub_blocks, [&](const MemorySubBlock &sub) {
                return offset >= sub.starting_offset &&
                       offset - sub.starting_offset < sub.length;
            });
        if (position == cursor_block->sub_blocks.end()) break;
        const auto local = offset - position->starting_offset;
        if (position->type == MemorySubBlockType::file_bytes) {
            if (position->source_address_or_offset < 0) {
                throw std::runtime_error("File Bytes source offset is negative");
            }
            const auto state = file_bytes_state(position->source_id);
            if (!state) throw std::runtime_error("File Bytes source is missing");
            const auto file_bytes_offset =
                static_cast<std::uint64_t>(position->source_address_or_offset) +
                local;
            if (file_bytes_offset > static_cast<std::uint64_t>(
                                        std::numeric_limits<std::int64_t>::max()) ||
                state->info.file_offset >
                    std::numeric_limits<std::int64_t>::max() -
                        static_cast<std::int64_t>(file_bytes_offset)) {
                throw std::overflow_error("source file offset overflows");
            }
            result.filename = state->info.filename;
            result.file_offset = state->info.file_offset +
                                 static_cast<std::int64_t>(file_bytes_offset);
            result.original_value =
                read_file_bytes(state->info.id, file_bytes_offset, 1, true).front();
            break;
        }
        if (position->type != MemorySubBlockType::bit_mapped &&
            position->type != MemorySubBlockType::byte_mapped) {
            break;
        }
        const auto mapped_base = address_map_->decode(
            unsigned_key(position->source_address_or_offset));
        const auto mapped_offset =
            position->type == MemorySubBlockType::bit_mapped
                ? local / 8
                : ByteMappingScheme::decode(position->source_id)
                      .source_offset(local);
        if (!mapped_base.is_valid() ||
            mapped_offset > static_cast<std::uint64_t>(
                                std::numeric_limits<std::int64_t>::max())) {
            break;
        }
        cursor = mapped_base.add_no_wrap(
            static_cast<std::int64_t>(mapped_offset));
    }
    return result;
}

std::uint8_t MemoryManager::read_sub_block(
    const MemoryBlock &block, const MemorySubBlock &sub,
    std::uint64_t block_offset, std::vector<Address> &active) const {
    const auto local = block_offset - sub.starting_offset;
    switch (sub.type) {
    case MemorySubBlockType::uninitialized:
        throw MemoryAccessError("memory is uninitialized");
    case MemorySubBlockType::buffer: {
        auto buffer = database_->open_chained_buffer(sub.source_id);
        return buffer->get_u8(local);
    }
    case MemorySubBlockType::file_bytes: {
        if (sub.source_address_or_offset < 0) {
            throw MemoryAccessError("File Bytes source offset is negative");
        }
        const auto bytes = read_file_bytes(
            sub.source_id,
            static_cast<std::uint64_t>(sub.source_address_or_offset) + local,
            1, false);
        return bytes.front();
    }
    case MemorySubBlockType::byte_mapped:
    case MemorySubBlockType::bit_mapped: {
        const auto source_base = address_map_->decode(
            unsigned_key(sub.source_address_or_offset));
        std::uint64_t source_offset{};
        if (sub.type == MemorySubBlockType::bit_mapped) {
            source_offset = local / 8;
        }
        else {
            source_offset = ByteMappingScheme::decode(sub.source_id)
                                .source_offset(local);
        }
        if (source_offset > static_cast<std::uint64_t>(
                                std::numeric_limits<std::int64_t>::max())) {
            throw MemoryAccessError("mapped memory source overflows");
        }
        const auto source = source_base.add_no_wrap(
            static_cast<std::int64_t>(source_offset));
        if (std::ranges::find(active, source) != active.end()) {
            throw MemoryAccessError("cyclic mapped memory access");
        }
        ActiveAddressGuard guard(active, source);
        const auto source_block = block_containing(source);
        if (!source_block) throw MemoryAccessError("mapped source memory is absent");
        const auto source_block_offset =
            static_cast<std::uint64_t>(source.subtract(source_block->start));
        const auto source_position = std::ranges::find_if(
            source_block->sub_blocks, [&](const MemorySubBlock &candidate) {
                return source_block_offset >= candidate.starting_offset &&
                       source_block_offset - candidate.starting_offset < candidate.length;
            });
        if (source_position == source_block->sub_blocks.end()) {
            throw MemoryAccessError("mapped source has no sub-block");
        }
        auto value = read_sub_block(*source_block, *source_position,
                                    source_block_offset, active);
        if (sub.type == MemorySubBlockType::bit_mapped) {
            value = static_cast<std::uint8_t>((value >> (local % 8)) & 1U);
        }
        return value;
    }
    }
    throw MemoryAccessError("unknown memory sub-block type");
}

void MemoryManager::write_sub_block(
    const MemoryBlock &block, const MemorySubBlock &sub,
    std::uint64_t block_offset, std::uint8_t value,
    std::vector<Address> &active) {
    const auto local = block_offset - sub.starting_offset;
    switch (sub.type) {
    case MemorySubBlockType::uninitialized:
        throw MemoryAccessError("memory is uninitialized");
    case MemorySubBlockType::buffer: {
        auto buffer = database_->open_chained_buffer(sub.source_id);
        buffer->put_u8(local, value);
        return;
    }
    case MemorySubBlockType::file_bytes:
        if (sub.source_address_or_offset < 0) {
            throw MemoryAccessError("File Bytes source offset is negative");
        }
        write_file_bytes(sub.source_id,
                         static_cast<std::uint64_t>(
                             sub.source_address_or_offset) + local,
                         std::span<const std::uint8_t>(&value, 1));
        return;
    case MemorySubBlockType::byte_mapped:
    case MemorySubBlockType::bit_mapped: {
        const auto source_base = address_map_->decode(
            unsigned_key(sub.source_address_or_offset));
        const auto source_offset = sub.type == MemorySubBlockType::bit_mapped
            ? local / 8
            : ByteMappingScheme::decode(sub.source_id).source_offset(local);
        if (source_offset > static_cast<std::uint64_t>(
                                std::numeric_limits<std::int64_t>::max())) {
            throw MemoryAccessError("mapped memory source overflows");
        }
        const auto source = source_base.add_no_wrap(
            static_cast<std::int64_t>(source_offset));
        if (std::ranges::find(active, source) != active.end()) {
            throw MemoryAccessError("cyclic mapped memory access");
        }
        ActiveAddressGuard guard(active, source);
        const auto source_block = block_containing(source);
        if (!source_block) throw MemoryAccessError("mapped source memory is absent");
        const auto source_block_offset =
            static_cast<std::uint64_t>(source.subtract(source_block->start));
        const auto position = std::ranges::find_if(
            source_block->sub_blocks, [&](const MemorySubBlock &candidate) {
                return source_block_offset >= candidate.starting_offset &&
                       source_block_offset - candidate.starting_offset < candidate.length;
            });
        if (position == source_block->sub_blocks.end()) {
            throw MemoryAccessError("mapped source has no sub-block");
        }
        auto source_value = value;
        if (sub.type == MemorySubBlockType::bit_mapped) {
            source_value = read_sub_block(*source_block, *position,
                                          source_block_offset, active);
            const auto mask = static_cast<std::uint8_t>(1U << (local % 8));
            source_value = value == 0
                               ? static_cast<std::uint8_t>(source_value & ~mask)
                               : static_cast<std::uint8_t>(source_value | mask);
        }
        write_sub_block(*source_block, *position, source_block_offset,
                        source_value, active);
        return;
    }
    }
}

std::uint8_t MemoryManager::read_byte(const Address &address) const {
    const auto value = block_containing(address);
    if (!value) throw MemoryAccessError("no memory block contains address");
    const auto offset = static_cast<std::uint64_t>(address.subtract(value->start));
    const auto position = std::ranges::find_if(
        value->sub_blocks, [&](const MemorySubBlock &sub) {
            return offset >= sub.starting_offset &&
                   offset - sub.starting_offset < sub.length;
        });
    if (position == value->sub_blocks.end()) {
        throw MemoryAccessError("memory block has no covering sub-block");
    }
    std::vector<Address> active{address};
    return read_sub_block(*value, *position, offset, active);
}

std::vector<std::uint8_t> MemoryManager::read(
    const Address &address, std::size_t length) const {
    std::vector<std::uint8_t> result;
    result.reserve(length);
    auto cursor = address;
    for (std::size_t index = 0; index < length; ++index) {
        result.push_back(read_byte(cursor));
        if (index + 1 != length) cursor = cursor.add_no_wrap(1);
    }
    return result;
}

void MemoryManager::write_byte(const Address &address, std::uint8_t value) {
    require_mutation();
    const auto block_value = block_containing(address);
    if (!block_value) throw MemoryAccessError("no memory block contains address");
    const auto offset = static_cast<std::uint64_t>(
        address.subtract(block_value->start));
    const auto position = std::ranges::find_if(
        block_value->sub_blocks, [&](const MemorySubBlock &sub) {
            return offset >= sub.starting_offset &&
                   offset - sub.starting_offset < sub.length;
        });
    if (position == block_value->sub_blocks.end()) {
        throw MemoryAccessError("memory block has no covering sub-block");
    }
    std::vector<Address> active{address};
    write_sub_block(*block_value, *position, offset, value, active);
}

void MemoryManager::write(const Address &address,
                          std::span<const std::uint8_t> bytes) {
    auto cursor = address;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        write_byte(cursor, bytes[index]);
        if (index + 1 != bytes.size()) cursor = cursor.add_no_wrap(1);
    }
}

void MemoryManager::set_external_move_handler(
    std::function<void(const Address &, const Address &, std::uint64_t)> handler) {
    external_move_handler_ = std::move(handler);
}

void MemoryManager::set_external_delete_handler(
    std::function<void(const Address &, const Address &)> handler) {
    external_delete_handler_ = std::move(handler);
}

void MemoryManager::set_external_overlay_creation_handler(
    std::function<Address(const std::string &, const Address &,
                          std::uint64_t)> handler) {
    external_overlay_creation_handler_ = std::move(handler);
}

void MemoryManager::set_external_region_change_handler(
    std::function<void()> handler) {
    external_region_change_handler_ = std::move(handler);
}

void MemoryManager::set_external_overlay_cleanup_handler(
    std::function<void(const std::string &)> handler) {
    external_overlay_cleanup_handler_ = std::move(handler);
}

void MemoryManager::invalidate_caches() noexcept {
    file_bytes_cache_.clear();
}

} // namespace llmghidra::program
