#include "llmghidra/program/comment_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace llmghidra::program {
namespace {

constexpr std::size_t comment_column_count = 5;

[[nodiscard]] std::size_t column(CommentType type) {
    const auto value = static_cast<std::size_t>(type);
    if (value >= comment_column_count) {
        throw std::invalid_argument("unsupported Ghidra comment type");
    }
    return value;
}

} // namespace

std::shared_ptr<db::Schema> CommentManager::schema(int version) {
    if (version != 0 && version != schema_version) {
        throw std::invalid_argument("unsupported Comments schema version");
    }
    std::vector<std::unique_ptr<db::Field>> fields;
    const auto count = version == 0 ? std::size_t{4} : comment_column_count;
    fields.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        fields.push_back(std::make_unique<db::StringField>());
    }
    std::vector<std::string> names{"EOL", "Pre", "Post", "Plate"};
    if (version == schema_version) names.emplace_back("Repeatable");
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "Address", std::move(fields), std::move(names));
}

CommentManager::CommentManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    ProgramOpenMode mode,
    bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) {
        throw std::invalid_argument("comment manager requires a database");
    }
    if (create) {
        table_ = database_->create_table(table_name, schema(schema_version));
        return;
    }
    table_ = database_->get_table(table_name);
    if (!table_) {
        if (mode_ != ProgramOpenMode::upgrade) {
            throw std::runtime_error("missing Ghidra Comments table");
        }
        table_ = database_->create_table(table_name, schema(schema_version));
        return;
    }
    stored_schema_version_ = table_->schema().version();
    const bool supported =
        (stored_schema_version_ == 0 || stored_schema_version_ == schema_version) &&
        table_->schema().equals(*schema(stored_schema_version_));
    if (!supported) {
        throw std::runtime_error("unsupported Ghidra Comments table");
    }
    const bool address_rekey_required = address_map_->upgraded();
    if ((stored_schema_version_ != schema_version || address_rekey_required) &&
        mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra Comments table requires upgrade");
    }
    if ((stored_schema_version_ != schema_version || address_rekey_required) &&
        mode_ == ProgramOpenMode::upgrade) {
        upgrade_table(stored_schema_version_);
    }
}

void CommentManager::upgrade_table(int stored_version) {
    std::vector<std::unique_ptr<db::Record>> translated;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto source = iterator->next();
        if (!source) continue;
        const auto old_key = std::bit_cast<std::uint64_t>(
            source->key().as_integer());
        const Address address = address_map_->decode(old_key);
        if (!address.is_valid()) {
            throw std::runtime_error(
                "Comments table contains an undecodable address key");
        }
        const auto new_key = address_map_->key(address, true);
        auto destination = schema(schema_version)->create_record(
            std::bit_cast<std::int64_t>(new_key));
        const auto count = stored_version == 0 ? std::size_t{4}
                                               : comment_column_count;
        for (std::size_t index = 0; index < count; ++index) {
            destination->set_string(index, source->field(index).as_string());
        }
        translated.push_back(std::move(destination));
    }
    if (!database_->delete_table(table_name)) {
        throw std::runtime_error("failed to replace legacy Comments table");
    }
    table_ = database_->create_table(table_name, schema(schema_version));
    for (auto &record : translated) table_->put_record(*record);
    stored_schema_version_ = schema_version;
}

std::uint64_t CommentManager::address_key(const Address &address,
                                          bool create) const {
    if (!address.is_memory_address() && !address.is_external_address()) {
        throw std::invalid_argument(
            "comments require a memory or external address");
    }
    if (stored_schema_version_ == 0) {
        if (create) {
            throw std::logic_error(
                "legacy Comments V0 is read-only until coordinated upgrade");
        }
        return address_map_->factory()->old_index(address);
    }
    return address_map_->key(address, create);
}

std::optional<std::string> CommentManager::get(
    const Address &address,
    CommentType type) const {
    const auto key = address_key(address, false);
    if (key == PersistentAddressMap::invalid_key) return std::nullopt;
    const auto record = table_->record(std::bit_cast<std::int64_t>(key));
    if (!record || column(type) >= record->column_count()) return std::nullopt;
    return record->field(column(type)).as_string();
}

std::vector<CommentRecord> CommentManager::all() const {
    std::vector<CommentRecord> result;
    result.reserve(static_cast<std::size_t>(table_->record_count()));
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record) continue;
        const auto address = address_map_->decode(
            std::bit_cast<std::uint64_t>(record->key().as_integer()));
        if (!address.is_valid()) {
            throw std::runtime_error(
                "Comments table contains an undecodable address key");
        }
        CommentRecord item;
        item.address = address;
        const auto count = std::min(
            item.comments.size(), record->column_count());
        for (std::size_t index = 0; index < count; ++index) {
            item.comments[index] = record->field(index).as_string();
        }
        result.push_back(std::move(item));
    }
    std::ranges::sort(result, {}, &CommentRecord::address);
    return result;
}

void CommentManager::set(const Address &address,
                         CommentType type,
                         std::optional<std::string> comment) {
    require_mutation();
    const auto key = address_key(address, true);
    const auto signed_key = std::bit_cast<std::int64_t>(key);
    auto record = table_->record(signed_key);
    if (!record) {
        if (!comment) return;
        record = schema(schema_version)->create_record(signed_key);
    }
    record->set_string(column(type), std::move(comment));
    bool populated = false;
    for (std::size_t index = 0; index < comment_column_count; ++index) {
        if (!record->field(index).is_null()) {
            populated = true;
            break;
        }
    }
    if (populated) table_->put_record(*record);
    else (void)table_->delete_record(signed_key);
}

std::size_t CommentManager::size() const {
    return static_cast<std::size_t>(table_->record_count());
}

void CommentManager::delete_address_range(const Address &start,
                                          const Address &end) {
    require_mutation();
    if (!start.is_valid() || !end.is_valid() || !start.same_space(end) ||
        end < start) {
        throw std::invalid_argument("comment deletion range is invalid");
    }
    std::vector<std::int64_t> keys;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        const auto address = address_map_->decode(std::bit_cast<std::uint64_t>(
            record->key().as_integer()));
        if (address.same_space(start) && address >= start && address <= end) {
            keys.push_back(record->key().as_integer());
        }
    }
    for (const auto key : keys) (void)table_->delete_record(key);
}

void CommentManager::move_address_range(const Address &from,
                                        const Address &to,
                                        std::uint64_t length) {
    require_mutation();
    if (!from.is_memory_address() || !to.is_memory_address() || length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("comment move range is invalid");
    }
    const auto end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    std::vector<std::unique_ptr<db::Record>> moved;
    std::vector<std::int64_t> old_keys;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        const auto address = address_map_->decode(std::bit_cast<std::uint64_t>(
            record->key().as_integer()));
        if (!address.same_space(from) || address < from || address > end) continue;
        auto copy = record->clone();
        copy->set_key(std::bit_cast<std::int64_t>(address_key(
            to.add_no_wrap(address.subtract(from)), true)));
        old_keys.push_back(record->key().as_integer());
        moved.push_back(std::move(copy));
    }
    for (const auto key : old_keys) (void)table_->delete_record(key);
    for (const auto &record : moved) table_->put_record(*record);
}

void CommentManager::validate_bound_table() const {
    const bool current =
        table_ && table_->schema().equals(*schema(schema_version));
    const bool legacy_read_only =
        table_ && mode_ == ProgramOpenMode::read_only &&
        stored_schema_version_ == 0 && table_->schema().equals(*schema(0));
    if (!current && !legacy_read_only) {
        throw std::runtime_error("unsupported or missing Ghidra Comments table");
    }
}

void CommentManager::invalidate_cache() {
    table_ = database_->get_table(table_name);
    stored_schema_version_ = table_ ? table_->schema().version() : -1;
    validate_bound_table();
}

void CommentManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

} // namespace llmghidra::program
