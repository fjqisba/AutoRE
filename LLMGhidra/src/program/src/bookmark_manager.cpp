#include "llmghidra/program/bookmark_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/persistent_address_map.hpp"
#include "llmghidra/program/property_map_manager.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <map>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr std::uint64_t bookmark_sequence_mask =
    (std::uint64_t{1} << 48U) - 1U;
constexpr std::string_view old_bookmark_property_prefix = "Bookmarks";
constexpr std::string_view note_type = "Note";

[[nodiscard]] std::int32_t bookmark_type_id(std::int64_t id) {
    return static_cast<std::int32_t>(
        std::bit_cast<std::uint64_t>(id) >> 48U);
}

[[nodiscard]] std::string old_property_type(const std::string &name) {
    if (name == old_bookmark_property_prefix) return std::string(note_type);
    return name.substr(old_bookmark_property_prefix.size());
}

} // namespace

std::shared_ptr<db::Schema> BookmarkManager::type_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        type_schema_version,
        std::make_unique<db::IntegerField>(db::FieldType::int64),
        "ID", std::move(fields), std::vector<std::string>{"Name"});
}

std::shared_ptr<db::Schema> BookmarkManager::bookmark_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        bookmark_schema_version,
        std::make_unique<db::IntegerField>(db::FieldType::int64),
        "ID", std::move(fields),
        std::vector<std::string>{"Address", "Category", "Comment"});
}

std::shared_ptr<db::Schema> BookmarkManager::legacy_bookmark_schema(
    int version) {
    if (version != 1 && version != 2) {
        throw std::invalid_argument("unsupported legacy Bookmarks schema");
    }
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "ID", std::move(fields),
        std::vector<std::string>{
            "Address", "Type ID", "Type ID/Category", "Comment"});
}

std::string BookmarkManager::bookmark_table_name(std::int32_t type_id) {
    return std::string(bookmark_table_prefix) + std::to_string(type_id);
}

BookmarkManager::BookmarkManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    PropertyMapManager &properties,
    ProgramOpenMode mode,
    bool create)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode) {
    if (!database_) {
        throw std::invalid_argument("bookmark manager requires a database");
    }
    if (create) {
        create_current_tables();
        return;
    }

    type_table_ = database_->get_table(type_table_name);
    const auto legacy = database_->get_table(bookmark_table_prefix);
    if (!type_table_) {
        load_legacy_property_view(properties);
        if (mode_ == ProgramOpenMode::update) {
            throw std::runtime_error(
                "legacy bookmark properties require Program upgrade mode");
        }
        if (mode_ == ProgramOpenMode::upgrade) {
            upgrade_legacy_properties(properties);
        }
        return;
    }

    if (!type_table_->schema().equals(*type_schema())) {
        throw std::runtime_error("unsupported Ghidra Bookmark Types table");
    }
    if (legacy && legacy->record_count() != 0) {
        const auto version = legacy->schema().version();
        if ((version != 1 && version != 2) ||
            !legacy->schema().equals(*legacy_bookmark_schema(version))) {
            throw std::runtime_error(
                "unsupported legacy Ghidra Bookmarks table");
        }
        if (mode_ != ProgramOpenMode::upgrade) {
            throw std::runtime_error("Ghidra Bookmarks table requires upgrade");
        }
        upgrade_legacy_table(legacy);
    }
    else {
        load_and_validate_current();
        if (address_map_->upgraded()) {
            if (mode_ != ProgramOpenMode::upgrade) {
                throw std::runtime_error(
                    "Ghidra Bookmarks address keys require upgrade");
            }
            rekey_current_tables();
        }
    }
}

void BookmarkManager::create_current_tables() {
    type_table_ = database_->create_table(type_table_name, type_schema());
}

void BookmarkManager::load_and_validate_current() {
    for (const auto &bookmark_type : types()) {
        const auto table = bookmark_table(bookmark_type.id);
        if (!table) {
            throw std::runtime_error(
                "Bookmark Types record has no per-type Bookmarks table");
        }
        if (!table->schema().equals(*bookmark_schema())) {
            throw std::runtime_error(
                "unsupported per-type Ghidra Bookmarks table");
        }
    }
}

void BookmarkManager::load_legacy_property_view(
    PropertyMapManager &properties) {
    std::map<std::string, std::int32_t> type_ids;
    for (const auto &definition : properties.definitions()) {
        if (definition.kind != PropertyMapKind::object ||
            !definition.name.starts_with(old_bookmark_property_prefix)) {
            continue;
        }
        const auto type_name = old_property_type(definition.name);
        if (type_name.empty()) continue;
        auto [type_position, inserted] = type_ids.try_emplace(
            type_name, static_cast<std::int32_t>(type_ids.size()));
        const auto type_id = type_position->second;
        const auto table = properties.object_table(definition.name);
        if (!table || table->schema().key_type().type() != db::FieldType::int64 ||
            table->schema().field_count() < 3 ||
            table->schema().field_type(0).type() != db::FieldType::string ||
            table->schema().field_type(1).type() != db::FieldType::string ||
            table->schema().field_type(2).type() != db::FieldType::string) {
            throw std::runtime_error(
                "legacy OldBookmark property has an incompatible schema");
        }
        std::uint64_t sequence = 0;
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            const auto record = iterator->next();
            if (!record) continue;
            const auto address = address_map_->decode(
                std::bit_cast<std::uint64_t>(record->key().as_integer()));
            if (!address.is_valid()) {
                throw std::runtime_error(
                    "legacy OldBookmark property has an undecodable address");
            }
            const auto raw_id =
                (static_cast<std::uint64_t>(type_id) << 48U) | ++sequence;
            legacy_bookmarks_.push_back(
                {std::bit_cast<std::int64_t>(raw_id),
                 {type_id, type_name}, address,
                 record->field(0).as_string().value_or(std::string{}),
                 record->field(1).as_string().value_or(std::string{})});
        }
        (void)inserted;
    }
    for (const auto &[name, id] : type_ids) {
        legacy_types_.push_back({id, name});
    }
    std::ranges::sort(legacy_types_, {}, &BookmarkType::id);
}

void BookmarkManager::upgrade_legacy_properties(
    PropertyMapManager &properties) {
    const auto source_types = legacy_types_;
    const auto source_bookmarks = legacy_bookmarks_;
    create_current_tables();
    for (const auto &bookmark_type : source_types) {
        auto record = type_schema()->create_record(bookmark_type.id);
        record->set_string(0, bookmark_type.name);
        type_table_->put_record(*record);
        (void)database_->create_table(
            bookmark_table_name(bookmark_type.id), bookmark_schema(), {0, 1});
    }
    for (const auto &bookmark : source_bookmarks) {
        (void)set(bookmark.address, bookmark.type.name,
                  bookmark.category, bookmark.comment);
    }
    for (const auto &bookmark_type : source_types) {
        const auto property_name = bookmark_type.name == note_type
            ? std::string(old_bookmark_property_prefix)
            : std::string(old_bookmark_property_prefix) + bookmark_type.name;
        (void)properties.remove_map(property_name);
    }
    legacy_types_.clear();
    legacy_bookmarks_.clear();
}

void BookmarkManager::upgrade_legacy_table(
    const std::shared_ptr<db::Table> &legacy) {
    struct Staged {
        std::int32_t type_id{};
        Address address;
        std::string category;
        std::string comment;
    };
    std::vector<Staged> staged;
    auto iterator = legacy->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record) continue;
        const auto raw_type_id = record->field(1).as_integer();
        if (raw_type_id < 0 || raw_type_id > 0x7fff) {
            throw std::runtime_error(
                "legacy Bookmark has an invalid type ID");
        }
        auto mangled = record->field(2).as_string().value_or(std::string{});
        const auto separator = mangled.find('/');
        if (separator != std::string::npos) {
            mangled.erase(0, separator + 1);
        }
        const auto address = address_map_->decode(
            std::bit_cast<std::uint64_t>(record->field(0).as_integer()));
        if (!address.is_valid()) {
            throw std::runtime_error(
                "legacy Bookmarks table has an undecodable address");
        }
        staged.push_back(
            {static_cast<std::int32_t>(raw_type_id), address,
             std::move(mangled),
             record->field(3).as_string().value_or(std::string{})});
    }
    (void)database_->delete_table(bookmark_table_prefix);
    for (const auto &bookmark_type : types()) {
        const auto table_name = bookmark_table_name(bookmark_type.id);
        if (database_->get_table(table_name)) {
            (void)database_->delete_table(table_name);
        }
        (void)database_->create_table(table_name, bookmark_schema(), {0, 1});
    }
    for (const auto &entry : staged) {
        const auto type_record = type_table_->record(entry.type_id);
        if (!type_record) {
            throw std::runtime_error(
                "legacy Bookmark references an unknown type ID");
        }
        (void)set(entry.address,
                  type_record->field(0).as_string().value_or(std::string{}),
                  entry.category, entry.comment);
    }
}

void BookmarkManager::rekey_current_tables() {
    for (const auto &bookmark_type : types()) {
        const auto table = bookmark_table(bookmark_type.id);
        std::vector<std::unique_ptr<db::Record>> translated;
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            const auto source = iterator->next();
            if (!source) continue;
            const auto address = address_map_->decode(
                std::bit_cast<std::uint64_t>(source->field(0).as_integer()));
            if (!address.is_valid()) {
                throw std::runtime_error(
                    "Bookmarks table has an undecodable address key");
            }
            auto destination = source->clone();
            destination->set_integer(
                0, std::bit_cast<std::int64_t>(
                       address_map_->key(address, true)));
            translated.push_back(std::move(destination));
        }
        const auto name = bookmark_table_name(bookmark_type.id);
        (void)database_->delete_table(name);
        const auto replacement = database_->create_table(
            name, bookmark_schema(), {0, 1});
        for (const auto &record : translated) replacement->put_record(*record);
    }
}

std::shared_ptr<db::Table> BookmarkManager::bookmark_table(
    std::int32_t type_id) const {
    return database_->get_table(bookmark_table_name(type_id));
}

std::vector<BookmarkType> BookmarkManager::types() const {
    if (!type_table_) return legacy_types_;
    std::vector<BookmarkType> result;
    auto iterator = type_table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (!record) continue;
        const auto name = record->field(0).as_string();
        if (!name || name->empty() || record->key().as_integer() < 0 ||
            record->key().as_integer() > std::numeric_limits<std::int32_t>::max()) {
            throw std::runtime_error("invalid Ghidra Bookmark Type record");
        }
        result.push_back(
            {static_cast<std::int32_t>(record->key().as_integer()), *name});
    }
    std::ranges::sort(result, {}, &BookmarkType::id);
    return result;
}

std::optional<BookmarkType> BookmarkManager::type(
    const std::string &name) const {
    const auto values = types();
    const auto found = std::ranges::find(values, name, &BookmarkType::name);
    return found == values.end() ? std::nullopt
                                 : std::optional<BookmarkType>(*found);
}

BookmarkType BookmarkManager::create_type(std::string name) {
    require_mutation();
    if (name.empty()) {
        throw std::invalid_argument("bookmark type name must not be empty");
    }
    if (type(name)) {
        throw std::invalid_argument("bookmark type already exists");
    }
    std::int32_t id = 0;
    const auto existing = types();
    while (std::ranges::any_of(existing, [id](const auto &candidate) {
        return candidate.id == id;
    })) {
        if (id == std::numeric_limits<std::int32_t>::max()) {
            throw std::overflow_error("bookmark type ID space is exhausted");
        }
        ++id;
    }
    if (id > 0x7fff) {
        throw std::overflow_error(
            "bookmark type ID exceeds the V3 composite-key range");
    }
    auto record = type_schema()->create_record(id);
    record->set_string(0, name);
    type_table_->put_record(*record);
    (void)database_->create_table(
        bookmark_table_name(id), bookmark_schema(), {0, 1});
    return {id, std::move(name)};
}

bool BookmarkManager::remove_type(const std::string &name) {
    require_mutation();
    const auto found = type(name);
    if (!found) return false;
    (void)database_->delete_table(bookmark_table_name(found->id));
    return type_table_->delete_record(found->id);
}

std::uint64_t BookmarkManager::address_key(
    const Address &address, bool create) const {
    if (!address.is_memory_address() && !address.is_external_address()) {
        throw std::invalid_argument(
            "bookmarks require a memory or external address");
    }
    return address_map_->key(address, create);
}

std::int64_t BookmarkManager::allocate_id(
    std::int32_t type_id, const db::Table &table) const {
    // BookmarkDBAdapterV3 deliberately allocates with table.getKey() + 1.
    // Table::next_long_key() is the native equivalent of Table.getKey(); it
    // uses the persisted high-water mark, including keys that were deleted.
    // Preserve the upstream sequence (1, 3, 5, ...) instead of scanning only
    // the records that happen to remain in the table.
    const auto next_table_key = table.next_long_key();
    if (next_table_key == std::numeric_limits<std::int64_t>::max()) {
        throw std::overflow_error("bookmark ID space is exhausted");
    }
    const auto raw = (static_cast<std::uint64_t>(type_id) << 48U) |
                     std::bit_cast<std::uint64_t>(next_table_key + 1);
    if ((raw >> 48U) != static_cast<std::uint64_t>(type_id) ||
        (raw & bookmark_sequence_mask) == 0) {
        throw std::overflow_error("bookmark ID space is exhausted");
    }
    return std::bit_cast<std::int64_t>(raw);
}

Bookmark BookmarkManager::decode(
    const BookmarkType &bookmark_type,
    const db::Record &record) const {
    if (bookmark_type_id(record.key().as_integer()) != bookmark_type.id) {
        throw std::runtime_error(
            "Bookmark record key does not match its type table");
    }
    const auto address = address_map_->decode(
        std::bit_cast<std::uint64_t>(record.field(0).as_integer()));
    if (!address.is_valid()) {
        throw std::runtime_error("Bookmark record has an invalid address");
    }
    return {record.key().as_integer(), bookmark_type, address,
            record.field(1).as_string().value_or(std::string{}),
            record.field(2).as_string().value_or(std::string{})};
}

Bookmark BookmarkManager::set(
    const Address &address,
    std::string type_name,
    std::string category,
    std::string comment) {
    require_mutation();
    auto bookmark_type = type(type_name);
    if (!bookmark_type) bookmark_type = create_type(std::move(type_name));
    const auto table = bookmark_table(bookmark_type->id);
    const auto key = address_key(address, true);
    auto iterator = table->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (!record ||
            std::bit_cast<std::uint64_t>(record->field(0).as_integer()) != key ||
            record->field(1).as_string().value_or(std::string{}) != category) {
            continue;
        }
        record->set_string(2, comment);
        table->put_record(*record);
        return decode(*bookmark_type, *record);
    }
    auto record = bookmark_schema()->create_record(
        allocate_id(bookmark_type->id, *table));
    record->set_integer(0, std::bit_cast<std::int64_t>(key));
    record->set_string(1, std::move(category));
    record->set_string(2, std::move(comment));
    table->put_record(*record);
    return decode(*bookmark_type, *record);
}

std::optional<Bookmark> BookmarkManager::get(std::int64_t id) const {
    if (!type_table_) {
        const auto found = std::ranges::find(
            legacy_bookmarks_, id, &Bookmark::id);
        return found == legacy_bookmarks_.end()
            ? std::nullopt : std::optional<Bookmark>(*found);
    }
    const auto type_id = bookmark_type_id(id);
    const auto type_record = type_table_->record(type_id);
    const auto table = bookmark_table(type_id);
    if (!type_record || !table) return std::nullopt;
    const auto record = table->record(id);
    if (!record) return std::nullopt;
    return decode(
        {type_id, type_record->field(0).as_string().value_or(std::string{})},
        *record);
}

std::vector<Bookmark> BookmarkManager::all() const {
    if (!type_table_) return legacy_bookmarks_;
    std::vector<Bookmark> result;
    for (const auto &bookmark_type : types()) {
        const auto table = bookmark_table(bookmark_type.id);
        if (!table) continue;
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            const auto record = iterator->next();
            if (record) result.push_back(decode(bookmark_type, *record));
        }
    }
    std::ranges::sort(result, [](const auto &left, const auto &right) {
        if (left.address != right.address) return left.address < right.address;
        return left.id < right.id;
    });
    return result;
}

std::optional<Bookmark> BookmarkManager::get(
    const Address &address,
    const std::string &type_name,
    const std::string &category) const {
    const auto values = of_type(type_name);
    const auto found = std::ranges::find_if(values, [&](const auto &bookmark) {
        return bookmark.address == address && bookmark.category == category;
    });
    return found == values.end() ? std::nullopt
                                 : std::optional<Bookmark>(*found);
}

std::vector<Bookmark> BookmarkManager::at(const Address &address) const {
    std::vector<Bookmark> result;
    for (const auto &bookmark : all()) {
        if (bookmark.address == address) result.push_back(bookmark);
    }
    return result;
}

std::vector<Bookmark> BookmarkManager::of_type(
    const std::string &type_name) const {
    std::vector<Bookmark> result;
    for (const auto &bookmark : all()) {
        if (bookmark.type.name == type_name) result.push_back(bookmark);
    }
    return result;
}

std::vector<std::string> BookmarkManager::categories(
    const std::string &type_name) const {
    std::set<std::string> unique;
    for (const auto &bookmark : of_type(type_name)) {
        if (!bookmark.category.empty()) unique.insert(bookmark.category);
    }
    return {unique.begin(), unique.end()};
}

std::size_t BookmarkManager::size() const {
    if (!type_table_) return legacy_bookmarks_.size();
    std::size_t count = 0;
    for (const auto &bookmark_type : types()) {
        if (const auto table = bookmark_table(bookmark_type.id)) {
            count += static_cast<std::size_t>(table->record_count());
        }
    }
    return count;
}

void BookmarkManager::update(const Bookmark &bookmark) {
    require_mutation();
    const auto stored = get(bookmark.id);
    if (!stored || stored->type.id != bookmark.type.id ||
        stored->type.name != bookmark.type.name) {
        throw std::invalid_argument("bookmark identity/type cannot be changed");
    }
    const auto table = bookmark_table(bookmark.type.id);
    auto record = table->record(bookmark.id);
    record->set_integer(
        0, std::bit_cast<std::int64_t>(address_key(bookmark.address, true)));
    record->set_string(1, bookmark.category);
    record->set_string(2, bookmark.comment);
    table->put_record(*record);
}

bool BookmarkManager::remove(std::int64_t id) {
    require_mutation();
    const auto table = bookmark_table(bookmark_type_id(id));
    return table && table->delete_record(id);
}

std::size_t BookmarkManager::remove(
    const std::string &type_name,
    const std::optional<std::string> &category) {
    require_mutation();
    const auto bookmark_type = type(type_name);
    if (!bookmark_type) return 0;
    const auto table = bookmark_table(bookmark_type->id);
    std::vector<std::int64_t> ids;
    auto iterator = table->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        if (record && (!category ||
            record->field(1).as_string().value_or(std::string{}) == *category)) {
            ids.push_back(record->key().as_integer());
        }
    }
    for (const auto id : ids) (void)table->delete_record(id);
    if (!category) (void)remove_type(type_name);
    return ids.size();
}

void BookmarkManager::delete_address_range(
    const Address &start, const Address &end) {
    require_mutation();
    if (!start.is_valid() || !end.is_valid() ||
        !start.same_space(end) || end < start) {
        throw std::invalid_argument("bookmark deletion range is invalid");
    }
    std::vector<std::int64_t> ids;
    for (const auto &bookmark : all()) {
        if (bookmark.address.same_space(start) &&
            bookmark.address >= start && bookmark.address <= end) {
            ids.push_back(bookmark.id);
        }
    }
    for (const auto id : ids) (void)remove(id);
}

void BookmarkManager::move_address_range(
    const Address &from,
    const Address &to,
    std::uint64_t length) {
    require_mutation();
    if (!from.is_memory_address() || !to.is_memory_address() || length == 0 ||
        length - 1 > static_cast<std::uint64_t>(
                         std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("bookmark move range is invalid");
    }
    const auto end = from.add_no_wrap(static_cast<std::int64_t>(length - 1));
    std::vector<Bookmark> moved;
    for (auto bookmark : all()) {
        if (!bookmark.address.same_space(from) ||
            bookmark.address < from || bookmark.address > end) {
            continue;
        }
        bookmark.address = to.add_no_wrap(bookmark.address.subtract(from));
        moved.push_back(std::move(bookmark));
    }
    for (const auto &bookmark : moved) update(bookmark);
}

void BookmarkManager::invalidate_cache() {
    type_table_ = database_->get_table(type_table_name);
    if (!type_table_) {
        if (mode_ != ProgramOpenMode::read_only) {
            throw std::runtime_error("missing Ghidra Bookmark Types table");
        }
        return;
    }
    if (!type_table_->schema().equals(*type_schema())) {
        throw std::runtime_error("unsupported Ghidra Bookmark Types table");
    }
    load_and_validate_current();
}

void BookmarkManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    if (!type_table_) {
        throw std::logic_error(
            "legacy bookmark properties must be upgraded before mutation");
    }
    database_->check_transaction();
}

} // namespace llmghidra::program
