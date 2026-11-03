#include "llmghidra/program/overlay_space_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/language_translator.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

using F = db::FieldType;
constexpr const char *scratch_table_name = "__LLMGHIDRA_OVERLAY_SPACES";

[[nodiscard]] std::vector<std::unique_ptr<db::Field>> fields(
    std::initializer_list<F> types) {
    std::vector<std::unique_ptr<db::Field>> result;
    result.reserve(types.size());
    for (const auto type : types) result.push_back(db::make_field(type));
    return result;
}

[[nodiscard]] std::shared_ptr<db::Schema> make_schema(
    int version, std::initializer_list<F> types,
    std::vector<std::string> names) {
    return std::make_shared<db::Schema>(
        version, db::make_field(F::int64), "ID", fields(types),
        std::move(names));
}

} // namespace

std::shared_ptr<db::Schema> OverlaySpaceManager::current_schema() {
    return make_schema(1, {F::string, F::string},
                       {"Overlay Space Name", "Base Space Name"});
}

std::shared_ptr<db::Schema> OverlaySpaceManager::legacy_schema() {
    return make_schema(0, {F::string, F::string, F::int64, F::int64},
                       {"Overlay Space Name", "Base Space Name",
                        "Minimum Offset", "Maximum Offset"});
}

OverlaySpaceManager::OverlaySpaceManager(
    std::shared_ptr<db::DatabaseHandle> database,
    std::shared_ptr<AddressFactory> address_factory,
    ProgramOpenMode mode, bool create)
    : database_(std::move(database)),
      address_factory_(std::move(address_factory)), mode_(mode) {
    if (!database_ || !address_factory_) {
        throw std::invalid_argument(
            "overlay space manager requires a database and address factory");
    }
    try {
        if (!create) open_table();
        initialize_factory();
    }
    catch (...) {
        for (const auto &name : managed_names_) {
            address_factory_->remove_space(name);
        }
        managed_names_.clear();
        address_factory_->refresh_stale_overlay_status();
        throw;
    }
}

OverlaySpaceManager::~OverlaySpaceManager() {
    for (const auto &name : managed_names_) {
        try {
            address_factory_->remove_space(name);
        }
        catch (...) {
        }
    }
    address_factory_->refresh_stale_overlay_status();
}

void OverlaySpaceManager::open_table() {
    auto source = database_->get_table(table_name);
    if (!source) return;
    if (source->schema().equals(*current_schema())) {
        table_ = std::move(source);
        return;
    }
    if (!source->schema().equals(*legacy_schema())) {
        throw std::runtime_error("unsupported Ghidra Overlay Spaces schema");
    }
    if (mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("Ghidra Overlay Spaces table requires upgrade");
    }

    auto &scratch = database_->scratch_database();
    if (scratch.get_table(scratch_table_name) &&
        !scratch.delete_table(scratch_table_name)) {
        throw std::runtime_error("failed to reset overlay staging table");
    }
    auto staged = scratch.create_table(scratch_table_name, current_schema());
    auto iterator = source->iterator();
    while (iterator->has_next()) {
        const auto old = iterator->next();
        auto current = current_schema()->create_record(
            old->key().as_integer());
        current->set_string(0, old->field(0).as_string());
        current->set_string(1, old->field(1).as_string());
        staged->put_record(*current);
    }
    if (mode_ == ProgramOpenMode::upgrade) {
        if (!database_->delete_table(table_name)) {
            throw std::runtime_error("failed to replace legacy overlay table");
        }
        table_ = database_->create_table(table_name, current_schema());
        iterator = staged->iterator();
        while (iterator->has_next()) table_->put_record(*iterator->next());
    }
    else {
        table_ = std::move(staged);
    }
}

void OverlaySpaceManager::initialize_factory() {
    managed_names_.clear();
    if (!table_) {
        address_factory_->refresh_stale_overlay_status();
        return;
    }
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        const auto name = record->field(0).as_string().value_or(std::string{});
        const auto base_name =
            record->field(1).as_string().value_or(std::string{});
        require_valid_name(name);
        const auto base = address_factory_->space(base_name);
        if (!base || !base->is_memory_space() || base->is_overlay_space()) {
            throw std::runtime_error("persisted overlay base space is unavailable");
        }
        if (const auto existing = address_factory_->space(name)) {
            const auto existing_base = existing->overlayed_space();
            if (!existing->is_overlay_space() || !existing_base ||
                !existing_base->equivalent(*base)) {
                throw std::runtime_error(
                    "persisted overlay duplicates an incompatible address-space name");
            }
            managed_names_.push_back(name);
            continue;
        }
        auto overlay = AddressSpace::create_overlay(
            name, base, allocate_unique(), {}, name);
        address_factory_->add_space(std::move(overlay));
        managed_names_.push_back(name);
    }
    address_factory_->refresh_stale_overlay_status();
}

std::vector<OverlaySpaceInfo> OverlaySpaceManager::all() const {
    std::vector<OverlaySpaceInfo> result;
    if (!table_) return result;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        const auto record = iterator->next();
        result.push_back({
            record->key().as_integer(),
            record->field(0).as_string().value_or(std::string{}),
            record->field(1).as_string().value_or(std::string{})});
    }
    return result;
}

void OverlaySpaceManager::require_mutation() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

void OverlaySpaceManager::require_valid_name(const std::string &name) const {
    if (name.empty() || std::ranges::any_of(name, [](unsigned char value) {
            return value <= 0x20 || value == ':';
        })) {
        throw std::invalid_argument("invalid overlay address-space name");
    }
}

std::uint32_t OverlaySpaceManager::allocate_unique() const {
    std::uint32_t next = 0;
    for (const auto &space : address_factory_->all_spaces()) {
        next = std::max(next, space->unique() + 1);
    }
    if (next > static_cast<std::uint32_t>(
                   std::numeric_limits<std::int16_t>::max())) {
        throw std::overflow_error("no address-space unique IDs remain");
    }
    return next;
}

std::shared_ptr<db::Table> OverlaySpaceManager::writable_table() {
    require_mutation();
    if (!table_) {
        table_ = database_->create_table(table_name, current_schema());
    }
    if (!table_->schema().equals(*current_schema())) {
        throw std::logic_error("overlay mutation requires current schema");
    }
    return table_;
}

std::shared_ptr<AddressSpace> OverlaySpaceManager::create(
    std::string name, const std::shared_ptr<AddressSpace> &base_space) {
    require_valid_name(name);
    if (!base_space || !base_space->is_memory_space() ||
        base_space->is_overlay_space() ||
        address_factory_->space(base_space->name()) != base_space) {
        throw std::invalid_argument("invalid overlay base address space");
    }
    if (address_factory_->space(name)) {
        throw std::invalid_argument("overlay address-space name already exists");
    }
    auto destination = writable_table();
    const auto id = destination->next_long_key();
    auto record = current_schema()->create_record(id);
    record->set_string(0, name);
    record->set_string(1, base_space->name());
    destination->put_record(*record);
    auto overlay = AddressSpace::create_overlay(
        name, base_space, allocate_unique(), {}, name);
    address_factory_->add_space(overlay);
    managed_names_.push_back(std::move(name));
    return overlay;
}

bool OverlaySpaceManager::rename(const std::string &old_name,
                                 std::string new_name) {
    require_mutation();
    require_valid_name(new_name);
    if (address_factory_->space(new_name)) {
        throw std::invalid_argument("overlay address-space name already exists");
    }
    if (!table_) return false;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (record->field(0).as_string() !=
            std::optional<std::string>(old_name)) {
            continue;
        }
        const auto existing = address_factory_->space(old_name);
        if (!existing || !existing->is_overlay_space()) {
            throw std::runtime_error("overlay factory/table state is inconsistent");
        }
        record->set_string(0, new_name);
        table_->put_record(*record);
        address_factory_->rename_overlay(old_name, new_name);
        auto position = std::ranges::find(managed_names_, old_name);
        if (position != managed_names_.end()) *position = std::move(new_name);
        return true;
    }
    return false;
}

bool OverlaySpaceManager::remove(const std::string &name) {
    require_mutation();
    if (!table_) return false;
    auto iterator = table_->iterator();
    while (iterator->has_next()) {
        auto record = iterator->next();
        if (record->field(0).as_string() != std::optional<std::string>(name)) {
            continue;
        }
        if (!table_->delete_record(record->key().as_integer())) return false;
        address_factory_->remove_space(name);
        std::erase(managed_names_, name);
        address_factory_->refresh_stale_overlay_status();
        return true;
    }
    return false;
}

void OverlaySpaceManager::set_language(
    std::shared_ptr<AddressFactory> new_address_factory,
    const LanguageTranslator &translator) {
    if (!new_address_factory) {
        throw std::invalid_argument(
            "overlay language change requires an address factory");
    }
    require_mutation();
    if (&translator.old_address_factory() != address_factory_.get() ||
        &translator.new_address_factory() != new_address_factory.get()) {
        throw std::invalid_argument(
            "language translator address factories do not match Overlay Spaces");
    }

    struct Replacement {
        std::int64_t key{};
        std::string base_name;
    };
    std::vector<Replacement> replacements;
    for (const auto &info : all()) {
        const auto mapped_base = translator.new_address_space(
            info.base_space_name);
        const auto target = mapped_base
            ? new_address_factory->space(*mapped_base) : nullptr;
        if (!target || !target->is_memory_space() ||
            target->is_overlay_space()) {
            throw std::runtime_error(
                "language translation cannot preserve overlay base space: " +
                info.base_space_name);
        }
        if (new_address_factory->space(info.name)) {
            throw std::runtime_error(
                "new language address factory already contains overlay name: " +
                info.name);
        }
        replacements.push_back({info.id, target->name()});
    }
    if (table_) {
        for (const auto &replacement : replacements) {
            auto record = table_->record(replacement.key);
            if (!record) {
                throw std::runtime_error(
                    "Overlay Spaces record disappeared during language change");
            }
            record->set_string(1, replacement.base_name);
            table_->put_record(*record);
        }
    }

    // Keep the old factory intact until the enclosing Program transaction is
    // committed.  A rollback can then rebind it without reconstructing stale
    // overlay Address objects held by decoded Program records.
    managed_names_.clear();
    address_factory_ = std::move(new_address_factory);
    initialize_factory();
}

void OverlaySpaceManager::rebind_address_factory(
    std::shared_ptr<AddressFactory> address_factory) {
    if (!address_factory) {
        throw std::invalid_argument("overlay address factory must not be null");
    }
    for (const auto &name : managed_names_) {
        address_factory_->remove_space(name);
    }
    managed_names_.clear();
    address_factory_->refresh_stale_overlay_status();
    address_factory_ = std::move(address_factory);
    if (mode_ != ProgramOpenMode::read_only) {
        table_ = database_->get_table(table_name);
    }
    initialize_factory();
}

void OverlaySpaceManager::reconcile_regions(
    const std::vector<AddressRange> &memory_ranges) {
    std::map<std::string,
             std::vector<std::pair<std::uint64_t, std::uint64_t>>> regions;
    for (const auto &range : memory_ranges) {
        const auto space = range.min_address().space();
        if (!space || !space->is_overlay_space()) continue;
        regions[space->name()].emplace_back(
            range.min_address().offset(), range.max_address().offset());
    }
    for (const auto &info : all()) {
        const auto space = address_factory_->space(info.name);
        if (!space || !space->is_overlay_space()) {
            throw std::runtime_error("overlay factory/table state is inconsistent");
        }
        space->set_overlay_regions(std::move(regions[info.name]));
    }
}

void OverlaySpaceManager::invalidate_cache() {
    for (const auto &name : managed_names_) {
        address_factory_->remove_space(name);
    }
    managed_names_.clear();
    if (mode_ != ProgramOpenMode::read_only) {
        table_ = database_->get_table(table_name);
    }
    initialize_factory();
}

} // namespace llmghidra::program
