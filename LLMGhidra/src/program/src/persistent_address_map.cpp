#include "llmghidra/program/persistent_address_map.hpp"

#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/language_translator.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr const char *address_map_table_name = "ADDRESS MAP";
constexpr std::uint32_t address_offset_bits = 32;
constexpr std::uint64_t address_offset_mask = 0xffffffffULL;
constexpr std::uint64_t base_mask = ~address_offset_mask;
constexpr std::uint32_t id_mask = 0x0fffffffU;
constexpr std::uint64_t type_shift = 60;
constexpr std::uint64_t absolute_type = 1ULL << type_shift;
constexpr std::uint64_t relocatable_type = 2ULL << type_shift;
constexpr std::uint64_t register_type = 3ULL << type_shift;
constexpr std::uint64_t stack_type = 4ULL << type_shift;
constexpr std::uint64_t external_type = 5ULL << type_shift;
constexpr std::uint64_t variable_type = 6ULL << type_shift;
constexpr std::uint64_t hash_type = 7ULL << type_shift;
constexpr std::uint64_t hash_mask = (1ULL << 60) - 1;
constexpr std::uint64_t no_address_type = 15ULL << type_shift;
constexpr std::uint64_t external_entry_key =
    std::bit_cast<std::uint64_t>(std::int64_t{-2});

[[nodiscard]] std::shared_ptr<db::Schema> map_schema(int version) {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::StringField>());
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int32));
    if (version == 0) {
        fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int16));
    }
    else {
        fields.push_back(std::make_unique<db::BooleanField>());
    }
    return std::make_shared<db::Schema>(
        version, std::make_unique<db::IntegerField>(db::FieldType::int64), "Key",
        std::move(fields),
        std::vector<std::string>{"Space Name", "Segment",
                                 version == 0 ? "Not Used" : "Deleted"});
}

[[nodiscard]] std::int32_t narrow_key(const db::Record &record) {
    const std::int64_t key = record.key().as_integer();
    if (key < 0 || key > std::numeric_limits<std::int32_t>::max()) {
        throw std::runtime_error("ADDRESS MAP contains an invalid record key");
    }
    return static_cast<std::int32_t>(key);
}

} // namespace

class PersistentAddressMap::Adapter {
public:
    Adapter(std::shared_ptr<db::DatabaseHandle> database,
            ProgramOpenMode mode,
            std::shared_ptr<AddressFactory> factory)
        : database_(std::move(database)), factory_(std::move(factory)) {
        if (mode == ProgramOpenMode::create) {
            schema_ = map_schema(1);
            table_ = database_->create_table(address_map_table_name, schema_);
            return;
        }

        table_ = database_->get_table(address_map_table_name);
        if (!table_) {
            if (mode == ProgramOpenMode::read_only) {
                schema_ = map_schema(1);
                no_table_ = true;
                use_old_address_encoding_ = true;
                return;
            }
            if (mode == ProgramOpenMode::upgrade) {
                const auto old_entries = factory_entries();
                schema_ = map_schema(1);
                table_ = database_->create_table(address_map_table_name, schema_);
                write_entries(old_entries);
                upgraded_ = true;
                return;
            }
            throw std::runtime_error("ADDRESS MAP table is missing");
        }
        const int version = table_->schema().version();
        if (version == 1) {
            schema_ = table_->schema_handle();
            return;
        }
        if (version != 0) {
            throw std::runtime_error("unsupported ADDRESS MAP schema version " +
                                     std::to_string(version));
        }
        if (mode == ProgramOpenMode::update) {
            throw std::runtime_error("ADDRESS MAP schema requires upgrade");
        }
        if (mode == ProgramOpenMode::upgrade) {
            const auto old_entries = entries();
            if (!database_->delete_table(address_map_table_name)) {
                throw std::runtime_error("failed to replace legacy ADDRESS MAP table");
            }
            schema_ = map_schema(1);
            table_ = database_->create_table(address_map_table_name, schema_);
            write_entries(old_entries);
            upgraded_ = true;
        }
        else {
            schema_ = table_->schema_handle();
            legacy_ = true;
        }
    }

    [[nodiscard]] bool upgraded() const noexcept { return upgraded_; }
    [[nodiscard]] bool uses_old_address_encoding() const noexcept {
        return use_old_address_encoding_;
    }

    [[nodiscard]] std::vector<Entry> entries() const {
        if (no_table_) {
            return factory_entries();
        }
        std::vector<Entry> result;
        auto iterator = table_->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            Entry entry;
            entry.index = narrow_key(*record);
            entry.name = record->field(0).as_string().value_or(std::string{});
            entry.segment = static_cast<std::int32_t>(record->field(1).as_integer());
            entry.deleted = legacy_ ? !factory_->space(entry.name)
                                    : record->field(2).as_boolean();
            if (entry.index != static_cast<std::int32_t>(result.size())) {
                throw std::runtime_error("ADDRESS MAP record indexes are not contiguous");
            }
            result.push_back(std::move(entry));
        }
        return result;
    }

    [[nodiscard]] std::vector<Address> bases(bool) const {
        std::vector<Address> result;
        for (const auto &entry : entries()) {
            auto selected = factory_->space(entry.name);
            std::int32_t segment = entry.segment;
            if (entry.deleted || !selected) {
                std::string deleted_name = "Deleted_" + entry.name;
                if (segment != 0) {
                    deleted_name += "_" + std::to_string(segment);
                }
                selected = AddressSpace::create(
                    {std::move(deleted_name), 64, 1, AddressSpaceType::deleted,
                     static_cast<std::uint32_t>(entry.index), true});
                segment = 0;
            }
            else if (legacy_ && selected->size() <= 32) {
                segment = 0;
            }
            const std::uint64_t base =
                static_cast<std::uint64_t>(static_cast<std::uint32_t>(segment)) << 32;
            result.push_back(selected->address_in_this_space(base));
        }
        return result;
    }

    [[nodiscard]] std::vector<Address> add_base(const Address &address,
                                                std::uint64_t normalized_offset) {
        if (legacy_ || no_table_) {
            throw std::logic_error("legacy/read-only ADDRESS MAP cannot add base addresses");
        }
        auto record = schema_->create_record(static_cast<std::int64_t>(table_->record_count()));
        record->set_string(0, address.space()->name());
        record->set_integer(1, static_cast<std::int32_t>(normalized_offset >> 32));
        record->set_boolean(2, false);
        table_->put_record(*record);
        return bases(true);
    }

    void rename_overlay(const std::string &old_name, const std::string &new_name) {
        require_current();
        auto iterator = table_->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (!record->field(2).as_boolean() &&
                record->field(0).as_string() == std::optional<std::string>(old_name)) {
                record->set_string(0, new_name);
                table_->put_record(*record);
            }
        }
    }

    void delete_overlay(const std::string &name) {
        require_current();
        auto iterator = table_->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (record->field(0).as_string() == std::optional<std::string>(name)) {
                record->set_boolean(2, true);
                table_->put_record(*record);
            }
        }
    }

    void clear() {
        require_current();
        table_->delete_all();
    }

    void set_factory(std::shared_ptr<AddressFactory> factory) {
        factory_ = std::move(factory);
    }

    void set_language(const AddressFactory &new_factory,
                      const LanguageTranslator &translator) {
        require_current();
        auto iterator = table_->iterator();
        while (iterator->has_next()) {
            auto record = iterator->next();
            if (record->field(2).as_boolean()) continue;
            const auto old_name =
                record->field(0).as_string().value_or(std::string{});
            std::optional<std::string> mapped_name;
            const auto old_space = factory_->space(old_name);
            if (old_space && old_space->is_overlay_space()) {
                const auto preserved = new_factory.space(old_name);
                if (preserved && preserved->is_overlay_space()) {
                    mapped_name = preserved->name();
                }
            }
            else {
                mapped_name = translator.new_address_space(old_name);
            }
            const auto mapped_space = mapped_name
                ? new_factory.space(*mapped_name) : nullptr;
            const auto segment = static_cast<std::int32_t>(
                record->field(1).as_integer());
            if (!mapped_space || (segment != 0 && mapped_space->size() <= 32)) {
                record->set_boolean(2, true);
            }
            else {
                record->set_string(0, mapped_space->name());
                record->set_boolean(2, false);
            }
            table_->put_record(*record);
        }
    }

private:
    [[nodiscard]] std::vector<Entry> factory_entries() const {
        std::vector<Address> addresses;
        addresses.reserve(factory_->all_spaces().size());
        for (const auto &space : factory_->all_spaces()) {
            addresses.push_back(space->address_in_this_space(0));
        }
        std::sort(addresses.begin(), addresses.end());
        std::vector<Entry> result;
        result.reserve(addresses.size());
        for (std::size_t index = 0; index < addresses.size(); ++index) {
            if (index > static_cast<std::size_t>(
                            std::numeric_limits<std::int32_t>::max())) {
                throw std::overflow_error(
                    "address factory has too many spaces for ADDRESS MAP");
            }
            result.push_back({static_cast<std::int32_t>(index),
                              addresses[index].space()->name(), 0, false});
        }
        return result;
    }

    void require_current() const {
        if (legacy_ || no_table_) {
            throw std::logic_error("operation requires the current writable ADDRESS MAP schema");
        }
    }

    void write_entries(const std::vector<Entry> &source) {
        for (const auto &entry : source) {
            if (entry.index != table_->record_count()) {
                throw std::runtime_error("legacy ADDRESS MAP has a missing index");
            }
            auto record = schema_->create_record(entry.index);
            record->set_string(0, entry.name);
            record->set_integer(1, entry.segment);
            record->set_boolean(2, entry.deleted);
            table_->put_record(*record);
        }
    }

    std::shared_ptr<db::DatabaseHandle> database_;
    std::shared_ptr<AddressFactory> factory_;
    std::shared_ptr<db::Table> table_;
    std::shared_ptr<const db::Schema> schema_;
    bool legacy_{};
    bool no_table_{};
    bool upgraded_{};
    bool use_old_address_encoding_{};
};

PersistentAddressMap::PersistentAddressMap(
    std::shared_ptr<db::DatabaseHandle> database,
    ProgramOpenMode mode,
    std::shared_ptr<AddressFactory> factory,
    std::uint64_t image_base_offset)
    : database_(std::move(database)),
      factory_(std::move(factory)),
      image_base_offset_(image_base_offset) {
    if (!database_ || !factory_) {
        throw std::invalid_argument("persistent address map requires database and factory");
    }
    adapter_ = std::make_unique<Adapter>(database_, mode, factory_);
    upgraded_ = adapter_->upgraded();
    use_old_address_encoding_ = adapter_->uses_old_address_encoding();
    reload_bases(false);
}

void PersistentAddressMap::reload_bases(bool force) {
    bases_ = adapter_->bases(force);
}

Address PersistentAddressMap::canonical_address(const Address &address) const {
    if (!address.is_valid()) {
        return Address::no_address();
    }
    if (address.is_external_entry_address()) {
        return address;
    }
    if (factory_->is_valid(address)) {
        return address;
    }
    const auto candidate = factory_->space(address.space()->name());
    if (!candidate || !candidate->equivalent(*address.space())) {
        throw std::invalid_argument("address belongs to a different program address factory");
    }
    return candidate->address_in_this_space(address.offset());
}

std::uint64_t PersistentAddressMap::normalized_offset(const Address &address) const noexcept {
    return address.space()->equivalent(*factory_->default_space())
               ? address.offset() - image_base_offset_
               : address.offset();
}

std::optional<std::uint32_t> PersistentAddressMap::base_index(
    const Address &address,
    bool normalize,
    LookupMode mode) {
    const std::uint64_t raw = normalize ? normalized_offset(address) : address.offset();
    const std::uint64_t base_offset = raw & base_mask;
    const auto found = std::ranges::find_if(bases_, [&](const Address &base) {
        return base.same_space(address) && base.offset() == base_offset;
    });
    if (found != bases_.end()) {
        return static_cast<std::uint32_t>(std::distance(bases_.begin(), found));
    }
    if (mode == LookupMode::match) {
        return std::nullopt;
    }
    if (bases_.size() > id_mask) {
        throw std::overflow_error("ADDRESS MAP exhausted its 28-bit base index");
    }
    bases_ = adapter_->add_base(address, base_offset);
    return static_cast<std::uint32_t>(bases_.size() - 1);
}

std::uint64_t PersistentAddressMap::encode(const Address &input,
                                           bool absolute,
                                           LookupMode mode) {
    if (!input.is_valid()) {
        return invalid_key;
    }
    const Address address = canonical_address(input);
    if (use_old_address_encoding_) {
        return factory_->old_index(address);
    }
    const auto type = address.space()->type();
    if (type == AddressSpaceType::unknown &&
        address.space()->equivalent(*hash_space())) {
        return hash_type | (address.offset() & hash_mask);
    }
    if (address.space()->is_memory_space()) {
        const bool normalize = !absolute && address.space()->equivalent(*factory_->default_space());
        const auto index = base_index(address, normalize, mode);
        if (!index) {
            return invalid_key;
        }
        const std::uint64_t offset = normalize ? normalized_offset(address) : address.offset();
        return (absolute ? absolute_type : relocatable_type) |
               (static_cast<std::uint64_t>(*index) << address_offset_bits) |
               (offset & address_offset_mask);
    }
    switch (type) {
    case AddressSpaceType::variable:
        return variable_type | (address.offset() & address_offset_mask);
    case AddressSpaceType::reg:
        return register_type | (address.offset() & address_offset_mask);
    case AddressSpaceType::stack:
        return stack_type | (address.offset() & address_offset_mask);
    case AddressSpaceType::external:
        return external_type | (address.offset() & address_offset_mask);
    case AddressSpaceType::none:
        return address.is_external_entry_address() ? external_entry_key
                                                   : invalid_key;
    default:
        throw std::invalid_argument("address-space type cannot be encoded by AddressMapDB");
    }
}

std::uint64_t PersistentAddressMap::key(const Address &address, bool create) {
    std::scoped_lock lock(mutex_);
    return encode(address, false, create ? LookupMode::create : LookupMode::match);
}

std::uint64_t PersistentAddressMap::absolute_key(const Address &address, bool create) {
    std::scoped_lock lock(mutex_);
    return encode(address, true, create ? LookupMode::create : LookupMode::match);
}

Address PersistentAddressMap::decode(std::uint64_t value) const noexcept {
    std::scoped_lock lock(mutex_);
    try {
        const std::uint32_t type = static_cast<std::uint32_t>(value >> type_shift);
        const std::uint64_t offset = value & address_offset_mask;
        const std::uint32_t index =
            static_cast<std::uint32_t>((value >> address_offset_bits) & id_mask);
        switch (type) {
        case 0:
            return factory_->decode_old_index(value);
        case 1:
            return index < bases_.size() ? bases_[index].add_no_wrap(
                                              static_cast<std::int64_t>(offset))
                                         : Address::no_address();
        case 2:
            if (index >= bases_.size()) {
                return Address::no_address();
            }
            return bases_[index].add_wrap(std::bit_cast<std::int64_t>(
                offset + (bases_[index].space()->equivalent(*factory_->default_space())
                              ? image_base_offset_
                              : 0)));
        case 3:
            return factory_->register_space()->address(offset);
        case 4: {
            const std::int32_t signed_offset =
                std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(offset));
            const auto stack = factory_->stack_space();
            if (!stack) {
                return Address::no_address();
            }
            try {
                return stack->address_signed(signed_offset);
            }
            catch (const AddressOutOfBoundsError &) {
                return signed_offset < 0 ? stack->min_address() : stack->max_address();
            }
        }
        case 5:
            return external_space()->address(offset);
        case 6:
            return variable_space()->address(offset);
        case 7:
            return hash_space()->address(value & hash_mask);
        case 15:
            return value == external_entry_key
                       ? Address::external_entry_address()
                       : Address::no_address();
        default:
            return Address::no_address();
        }
    }
    catch (...) {
        return Address::no_address();
    }
}

void PersistentAddressMap::append_memory_key_ranges(
    std::vector<AddressKeyRange> &result,
    Address start,
    Address end,
    bool absolute,
    bool create) {
    if (!start.same_space(end) || start > end) {
        throw std::invalid_argument("key range must be ordered within one address space");
    }

    const bool relative = !absolute;
    if (!absolute && start.space()->equivalent(*factory_->default_space())) {
        start = start.subtract_wrap(std::bit_cast<std::int64_t>(image_base_offset_));
        end = end.subtract_wrap(std::bit_cast<std::int64_t>(image_base_offset_));
    }

    const auto append_normalized = [&](Address range_start, Address range_end) {
        Address cursor = range_start;
        while (true) {
            const std::uint64_t page_base = cursor.offset() & base_mask;
            Address page_end = cursor.space()->address_in_this_space(
                std::min(page_base | address_offset_mask, cursor.space()->max_offset()));
            if (page_end > range_end) {
                page_end = range_end;
            }
            const auto index = base_index(
                cursor, false, create ? LookupMode::create : LookupMode::match);
            if (index) {
                const std::uint64_t prefix = relative ? relocatable_type : absolute_type;
                result.push_back(
                    {prefix | (static_cast<std::uint64_t>(*index) << address_offset_bits) |
                         (cursor.offset() & address_offset_mask),
                     prefix | (static_cast<std::uint64_t>(*index) << address_offset_bits) |
                         (page_end.offset() & address_offset_mask)});
            }
            if (page_end == range_end) {
                break;
            }
            cursor = *page_end.next();
        }
    };

    if (start > end) {
        append_normalized(start, start.space()->max_address());
        append_normalized(start.space()->min_address(), end);
    }
    else {
        append_normalized(start, end);
    }
}

std::vector<AddressKeyRange> PersistentAddressMap::key_ranges(
    const Address &start,
    const Address &end,
    bool absolute,
    bool create) {
    std::scoped_lock lock(mutex_);
    if (!start.same_space(end) || start > end) {
        throw std::invalid_argument("key range must be ordered within one address space");
    }
    if (use_old_address_encoding_) {
        (void)absolute;
        (void)create;
        return {{factory_->old_index(canonical_address(start)),
                 factory_->old_index(canonical_address(end))}};
    }
    std::vector<AddressKeyRange> result;
    if (start.is_memory_address()) {
        append_memory_key_ranges(result, canonical_address(start), canonical_address(end),
                                 absolute, create);
    }
    else {
        const auto minimum = encode(start, absolute, LookupMode::match);
        const auto maximum = encode(end, absolute, LookupMode::match);
        if (minimum != invalid_key && maximum != invalid_key) {
            result.push_back({minimum, maximum});
        }
    }
    return result;
}

std::vector<AddressKeyRange> PersistentAddressMap::key_ranges(
    const AddressSet &set,
    bool absolute,
    bool create) {
    std::scoped_lock lock(mutex_);
    std::vector<AddressKeyRange> result;
    if (use_old_address_encoding_) {
        (void)absolute;
        (void)create;
        result.reserve(set.ranges().size());
        for (const auto &range : set.ranges()) {
            result.push_back(
                {factory_->old_index(canonical_address(range.min_address())),
                 factory_->old_index(canonical_address(range.max_address()))});
        }
        return result;
    }
    for (const auto &range : set.ranges()) {
        if (range.min_address().is_memory_address()) {
            append_memory_key_ranges(result, range.min_address(), range.max_address(),
                                     absolute, create);
        }
        else {
            const auto partial = key_ranges(range.min_address(), range.max_address(),
                                            absolute, create);
            result.insert(result.end(), partial.begin(), partial.end());
        }
    }
    return result;
}

const std::shared_ptr<AddressFactory> &PersistentAddressMap::factory() const noexcept {
    return factory_;
}

Address PersistentAddressMap::image_base() const {
    std::scoped_lock lock(mutex_);
    return factory_->default_space()->address(image_base_offset_);
}

bool PersistentAddressMap::upgraded() const noexcept { return upgraded_; }

bool PersistentAddressMap::uses_old_address_encoding() const noexcept {
    return use_old_address_encoding_;
}

void PersistentAddressMap::set_image_base(Address base) {
    std::scoped_lock lock(mutex_);
    base = canonical_address(base);
    if (!base.space()->equivalent(*factory_->default_space())) {
        throw std::invalid_argument("image base must use the default address space");
    }
    image_base_offset_ = base.offset();
}

void PersistentAddressMap::invalidate_cache() {
    std::scoped_lock lock(mutex_);
    reload_bases(true);
}

void PersistentAddressMap::set_address_factory(std::shared_ptr<AddressFactory> factory) {
    if (!factory) {
        throw std::invalid_argument("address factory must not be null");
    }
    std::scoped_lock lock(mutex_);
    factory_ = std::move(factory);
    adapter_->set_factory(factory_);
    reload_bases(true);
}

void PersistentAddressMap::set_language(
    std::shared_ptr<AddressFactory> factory,
    const LanguageTranslator &translator) {
    if (!factory) {
        throw std::invalid_argument("address factory must not be null");
    }
    database_->check_transaction();
    if (&translator.old_address_factory() != factory_.get() ||
        &translator.new_address_factory() != factory.get()) {
        throw std::invalid_argument(
            "language translator address factories do not match ADDRESS MAP");
    }
    std::scoped_lock lock(mutex_);
    adapter_->set_language(*factory, translator);
    factory_ = std::move(factory);
    adapter_->set_factory(factory_);
    if (image_base_offset_ > factory_->default_space()->max_offset()) {
        throw std::runtime_error(
            "language change makes the image base invalid");
    }
    reload_bases(true);
}

void PersistentAddressMap::rename_overlay_space(const std::string &old_name,
                                                const std::string &new_name) {
    std::scoped_lock lock(mutex_);
    adapter_->rename_overlay(old_name, new_name);
    reload_bases(true);
}

void PersistentAddressMap::delete_overlay_space(const std::string &name) {
    std::scoped_lock lock(mutex_);
    adapter_->delete_overlay(name);
    reload_bases(true);
}

void PersistentAddressMap::clear() {
    std::scoped_lock lock(mutex_);
    adapter_->clear();
    bases_.clear();
}

} // namespace llmghidra::program
