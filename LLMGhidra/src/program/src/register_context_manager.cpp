#include "llmghidra/program/register_context_manager.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/language_translator.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace llmghidra::program {
namespace {

constexpr std::string_view old_context_prefix = "Range Map - ProgContext";

struct LegacyByteRange {
    AddressRange range;
    std::uint8_t value{};
};

struct LegacyContextData {
    std::map<std::int32_t, std::vector<LegacyByteRange>> values;
    std::vector<std::string> table_names;
};

[[nodiscard]] std::shared_ptr<db::Schema> legacy_byte_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::int64));
    fields.push_back(std::make_unique<db::IntegerField>(db::FieldType::byte));
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::IntegerField>(db::FieldType::int64),
        "From", std::move(fields), std::vector<std::string>{"To", "Value"});
}

[[nodiscard]] std::int32_t parse_legacy_offset(std::string_view table_name) {
    const auto suffix = table_name.substr(old_context_prefix.size());
    std::int32_t result{};
    const auto [end, error] = std::from_chars(
        suffix.data(), suffix.data() + suffix.size(), result);
    if (suffix.empty() || error != std::errc{} ||
        end != suffix.data() + suffix.size()) {
        throw std::runtime_error(
            "legacy Program Context table has an invalid register offset");
    }
    return result;
}

[[nodiscard]] LegacyContextData load_legacy_context(
    const std::shared_ptr<db::DatabaseHandle> &database,
    const PersistentAddressMap &address_map) {
    LegacyContextData result;
    for (const auto &table : database->tables()) {
        if (!table->name().starts_with(old_context_prefix)) continue;
        if (!table->schema().equals(*legacy_byte_schema()) ||
            !table->indexed_columns().empty()) {
            throw std::runtime_error(
                "unsupported legacy Program Context range-map schema");
        }
        const auto offset = parse_legacy_offset(table->name());
        if (result.values.contains(offset)) {
            throw std::runtime_error(
                "duplicate legacy Program Context register offset");
        }
        auto &ranges = result.values[offset];
        auto iterator = table->iterator();
        while (iterator->has_next()) {
            const auto row = iterator->next();
            const auto start = address_map.factory()->decode_old_index(
                std::bit_cast<std::uint64_t>(row->key().as_integer()));
            const auto end = address_map.factory()->decode_old_index(
                std::bit_cast<std::uint64_t>(
                    row->field(0).as_integer()));
            if (!start.is_valid() || !end.is_valid() ||
                !start.same_space(end)) {
                throw std::runtime_error(
                    "legacy Program Context record has an invalid address range");
            }
            const auto value = static_cast<std::uint8_t>(
                row->field(1).as_integer());
            if (start <= end) {
                ranges.push_back({AddressRange(start, end), value});
            }
            else {
                ranges.push_back({
                    AddressRange(start, start.space()->max_address()), value});
                ranges.push_back({
                    AddressRange(end.space()->min_address(), end), value});
            }
        }
        std::ranges::sort(ranges, [](const auto &left, const auto &right) {
            return left.range < right.range;
        });
        for (std::size_t index = 1; index < ranges.size(); ++index) {
            if (ranges[index - 1].range.intersects(ranges[index].range)) {
                throw std::runtime_error(
                    "legacy Program Context byte ranges overlap");
            }
        }
        result.table_names.push_back(table->name());
    }
    return result;
}

[[nodiscard]] std::optional<std::uint8_t> legacy_byte_at(
    const LegacyContextData &legacy, std::int32_t offset,
    const Address &address) {
    const auto found = legacy.values.find(offset);
    if (found == legacy.values.end()) return std::nullopt;
    for (const auto &entry : found->second) {
        if (entry.range.contains(address)) return entry.value;
    }
    return std::nullopt;
}

[[nodiscard]] std::int32_t legacy_register_offset(
    const RegisterDescription &description) {
    auto raw = static_cast<std::uint32_t>(description.address.offset());
    const auto bit_length = description.bit_length == 0
                                ? static_cast<std::uint32_t>(description.size) * 8
                                : description.bit_length;
    if (bit_length == 1 && !description.processor_context) {
        raw |= description.least_significant_bit << 28;
        raw |= 0x90000000U;
    }
    return std::bit_cast<std::int32_t>(raw);
}

[[nodiscard]] std::uint64_t parse_setting_integer(
    std::string_view text, const char *attribute) {
    bool negative = false;
    if (!text.empty() && text.front() == '-') {
        negative = true;
        text.remove_prefix(1);
    }
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        base = 16;
        text.remove_prefix(2);
    }
    std::uint64_t magnitude{};
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), magnitude, base);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size()) {
        throw std::runtime_error(
            std::string("invalid context setting ") + attribute);
    }
    return negative ? std::uint64_t{0} - magnitude : magnitude;
}

[[nodiscard]] const std::string &setting_attribute(
    const std::unordered_map<std::string, std::string> &setting,
    const char *name) {
    const auto found = setting.find(name);
    if (found == setting.end() || found->second.empty()) {
        throw std::runtime_error(
            std::string("context setting is missing ") + name);
    }
    return found->second;
}

[[nodiscard]] std::string folded(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] bool range_before(const BinaryAddressRangeValue &left,
                                const BinaryAddressRangeValue &right) {
    return left.range < right.range;
}

} // namespace

bool RegisterValue::has_any_value() const noexcept {
    return std::ranges::any_of(mask, [](std::uint8_t byte) {
        return byte != 0;
    });
}

bool RegisterValue::fully_defined() const noexcept {
    return !mask.empty() && std::ranges::all_of(mask, [](std::uint8_t byte) {
        return byte == 0xff;
    });
}

bool RegisterContextManager::old_context_present(
    const std::shared_ptr<db::DatabaseHandle> &database) {
    if (!database) return false;
    return std::ranges::any_of(database->tables(), [](const auto &table) {
        return table->name().starts_with(old_context_prefix);
    });
}

RegisterContextManager::RegisterContextManager(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    ProgramOpenMode mode,
    std::shared_ptr<const ProgramArchitecture> architecture)
    : database_(std::move(database)), address_map_(&address_map), mode_(mode),
      architecture_(std::move(architecture)) {
    if (!database_) {
        throw std::invalid_argument("register context requires a database");
    }
    auto current_table_names = [&]() {
        std::vector<std::string> result;
        for (const auto &table : database_->tables()) {
            if (table->name().starts_with(table_prefix)) {
                result.push_back(table->name());
            }
        }
        return result;
    }();
    if (!current_table_names.empty() && address_map_->upgraded()) {
        if (mode_ != ProgramOpenMode::upgrade) {
            throw std::logic_error(
                "register-context rekey requires Program upgrade mode");
        }
        auto &scratch = database_->scratch_database();
        auto scratch_owner =
            std::shared_ptr<db::DatabaseHandle>(database_, &scratch);
        std::vector<std::pair<std::string, std::string>> staged_tables;
        for (const auto &name : current_table_names) {
            const auto base_name = name.substr(
                std::char_traits<char>::length(table_prefix));
            if (base_name.empty()) {
                throw std::runtime_error(
                    "Ghidra register-context table has an empty register name");
            }
            const auto staging_map_name =
                "__LLMGHIDRA_REGISTER_CONTEXT_" + base_name;
            const auto staging_table_name =
                std::string("Range Map - ") + staging_map_name;
            if (scratch.get_table(staging_table_name) &&
                !scratch.delete_table(staging_table_name)) {
                throw std::runtime_error(
                    "failed to reset register-context rekey staging table");
            }
            const auto source_table = database_->get_table(name);
            (void)scratch.create_table(
                staging_table_name,
                std::make_shared<db::Schema>(source_table->schema()));
            BinaryAddressRangeMap source(
                database_, *address_map_, ProgramOpenMode::upgrade,
                "Register_" + base_name);
            BinaryAddressRangeMap staged(
                scratch_owner, *address_map_, ProgramOpenMode::upgrade,
                staging_map_name);
            for (auto entry : source.entries()) {
                staged.paint(entry.range.min_address(),
                             entry.range.max_address(),
                             std::move(entry.value));
            }
            staged_tables.emplace_back(name, staging_table_name);
        }
        for (const auto &name : current_table_names) {
            if (!database_->delete_table(name)) {
                throw std::runtime_error(
                    "failed to replace register-context table during rekey");
            }
        }
        for (const auto &[name, staging_name] : staged_tables) {
            const auto source = scratch.get_table(staging_name);
            auto destination = database_->create_table(
                name, std::make_shared<db::Schema>(source->schema()));
            auto iterator = source->iterator();
            while (iterator->has_next()) {
                destination->put_record(*iterator->next());
            }
        }
        current_table_names.clear();
        for (const auto &[name, staging_name] : staged_tables) {
            (void)staging_name;
            current_table_names.push_back(name);
        }
    }
    auto load_current_maps = [&](
        const std::shared_ptr<db::DatabaseHandle> &owner,
        PersistentAddressMap &map,
        ProgramOpenMode map_mode,
        const std::vector<std::string> &names) {
        for (const auto &name : names) {
            const auto base_name = name.substr(
                std::char_traits<char>::length(table_prefix));
            if (base_name.empty()) {
                throw std::runtime_error(
                    "Ghidra register-context table has an empty register name");
            }
            if (!maps_.emplace(
                    base_name, std::make_unique<BinaryAddressRangeMap>(
                                   owner, map, map_mode,
                                   "Register_" + base_name)).second) {
                throw std::runtime_error(
                    "duplicate Ghidra register-context table");
            }
        }
    };

    const auto legacy = load_legacy_context(database_, *address_map_);
    if (legacy.table_names.empty()) {
        load_current_maps(database_, *address_map_, mode_, current_table_names);
        return;
    }
    if (!current_table_names.empty()) {
        load_current_maps(database_, *address_map_, mode_, current_table_names);
        if (mode_ == ProgramOpenMode::upgrade) {
            for (const auto &name : legacy.table_names) {
                if (!database_->delete_table(name)) {
                    throw std::runtime_error(
                        "failed to remove obsolete Program Context table");
                }
            }
        }
        return;
    }
    if (mode_ == ProgramOpenMode::update) {
        throw std::runtime_error(
            "legacy Program Context tables require upgrade");
    }
    if (!architecture_) {
        throw std::runtime_error(
            "legacy Program Context requires ProgramArchitecture register metadata");
    }

    auto &scratch = database_->scratch_database();
    auto scratch_owner = std::shared_ptr<db::DatabaseHandle>(database_, &scratch);
    for (const auto &table : scratch.tables()) {
        if (table->name().starts_with(table_prefix) &&
            !scratch.delete_table(table->name())) {
            throw std::runtime_error(
                "failed to reset Program Context staging table");
        }
    }
    PersistentAddressMap *staging_address_map = address_map_;
    if (mode_ == ProgramOpenMode::read_only) {
        legacy_view_address_map_ = std::make_unique<PersistentAddressMap>(
            scratch_owner, ProgramOpenMode::create,
            address_map_->factory(), address_map_->image_base().offset());
        staging_address_map = legacy_view_address_map_.get();
    }

    std::set<std::string> base_names;
    for (const auto &[name, description] : architecture_->registers) {
        (void)description;
        base_names.insert(binding(name).base_name);
    }
    std::vector<std::string> staged_names;
    for (const auto &base_name : base_names) {
        const auto base_binding = binding(base_name);
        const auto width = static_cast<std::size_t>(base_binding.base.size);
        if (width == 0) continue;
        const auto first_offset = legacy_register_offset(base_binding.base);
        std::vector<Address> boundaries;
        for (std::size_t byte = 0; byte < width; ++byte) {
            const auto raw_offset = static_cast<std::uint32_t>(first_offset) +
                                    static_cast<std::uint32_t>(byte);
            const auto found = legacy.values.find(
                std::bit_cast<std::int32_t>(raw_offset));
            if (found == legacy.values.end()) continue;
            for (const auto &entry : found->second) {
                boundaries.push_back(entry.range.min_address());
                if (const auto after = entry.range.max_address().next()) {
                    boundaries.push_back(*after);
                }
            }
        }
        if (boundaries.empty()) continue;
        std::ranges::sort(boundaries);
        boundaries.erase(std::unique(boundaries.begin(), boundaries.end()),
                         boundaries.end());

        std::vector<std::uint8_t> context_valid_mask(width, 0xff);
        const bool processor_context =
            base_binding.base.processor_context ||
            (architecture_->processor_context_register &&
             folded(*architecture_->processor_context_register) ==
                 folded(base_name));
        if (processor_context) {
            std::ranges::fill(context_valid_mask, 0);
            for (const auto &field : architecture_->processor_context_fields) {
                if (field.end_bit < field.start_bit ||
                    field.end_bit >= width * 8) {
                    throw std::runtime_error(
                        "SLEIGH context field exceeds its base register");
                }
                for (std::uint32_t bit = field.start_bit;
                     bit <= field.end_bit; ++bit) {
                    context_valid_mask[bit / 8] |= static_cast<std::uint8_t>(
                        1U << (7U - bit % 8U));
                }
            }
            for (const auto &[child_name, child] : architecture_->registers) {
                if (folded(child_name) == folded(base_name) ||
                    !child.processor_context || !child.base_register ||
                    folded(*child.base_register) != folded(base_name)) {
                    continue;
                }
                const auto bit_length = child.bit_length == 0
                                            ? static_cast<std::uint32_t>(child.size) * 8
                                            : child.bit_length;
                for (std::uint32_t bit = 0; bit < bit_length; ++bit) {
                    const auto base_bit = child.least_significant_bit + bit;
                    if (base_bit >= width * 8) {
                        throw std::runtime_error(
                            "processor-context child exceeds its base register");
                    }
                    const auto byte_index = width - 1 - base_bit / 8;
                    context_valid_mask[byte_index] |= static_cast<std::uint8_t>(
                        1U << (base_bit % 8));
                }
            }
        }

        auto staged_map = std::make_unique<BinaryAddressRangeMap>(
            scratch_owner, *staging_address_map, ProgramOpenMode::upgrade,
            "Register_" + base_name);
        for (std::size_t boundary = 0; boundary < boundaries.size(); ++boundary) {
            const auto &start = boundaries[boundary];
            Address end = start.space()->max_address();
            if (boundary + 1 < boundaries.size() &&
                boundaries[boundary + 1].same_space(start)) {
                end = *boundaries[boundary + 1].previous();
            }
            std::vector<std::uint8_t> encoded(width * 2, 0);
            for (std::size_t byte = 0; byte < width; ++byte) {
                const auto raw_offset = static_cast<std::uint32_t>(first_offset) +
                                        static_cast<std::uint32_t>(byte);
                const auto value = legacy_byte_at(
                    legacy, std::bit_cast<std::int32_t>(raw_offset), start);
                if (!value) continue;
                const auto significance_index =
                    architecture_->endian == Endian::big
                        ? byte
                        : width - byte - 1;
                encoded[significance_index] = context_valid_mask[significance_index];
                encoded[width + significance_index] =
                    static_cast<std::uint8_t>(
                        *value & context_valid_mask[significance_index]);
            }
            if (has_mask(encoded)) {
                staged_map->paint(start, end, std::move(encoded));
            }
        }
        if (staged_map->has_table()) {
            staged_names.push_back(std::string(table_prefix) + base_name);
        }
    }

    if (mode_ == ProgramOpenMode::upgrade) {
        for (const auto &name : staged_names) {
            const auto source = scratch.get_table(name);
            auto destination = database_->create_table(
                name, std::make_shared<db::Schema>(source->schema()));
            auto iterator = source->iterator();
            while (iterator->has_next()) {
                destination->put_record(*iterator->next());
            }
        }
        for (const auto &name : legacy.table_names) {
            if (!database_->delete_table(name)) {
                throw std::runtime_error(
                    "failed to remove migrated Program Context table");
            }
        }
        load_current_maps(database_, *address_map_, mode_, staged_names);
    }
    else {
        load_current_maps(scratch_owner, *staging_address_map,
                          ProgramOpenMode::read_only, staged_names);
    }
}

RegisterContextManager::RegisterBinding RegisterContextManager::binding(
    const std::string &register_name) const {
    if (!architecture_) {
        throw std::logic_error(
            "register operations require an explicit ProgramArchitecture");
    }
    auto find_named = [&](const std::string &name)
        -> std::pair<std::string, RegisterDescription> {
        if (const auto exact = architecture_->registers.find(name);
            exact != architecture_->registers.end()) {
            return *exact;
        }
        const auto wanted = folded(name);
        for (const auto &candidate : architecture_->registers) {
            if (folded(candidate.first) == wanted) return candidate;
        }
        throw std::out_of_range("program register does not exist: " + name);
    };
    const auto requested = find_named(register_name);
    if (requested.second.size <= 0) {
        throw std::runtime_error("program register has invalid storage size");
    }
    const auto requested_end = requested.second.address.add_no_wrap(
        requested.second.size - 1);
    auto base = requested;
    if (requested.second.base_register) {
        base = find_named(*requested.second.base_register);
    }
    for (const auto &candidate : architecture_->registers) {
        if (requested.second.base_register) break;
        if (candidate.second.size < requested.second.size ||
            !candidate.second.address.same_space(requested.second.address) ||
            candidate.second.address > requested.second.address) {
            continue;
        }
        const auto candidate_end = candidate.second.address.add_no_wrap(
            candidate.second.size - 1);
        if (candidate_end < requested_end) continue;
        const bool candidate_has_table = maps_.contains(candidate.first);
        const bool base_has_table = maps_.contains(base.first);
        if (candidate.second.size > base.second.size ||
            (candidate.second.size == base.second.size &&
             candidate_has_table != base_has_table && candidate_has_table) ||
            (candidate.second.size == base.second.size &&
             candidate_has_table == base_has_table &&
             candidate.first < base.first)) {
            base = candidate;
        }
    }
    if (base.second.size <= 0) {
        throw std::runtime_error("register base has invalid storage size");
    }
    const auto base_end = base.second.address.add_no_wrap(base.second.size - 1);
    if (!base.second.address.same_space(requested.second.address) ||
        base.second.address > requested.second.address ||
        base_end < requested_end) {
        throw std::runtime_error(
            "register base metadata does not contain the requested register");
    }
    const auto byte_delta = static_cast<std::size_t>(
        requested.second.address.subtract(base.second.address));
    const auto requested_size = static_cast<std::size_t>(requested.second.size);
    const auto base_size = static_cast<std::size_t>(base.second.size);
    const auto base_offset = architecture_->endian == Endian::big
        ? byte_delta
        : base_size - byte_delta - requested_size;
    return {requested.first, base.first, requested.second, base.second,
            base_offset};
}

BinaryAddressRangeMap &RegisterContextManager::map_for(
    const std::string &base_name) const {
    if (const auto found = maps_.find(base_name); found != maps_.end()) {
        return *found->second;
    }
    auto inserted = maps_.emplace(
        base_name, std::make_unique<BinaryAddressRangeMap>(
                       database_, *address_map_, mode_,
                       "Register_" + base_name));
    return *inserted.first->second;
}

std::vector<std::uint8_t> RegisterContextManager::empty_base_value(
    const RegisterBinding &binding_value) const {
    return std::vector<std::uint8_t>(
        static_cast<std::size_t>(binding_value.base.size) * 2, 0);
}

std::vector<std::uint8_t> RegisterContextManager::encode_for_base(
    const RegisterBinding &binding_value,
    const RegisterValue &value) const {
    const auto requested_size =
        static_cast<std::size_t>(binding_value.requested.size);
    if (value.mask.size() != requested_size ||
        value.value.size() != requested_size ||
        folded(value.register_name) != folded(binding_value.requested_name)) {
        throw std::invalid_argument(
            "register value byte width or register identity is invalid");
    }
    auto result = empty_base_value(binding_value);
    const auto base_size = static_cast<std::size_t>(binding_value.base.size);
    for (std::size_t index = 0; index < requested_size; ++index) {
        const auto destination = binding_value.base_byte_offset + index;
        result[destination] = value.mask[index];
        result[base_size + destination] =
            static_cast<std::uint8_t>(value.value[index] & value.mask[index]);
    }
    return result;
}

RegisterValue RegisterContextManager::decode_from_base(
    const RegisterBinding &binding_value,
    const std::vector<std::uint8_t> &bytes) const {
    const auto base_size = static_cast<std::size_t>(binding_value.base.size);
    const auto requested_size =
        static_cast<std::size_t>(binding_value.requested.size);
    if (bytes.size() != base_size * 2) {
        throw std::runtime_error(
            "persisted register value does not match the selected language");
    }
    RegisterValue result;
    result.register_name = binding_value.requested_name;
    result.mask.resize(requested_size);
    result.value.resize(requested_size);
    for (std::size_t index = 0; index < requested_size; ++index) {
        const auto source = binding_value.base_byte_offset + index;
        result.mask[index] = bytes[source];
        result.value[index] = static_cast<std::uint8_t>(
            bytes[base_size + source] & bytes[source]);
    }
    return result;
}

void RegisterContextManager::combine(
    std::vector<std::uint8_t> &destination,
    const std::vector<std::uint8_t> &overlay) {
    if (destination.size() != overlay.size() || destination.size() % 2 != 0) {
        throw std::invalid_argument("incompatible register value encodings");
    }
    const auto width = destination.size() / 2;
    for (std::size_t index = 0; index < width; ++index) {
        const auto mask = overlay[index];
        destination[width + index] = static_cast<std::uint8_t>(
            (overlay[width + index] & mask) |
            (destination[width + index] & static_cast<std::uint8_t>(~mask)));
        destination[index] = static_cast<std::uint8_t>(
            destination[index] | mask);
    }
}

void RegisterContextManager::clear_bits(
    std::vector<std::uint8_t> &destination,
    const std::vector<std::uint8_t> &mask) {
    if (destination.size() % 2 != 0 ||
        mask.size() != destination.size() / 2) {
        throw std::invalid_argument("incompatible register clear mask");
    }
    const auto width = mask.size();
    for (std::size_t index = 0; index < width; ++index) {
        const auto keep = static_cast<std::uint8_t>(~mask[index]);
        destination[index] &= keep;
        destination[width + index] &= keep;
    }
}

bool RegisterContextManager::has_mask(
    const std::vector<std::uint8_t> &bytes) noexcept {
    if (bytes.size() % 2 != 0) return false;
    return std::ranges::any_of(
        bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(bytes.size() / 2),
        [](std::uint8_t value) { return value != 0; });
}

void RegisterContextManager::validate_write(
    const RegisterBinding &binding_value,
    const Address &start,
    const Address &end) const {
    if (!start.same_space(end) || end < start) {
        throw std::invalid_argument("register-context range is invalid");
    }
    if (!architecture_ || !architecture_->processor_context_register ||
        !write_validator_) {
        return;
    }
    const auto context = binding(*architecture_->processor_context_register);
    if (folded(context.base_name) == folded(binding_value.base_name)) {
        write_validator_(start, end);
    }
}

void RegisterContextManager::apply_overlay(
    BinaryAddressRangeMap &map,
    const Address &start,
    const Address &end,
    const std::vector<std::uint8_t> &overlay) {
    const AddressRange target(start, end);
    std::vector<BinaryAddressRangeValue> covered;
    for (const auto &entry : map.entries()) {
        if (const auto intersection = entry.range.intersection(target)) {
            covered.push_back({*intersection, entry.value});
        }
    }
    std::ranges::sort(covered, range_before);
    Address cursor = start;
    const auto paint_combined = [&](const Address &segment_start,
                                    const Address &segment_end,
                                    std::vector<std::uint8_t> existing) {
        combine(existing, overlay);
        map.paint(segment_start, segment_end, std::move(existing));
    };
    for (const auto &entry : covered) {
        if (cursor < entry.range.min_address()) {
            paint_combined(cursor, *entry.range.min_address().previous(),
                           std::vector<std::uint8_t>(overlay.size(), 0));
        }
        paint_combined(entry.range.min_address(), entry.range.max_address(),
                       entry.value);
        if (entry.range.max_address() == end) return;
        cursor = *entry.range.max_address().next();
    }
    if (cursor <= end) {
        paint_combined(cursor, end,
                       std::vector<std::uint8_t>(overlay.size(), 0));
    }
}

std::optional<RegisterValue> RegisterContextManager::value_at(
    const std::string &register_name,
    const Address &address,
    bool include_default) const {
    const auto binding_value = binding(register_name);
    auto bytes = empty_base_value(binding_value);
    bool found = false;
    if (include_default) {
        if (const auto defaults = defaults_.find(binding_value.base_name);
            defaults != defaults_.end()) {
            for (const auto &entry : defaults->second) {
                if (entry.range.contains(address)) {
                    combine(bytes, entry.value);
                    found = true;
                    break;
                }
            }
        }
    }
    if (const auto stored = map_for(binding_value.base_name).value_at(address)) {
        combine(bytes, *stored);
        found = true;
    }
    auto result = decode_from_base(binding_value, bytes);
    return found && result.has_any_value()
        ? std::optional<RegisterValue>(std::move(result))
        : std::nullopt;
}

std::optional<AddressRange> RegisterContextManager::value_range_containing(
    const std::string &register_name,
    const Address &address) const {
    const auto binding_value = binding(register_name);
    return map_for(binding_value.base_name).range_containing(address);
}

std::vector<RegisterValueRange> RegisterContextManager::ranges(
    const std::string &register_name) const {
    const auto binding_value = binding(register_name);
    std::vector<RegisterValueRange> result;
    for (const auto &entry : map_for(binding_value.base_name).entries()) {
        auto value = decode_from_base(binding_value, entry.value);
        if (value.has_any_value()) {
            result.push_back({entry.range, std::move(value)});
        }
    }
    return result;
}

std::vector<RegisterValueRange> RegisterContextManager::default_ranges(
    const std::string &register_name) const {
    const auto binding_value = binding(register_name);
    std::vector<RegisterValueRange> result;
    const auto found = defaults_.find(binding_value.base_name);
    if (found == defaults_.end()) return result;
    result.reserve(found->second.size());
    for (const auto &entry : found->second) {
        auto value = decode_from_base(binding_value, entry.value);
        if (value.has_any_value()) {
            result.push_back({entry.range, std::move(value)});
        }
    }
    return result;
}

std::vector<std::string> RegisterContextManager::registers_with_values() const {
    std::vector<std::string> result;
    for (const auto &entry : maps_) {
        if (!entry.second->empty()) result.push_back(entry.first);
    }
    std::ranges::sort(result);
    return result;
}

void RegisterContextManager::set_value(const Address &start,
                                       const Address &end,
                                       RegisterValue value) {
    const auto binding_value = binding(value.register_name);
    validate_write(binding_value, start, end);
    const auto overlay = encode_for_base(binding_value, value);
    if (!has_mask(overlay)) {
        remove_value(start, end, value.register_name);
        return;
    }
    apply_overlay(map_for(binding_value.base_name), start, end, overlay);
}

void RegisterContextManager::remove_value(
    const Address &start,
    const Address &end,
    const std::string &register_name) {
    const auto binding_value = binding(register_name);
    validate_write(binding_value, start, end);
    auto &map = map_for(binding_value.base_name);
    if (!map.has_table()) return;
    std::vector<std::uint8_t> clear_mask(
        static_cast<std::size_t>(binding_value.base.size), 0);
    const auto requested_size =
        static_cast<std::size_t>(binding_value.requested.size);
    std::fill(clear_mask.begin() +
                  static_cast<std::ptrdiff_t>(binding_value.base_byte_offset),
              clear_mask.begin() + static_cast<std::ptrdiff_t>(
                  binding_value.base_byte_offset + requested_size),
              0xff);
    const AddressRange target(start, end);
    std::vector<BinaryAddressRangeValue> affected;
    for (const auto &entry : map.entries()) {
        if (const auto intersection = entry.range.intersection(target)) {
            affected.push_back({*intersection, entry.value});
        }
    }
    for (auto &entry : affected) {
        clear_bits(entry.value, clear_mask);
        if (has_mask(entry.value)) {
            map.paint(entry.range.min_address(), entry.range.max_address(),
                      std::move(entry.value));
        }
        else {
            map.clear(entry.range.min_address(), entry.range.max_address());
        }
    }
}

void RegisterContextManager::set_default_value(
    const Address &start,
    const Address &end,
    RegisterValue value) {
    const auto binding_value = binding(value.register_name);
    if (!start.same_space(end) || end < start) {
        throw std::invalid_argument("default register-context range is invalid");
    }
    auto overlay = encode_for_base(binding_value, value);
    auto &entries = defaults_[binding_value.base_name];
    const AddressRange target(start, end);
    std::vector<BinaryAddressRangeValue> result;
    std::vector<BinaryAddressRangeValue> covered;
    for (const auto &entry : entries) {
        if (!entry.range.intersects(target)) {
            result.push_back(entry);
            continue;
        }
        const auto intersection = entry.range.intersection(target);
        covered.push_back({*intersection, entry.value});
        if (entry.range.min_address() < start) {
            result.push_back({AddressRange(entry.range.min_address(),
                                           *start.previous()),
                              entry.value});
        }
        if (entry.range.max_address() > end) {
            result.push_back({AddressRange(*end.next(),
                                           entry.range.max_address()),
                              entry.value});
        }
    }
    if (has_mask(overlay)) {
        std::ranges::sort(covered, range_before);
        Address cursor = start;
        for (const auto &entry : covered) {
            if (cursor < entry.range.min_address()) {
                result.push_back({
                    AddressRange(cursor, *entry.range.min_address().previous()),
                    overlay});
            }
            auto combined = entry.value;
            combine(combined, overlay);
            result.push_back({entry.range, std::move(combined)});
            if (entry.range.max_address() == end) {
                cursor = Address::no_address();
                break;
            }
            cursor = *entry.range.max_address().next();
        }
        if (cursor.is_valid() && cursor <= end) {
            result.push_back({AddressRange(cursor, end), std::move(overlay)});
        }
    }
    std::ranges::sort(result, range_before);
    std::vector<BinaryAddressRangeValue> normalized;
    for (auto &entry : result) {
        if (!normalized.empty() &&
            normalized.back().value == entry.value &&
            normalized.back().range.max_address().same_space(
                entry.range.min_address()) &&
            normalized.back().range.space()->is_successor(
                normalized.back().range.max_address(),
                entry.range.min_address())) {
            normalized.back().range = AddressRange(
                normalized.back().range.min_address(),
                entry.range.max_address());
        }
        else {
            normalized.push_back(std::move(entry));
        }
    }
    entries = std::move(normalized);
}

void RegisterContextManager::initialize_default_values(
    const ProcessorSpec &processor_spec,
    const CompilerSpec &compiler_spec) {
    if (!architecture_ || !architecture_->processor_context_register) {
        if (!processor_spec.context_settings.empty() ||
            !compiler_spec.context_settings.empty()) {
            throw std::runtime_error(
                "context defaults require processor-context architecture metadata");
        }
        defaults_.clear();
        return;
    }
    const auto base = binding(*architecture_->processor_context_register);
    const auto width = static_cast<std::size_t>(base.base.size);
    auto apply = [&](const auto &settings) {
        for (const auto &setting : settings) {
            const auto &name = setting_attribute(setting, "name");
            const auto field = std::ranges::find_if(
                architecture_->processor_context_fields,
                [&](const auto &candidate) {
                    return folded(candidate.name) == folded(name);
                });
            if (field == architecture_->processor_context_fields.end()) {
                throw std::runtime_error(
                    "unknown SLEIGH processor-context field: " + name);
            }
            if (field->end_bit < field->start_bit ||
                field->end_bit >= width * 8 ||
                field->end_bit - field->start_bit + 1 > 64) {
                throw std::runtime_error(
                    "invalid SLEIGH processor-context field range");
            }
            const auto value = parse_setting_integer(
                setting_attribute(setting, "val"), "val");
            RegisterValue register_value;
            register_value.register_name = base.base_name;
            register_value.mask.assign(width, 0);
            register_value.value.assign(width, 0);
            const auto bit_length = field->end_bit - field->start_bit + 1;
            for (std::uint32_t value_bit = 0;
                 value_bit < bit_length; ++value_bit) {
                const auto context_bit = field->end_bit - value_bit;
                const auto byte = context_bit / 8;
                const auto mask = static_cast<std::uint8_t>(
                    1U << (7U - context_bit % 8U));
                register_value.mask[byte] |= mask;
                if ((value >> value_bit) & 1U) {
                    register_value.value[byte] |= mask;
                }
            }

            const auto &space_name = setting_attribute(setting, "space");
            const auto space = address_map_->factory()->space(space_name);
            if (!space) {
                throw std::runtime_error(
                    "context setting uses an unknown address space: " +
                    space_name);
            }
            Address start = space->min_address();
            Address end = space->max_address();
            if (const auto first = setting.find("first");
                first != setting.end()) {
                start = space->address(parse_setting_integer(
                    first->second, "first"));
            }
            if (const auto last = setting.find("last");
                last != setting.end()) {
                end = space->address(parse_setting_integer(
                    last->second, "last"));
            }
            set_default_value(start, end, std::move(register_value));
        }
    };

    defaults_.clear();
    apply(processor_spec.context_settings);
    apply(compiler_spec.context_settings);
}

void RegisterContextManager::reload_current_maps() {
    maps_.clear();
    for (const auto &table : database_->tables()) {
        if (!table->name().starts_with(table_prefix)) continue;
        const auto base_name = table->name().substr(
            std::char_traits<char>::length(table_prefix));
        if (base_name.empty()) {
            throw std::runtime_error(
                "Ghidra register-context table has an empty register name");
        }
        maps_.emplace(
            base_name,
            std::make_unique<BinaryAddressRangeMap>(
                database_, *address_map_, mode_, "Register_" + base_name));
    }
}

void RegisterContextManager::set_language(
    std::shared_ptr<const ProgramArchitecture> new_architecture,
    std::shared_ptr<AddressFactory> new_address_factory,
    const LanguageTranslator *translator,
    const ProcessorSpec &new_processor_spec,
    const CompilerSpec &new_compiler_spec,
    const AddressSet &program_memory) {
    if (!new_architecture || !new_address_factory) {
        throw std::invalid_argument(
            "register-context language change requires a new architecture and address factory");
    }
    database_->check_transaction();
    const auto reset_property = new_processor_spec.properties.find(
        "resetContextOnUpgrade");
    const bool reset_processor_context =
        reset_property != new_processor_spec.properties.end() &&
        folded(reset_property->second) == "true";

    if (translator == nullptr) {
        if (reset_processor_context && architecture_ &&
            architecture_->processor_context_register) {
            clear_register(*architecture_->processor_context_register);
        }
        // Same-language/minor-version changes reuse the existing Program
        // address factory.  Replacing it here would desynchronize the other
        // ProgramDB managers without an address translation pass.
        if (new_address_factory.get() != address_map_->factory().get()) {
            throw std::invalid_argument(
                "same-language context update must reuse the Program address factory");
        }
        architecture_ = std::move(new_architecture);
        initialize_default_values(new_processor_spec, new_compiler_spec);
        reload_current_maps();
        return;
    }
    if (&translator->old_architecture() != architecture_.get() ||
        &translator->new_architecture() != new_architecture.get() ||
        &translator->old_address_factory() != address_map_->factory().get() ||
        &translator->new_address_factory() != new_address_factory.get()) {
        throw std::invalid_argument(
            "language translator endpoints do not match Program context");
    }

    struct StagedRange {
        AddressRange range;
        RegisterValue value;
    };

    // Program memory is still expressed with the old Program address factory
    // at this point.  Translate it before ADDRESS MAP changes factories so a
    // context-gap value can only be painted into surviving target ranges.
    // A physical space deleted by the translator contributes no target
    // memory; a partial, cross-space, or reversed range is an invalid language
    // translation and must abort the enclosing Program transaction.
    AddressSet translated_program_memory;
    for (const auto &range : program_memory.ranges()) {
        const auto translated_start = translator->new_address(
            range.min_address());
        const auto translated_end = translator->new_address(
            range.max_address());
        if (!translated_start && !translated_end) continue;
        if (!translated_start || !translated_end ||
            !translated_start->same_space(*translated_end) ||
            *translated_end < *translated_start) {
            throw std::runtime_error(
                "language translator produced an invalid Program memory range");
        }
        translated_program_memory.add(
            *translated_start, *translated_end);
    }

    std::vector<std::string> source_registers = registers_with_values();
    std::ranges::sort(source_registers, [&](const auto &left,
                                            const auto &right) {
        const auto left_description = architecture_->register_named(left);
        const auto right_description = architecture_->register_named(right);
        const auto left_bits = left_description
            ? left_description->bit_length : 0U;
        const auto right_bits = right_description
            ? right_description->bit_length : 0U;
        if (left_bits != right_bits) return left_bits > right_bits;
        return left < right;
    });

    std::vector<StagedRange> staged;
    for (const auto &source_name : source_registers) {
        const auto source = architecture_->register_named(source_name);
        if (!source || source->base_register) {
            throw std::runtime_error(
                "persisted register-context table is not a known base register: " +
                source_name);
        }
        if (reset_processor_context && source->processor_context) continue;
        for (const auto &entry : ranges(source_name)) {
            const auto translated_start = translator->new_address(
                entry.range.min_address());
            const auto translated_end = translator->new_address(
                entry.range.max_address());
            if (!translated_start && !translated_end) continue;
            if (!translated_start || !translated_end ||
                !translated_start->same_space(*translated_end) ||
                *translated_end < *translated_start) {
                throw std::runtime_error(
                    "language translator produced an invalid register-context range");
            }
            auto translated = translator->new_register_value(entry.value);
            if (!translated || !translated->has_any_value()) continue;
            const auto target = new_architecture->register_named(
                translated->register_name);
            if (!target || target->base_register || target->size <= 0 ||
                translated->mask.size() !=
                    static_cast<std::size_t>(target->size) ||
                translated->value.size() != translated->mask.size()) {
                throw std::runtime_error(
                    "language translator produced an invalid base-register value");
            }
            staged.push_back(
                {AddressRange(*translated_start, *translated_end),
                 std::move(*translated)});
        }
    }

    std::vector<std::string> old_tables;
    for (const auto &table : database_->tables()) {
        if (table->name().starts_with(table_prefix)) {
            old_tables.push_back(table->name());
        }
    }
    for (const auto &name : old_tables) {
        if (!database_->delete_table(name)) {
            throw std::runtime_error(
                "failed to replace register context during language change");
        }
    }

    address_map_->set_language(new_address_factory, *translator);

    RegisterContextManager replacement(
        database_, *address_map_, mode_, new_architecture);
    for (auto &entry : staged) {
        replacement.set_value(
            entry.range.min_address(), entry.range.max_address(),
            std::move(entry.value));
    }
    replacement.initialize_default_values(
        new_processor_spec, new_compiler_spec);

    if (!reset_processor_context) {
        if (const auto gap_value = translator->context_gap_value();
            gap_value && gap_value->has_any_value() &&
            new_architecture->processor_context_register) {
            AddressSet gaps = translated_program_memory;
            for (const auto &entry : replacement.ranges(
                     *new_architecture->processor_context_register)) {
                gaps.erase(entry.range);
            }
            for (const auto &range : gaps.ranges()) {
                replacement.set_value(
                    range.min_address(), range.max_address(), *gap_value);
            }
        }
    }

    architecture_ = std::move(new_architecture);
    initialize_default_values(new_processor_spec, new_compiler_spec);
    reload_current_maps();
}

void RegisterContextManager::rebind_language(
    std::shared_ptr<const ProgramArchitecture> architecture,
    const ProcessorSpec &processor_spec,
    const CompilerSpec &compiler_spec) {
    if (!architecture) {
        throw std::invalid_argument(
            "register-context rebind requires an architecture");
    }
    architecture_ = std::move(architecture);
    reload_current_maps();
    initialize_default_values(processor_spec, compiler_spec);
}

void RegisterContextManager::clear_default_values(
    const std::string &register_name) {
    const auto binding_value = binding(register_name);
    defaults_.erase(binding_value.base_name);
}

void RegisterContextManager::delete_address_range(
    const Address &start,
    const Address &end) {
    for (auto &entry : maps_) entry.second->clear(start, end);
}

void RegisterContextManager::move_address_range(
    const Address &from,
    const Address &to,
    std::uint64_t length) {
    for (auto &entry : maps_) {
        entry.second->move_address_range(from, to, length);
    }
}

void RegisterContextManager::clear_register(
    const std::string &register_name) {
    const auto binding_value = binding(register_name);
    auto &map = map_for(binding_value.base_name);
    if (map.has_table()) map.dispose();
}

void RegisterContextManager::set_context_write_validator(
    std::function<void(const Address &, const Address &)> validator) {
    write_validator_ = std::move(validator);
}

void RegisterContextManager::invalidate_cache() {
    for (auto &entry : maps_) entry.second->invalidate_cache();
}

} // namespace llmghidra::program
