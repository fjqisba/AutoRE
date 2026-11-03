#include "llmghidra/program/language.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/program_architecture.hpp"

#include "xml.hh"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <tuple>

namespace llmghidra::program {
namespace {

[[nodiscard]] std::optional<std::string> attribute(const Element *element,
                                                   const std::string &name) {
    for (int4 index = 0; index < element->getNumAttributes(); ++index) {
        if (element->getAttributeName(index) == name) {
            return element->getAttributeValue(index);
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::string required_attribute(const Element *element,
                                             const std::string &name) {
    const auto value = attribute(element, name);
    if (!value) {
        throw std::runtime_error("missing XML attribute '" + name + "' on <" +
                                 element->getName() + ">");
    }
    return *value;
}

template <typename Integer>
[[nodiscard]] Integer integer_value(const std::string &text, int base = 10) {
    std::string value = text;
    if (base == 0) {
        base = 10;
        if (value.starts_with("0x") || value.starts_with("0X")) {
            value.erase(0, 2);
            base = 16;
        }
    }
    Integer result{};
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), result, base);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw std::runtime_error("invalid integer in processor specification: " + text);
    }
    return result;
}

template <typename Integer>
[[nodiscard]] Integer integer_attribute(const Element *element,
                                        const std::string &name,
                                        Integer fallback = {}) {
    const auto value = attribute(element, name);
    return value ? integer_value<Integer>(*value, 0) : fallback;
}

[[nodiscard]] bool boolean_value(const std::string &value) {
    return value == "true" || value == "yes" || value == "1";
}

[[nodiscard]] bool boolean_attribute(const Element *element,
                                     const std::string &name,
                                     bool fallback = false) {
    const auto value = attribute(element, name);
    return value ? boolean_value(*value) : fallback;
}

[[nodiscard]] Endian parse_endian(const std::string &value) {
    if (value == "little") {
        return Endian::little;
    }
    if (value == "big") {
        return Endian::big;
    }
    throw std::runtime_error("unsupported endian value: " + value);
}

[[nodiscard]] std::pair<std::int32_t, std::int32_t> parse_version(
    const std::string &value) {
    const std::size_t dot = value.find('.');
    if (dot == std::string::npos) {
        return {integer_value<std::int32_t>(value), 0};
    }
    return {integer_value<std::int32_t>(value.substr(0, dot)),
            integer_value<std::int32_t>(value.substr(dot + 1))};
}

[[nodiscard]] std::unique_ptr<DocumentStorage> read_xml(
    const std::filesystem::path &path,
    Document *&document);

[[nodiscard]] std::string trimmed(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

[[nodiscard]] std::uint64_t translation_context_value(
    std::string_view text) {
    bool negative = false;
    if (!text.empty() && text.front() == '-') {
        negative = true;
        text.remove_prefix(1);
    }
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    std::uint64_t magnitude{};
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), magnitude, base);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size()) {
        throw std::runtime_error("invalid language-translation context value");
    }
    return negative ? std::uint64_t{0} - magnitude : magnitude;
}

[[nodiscard]] LanguageTranslationDescription parse_translation(
    const std::filesystem::path &path) {
    Document *document = nullptr;
    auto storage = read_xml(path, document);
    const Element *root = document->getRoot();
    if (root->getName() != "language_translation") {
        throw std::runtime_error(
            "language translation root is not <language_translation>: " +
            path.string());
    }
    LanguageTranslationDescription result;
    result.source = path;
    std::set<std::string> mapped_target_spaces;
    for (const Element *element : root->getChildren()) {
        const auto &name = element->getName();
        if (name == "from_language" || name == "to_language") {
            auto &language_id = name == "from_language"
                ? result.from_language_id : result.to_language_id;
            auto &version = name == "from_language"
                ? result.from_version : result.to_version;
            if (!language_id.empty()) {
                throw std::runtime_error(
                    "duplicate <" + name + "> in " + path.string());
            }
            language_id = trimmed(element->getContent());
            version = integer_value<std::int32_t>(
                required_attribute(element, "version"), 0);
        }
        else if (name == "map_space") {
            const auto from = required_attribute(element, "from");
            const auto to = required_attribute(element, "to");
            if (result.address_spaces.contains(from) ||
                !mapped_target_spaces.insert(to).second) {
                throw std::runtime_error(
                    "duplicate address-space mapping in " + path.string());
            }
            result.address_spaces.emplace(from, to);
        }
        else if (name == "delete_space") {
            const auto deleted = required_attribute(element, "name");
            if (!result.address_spaces.emplace(deleted, std::nullopt).second) {
                throw std::runtime_error(
                    "duplicate deleted address space in " + path.string());
            }
        }
        else if (name == "map_register") {
            const auto from = required_attribute(element, "from");
            const auto to = required_attribute(element, "to");
            if (!result.registers.emplace(from, to).second) {
                throw std::runtime_error(
                    "duplicate register mapping in " + path.string());
            }
        }
        else if (name == "set_context") {
            const auto context_name = required_attribute(element, "name");
            result.context_values.insert_or_assign(
                context_name,
                translation_context_value(
                    required_attribute(element, "value")));
        }
        else if (name == "clear_all_context") {
            result.clear_all_context = true;
        }
        else if (name == "map_compiler_spec") {
            const auto from = required_attribute(element, "from");
            const auto to = required_attribute(element, "to");
            if (!result.compiler_specs.emplace(from, to).second) {
                throw std::runtime_error(
                    "duplicate compiler-spec mapping in " + path.string());
            }
        }
        else if (name == "post_upgrade_handler") {
            if (result.post_upgrade_handler) {
                throw std::runtime_error(
                    "duplicate post-upgrade handler in " + path.string());
            }
            result.post_upgrade_handler = required_attribute(element, "class");
        }
        else {
            throw std::runtime_error(
                "unsupported <" + name + "> in language translation " +
                path.string());
        }
    }
    if (result.from_language_id.empty() || result.to_language_id.empty() ||
        result.from_version < 0 || result.to_version < 0 ||
        (result.from_language_id == result.to_language_id &&
         result.from_version >= result.to_version)) {
        throw std::runtime_error(
            "invalid language-translation endpoints: " + path.string());
    }
    return result;
}

[[nodiscard]] AddressSpaceType legacy_space_type(const std::string &value) {
    if (value == "ram") return AddressSpaceType::ram;
    if (value == "code") return AddressSpaceType::code;
    if (value == "register") return AddressSpaceType::reg;
    throw std::runtime_error("unsupported historical language address-space type: " +
                             value);
}

[[nodiscard]] std::pair<std::uint32_t, std::uint32_t>
legacy_context_range(const std::string &text) {
    const auto comma = text.find(',');
    if (comma == std::string::npos ||
        text.find(',', comma + 1) != std::string::npos) {
        throw std::runtime_error(
            "invalid historical processor-context field range: " + text);
    }
    const auto first = integer_value<std::uint32_t>(text.substr(0, comma), 0);
    const auto last = integer_value<std::uint32_t>(text.substr(comma + 1), 0);
    if (last < first) {
        throw std::runtime_error(
            "reversed historical processor-context field range: " + text);
    }
    return {first, last};
}

void recover_legacy_register_construction(ProgramArchitecture &architecture) {
    for (auto &[name, description] : architecture.registers) {
        // The processor-context register is a distinct storage domain.  A
        // coincident or enclosing ordinary register must never turn it into a
        // child register, otherwise Program Context tables bind to the wrong
        // base during a language upgrade.
        if (description.processor_context) {
            if (description.bit_length == 0) {
                description.bit_length =
                    static_cast<std::uint32_t>(description.size) * 8U;
            }
            continue;
        }
        const std::pair<const std::string, RegisterDescription> *base = nullptr;
        for (const auto &candidate : architecture.registers) {
            if (candidate.first == name ||
                candidate.second.size <= description.size ||
                !candidate.second.address.same_space(description.address) ||
                candidate.second.address > description.address) {
                continue;
            }
            const auto byte_delta = description.address.offset() -
                                    candidate.second.address.offset();
            if (byte_delta > static_cast<std::uint64_t>(
                    candidate.second.size - description.size)) {
                continue;
            }
            if (base == nullptr || candidate.second.size > base->second.size ||
                (candidate.second.size == base->second.size &&
                 candidate.first < base->first)) {
                base = &candidate;
            }
        }
        if (description.bit_length == 0) {
            description.bit_length =
                static_cast<std::uint32_t>(description.size) * 8U;
        }
        if (base == nullptr) continue;
        description.base_register = base->first;
        const auto byte_delta = description.address.offset() -
                                base->second.address.offset();
        description.least_significant_bit = architecture.endian == Endian::little
            ? static_cast<std::uint32_t>(byte_delta * 8U)
            : static_cast<std::uint32_t>(
                  (base->second.size - description.size - byte_delta) * 8U);
    }
}

[[nodiscard]] LegacyLanguageDescription parse_legacy_language(
    const std::filesystem::path &path) {
    Document *document = nullptr;
    auto storage = read_xml(path, document);
    const Element *root = document->getRoot();
    if (root->getName() != "language") {
        throw std::runtime_error(
            "historical language root is not <language>: " + path.string());
    }

    LegacyLanguageDescription result;
    result.source = path;
    result.version = integer_value<std::int32_t>(
        required_attribute(root, "version"), 0);
    result.endian = parse_endian(required_attribute(root, "endian"));
    if (result.version < 0) {
        throw std::runtime_error(
            "historical language version must not be negative: " +
            path.string());
    }

    const Element *description = nullptr;
    const Element *spaces_element = nullptr;
    const Element *registers_element = nullptr;
    for (const Element *element : root->getChildren()) {
        if (element->getName() == "description") description = element;
        else if (element->getName() == "spaces") spaces_element = element;
        else if (element->getName() == "registers") registers_element = element;
        else if (element->getName() == "compiler") {
            const auto id = required_attribute(element, "id");
            result.compiler_specs.push_back(
                {id, required_attribute(element, "name"), {}});
        }
    }
    if (!description || !spaces_element || !registers_element) {
        throw std::runtime_error(
            "historical language is missing description, spaces, or registers: " +
            path.string());
    }
    for (const Element *element : description->getChildren()) {
        const auto value = trimmed(element->getContent());
        if (element->getName() == "id") result.id = value;
        else if (element->getName() == "processor") result.processor = value;
        else if (element->getName() == "variant") result.variant = value;
    }
    if (result.id.empty()) {
        throw std::runtime_error(
            "historical language has no canonical id: " + path.string());
    }
    result.aliases.push_back(result.id);

    std::vector<std::shared_ptr<AddressSpace>> spaces;
    std::shared_ptr<AddressSpace> default_space;
    std::uint32_t next_unique{};
    for (const Element *element : spaces_element->getChildren()) {
        const auto name = required_attribute(element, "name");
        const auto unique = attribute(element, "unique")
            ? integer_attribute<std::uint32_t>(element, "unique")
            : next_unique;
        std::shared_ptr<AddressSpace> address_space;
        if (element->getName() == "segmented_space") {
            const auto type = required_attribute(element, "type");
            if (type == "real") {
                address_space = AddressSpace::create_segmented(name, unique);
            }
            else if (type == "protected") {
                address_space =
                    AddressSpace::create_protected_segmented(name, unique);
            }
            else {
                throw std::runtime_error(
                    "unsupported historical segmented-space type: " + type);
            }
        }
        else if (element->getName() == "space") {
            const auto byte_size = integer_attribute<std::uint32_t>(
                element, "size");
            const auto word_size = integer_attribute<std::uint32_t>(
                element, "wordsize", 1);
            if (byte_size == 0 || byte_size > 8) {
                throw std::runtime_error(
                    "historical address-space size is outside 1..8 bytes");
            }
            address_space = AddressSpace::create(
                {name, byte_size * 8U, word_size,
                 legacy_space_type(required_attribute(element, "type")),
                 unique});
        }
        else {
            throw std::runtime_error(
                "unsupported element in historical <spaces>: " +
                element->getName());
        }
        if (boolean_attribute(element, "default")) {
            if (default_space) {
                throw std::runtime_error(
                    "historical language has multiple default spaces");
            }
            default_space = address_space;
        }
        spaces.push_back(std::move(address_space));
        if (unique == std::numeric_limits<std::uint32_t>::max()) {
            throw std::overflow_error(
                "historical language address-space unique id is exhausted");
        }
        next_unique = unique + 1U;
    }
    if (!default_space) {
        throw std::runtime_error(
            "historical language has no default address space: " +
            path.string());
    }
    result.address_factory =
        std::make_shared<AddressFactory>(std::move(spaces), default_space);

    auto architecture = std::make_shared<ProgramArchitecture>();
    architecture->endian = result.endian;
    std::set<std::string> register_names;
    for (const Element *element : registers_element->getChildren()) {
        if (element->getName() != "register" &&
            element->getName() != "context_register") {
            throw std::runtime_error(
                "unsupported element in historical <registers>: " +
                element->getName());
        }
        const auto name = required_attribute(element, "name");
        std::string folded_name = name;
        std::ranges::transform(
            folded_name, folded_name.begin(), [](unsigned char value) {
                return static_cast<char>(std::tolower(value));
            });
        if (!register_names.insert(folded_name).second) {
            throw std::runtime_error(
                "duplicate historical register name: " + name);
        }
        const auto bit_length = integer_attribute<std::uint32_t>(
            element, "bitsize");
        if (bit_length == 0) {
            throw std::runtime_error(
                "historical register bit size is invalid: " + name);
        }
        Address address;
        if (const auto encoded = attribute(element, "address")) {
            const auto parsed = result.address_factory->parse_address(*encoded);
            if (!parsed) {
                throw std::runtime_error(
                    "historical register has an invalid address: " + name);
            }
            address = *parsed;
        }
        else {
            const auto register_space = result.address_factory->register_space();
            if (!register_space) {
                throw std::runtime_error(
                    "historical register requires a register address space");
            }
            address = register_space->address_in_this_space(
                integer_attribute<std::uint64_t>(element, "offset"));
        }
        const auto byte_size = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(bit_length) + 7U) / 8U);
        architecture->registers.emplace(
            name, RegisterDescription{
                      address, static_cast<std::int32_t>(byte_size), 0,
                      bit_length, std::nullopt,
                      element->getName() == "context_register"});
        if (element->getName() == "context_register") {
            if (architecture->processor_context_register) {
                throw std::runtime_error(
                    "historical language has multiple context registers");
            }
            architecture->processor_context_register = name;
            std::set<std::string> context_field_names;
            for (const Element *field : element->getChildren()) {
                if (field->getName() != "field") {
                    throw std::runtime_error(
                        "unsupported historical context-register child");
                }
                const auto [first, last] = legacy_context_range(
                    required_attribute(field, "range"));
                if (last >= byte_size * 8U) {
                    throw std::runtime_error(
                        "historical context field exceeds its base register");
                }
                const auto field_name = required_attribute(field, "name");
                std::string folded_field_name = field_name;
                std::ranges::transform(
                    folded_field_name, folded_field_name.begin(),
                    [](unsigned char value) {
                        return static_cast<char>(std::tolower(value));
                    });
                if (!context_field_names.insert(folded_field_name).second) {
                    throw std::runtime_error(
                        "duplicate historical processor-context field: " +
                        field_name);
                }
                architecture->processor_context_fields.push_back(
                    {field_name, first, last});
            }
        }
    }
    recover_legacy_register_construction(*architecture);
    result.architecture = std::move(architecture);
    return result;
}

[[nodiscard]] const Element *first_child(const Element *parent,
                                         const std::string &name) noexcept {
    for (const Element *child : parent->getChildren()) {
        if (child->getName() == name) {
            return child;
        }
    }
    return nullptr;
}

[[nodiscard]] std::filesystem::path canonical_spec_path(
    const std::filesystem::path &base,
    const std::string &relative) {
    return (base / std::filesystem::path(relative)).lexically_normal();
}

[[nodiscard]] std::unique_ptr<DocumentStorage> read_xml(
    const std::filesystem::path &path,
    Document *&document) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("unable to open processor specification: " + path.string());
    }
    auto storage = std::make_unique<DocumentStorage>();
    document = storage->parseDocument(input);
    if (!document || !document->getRoot()) {
        throw std::runtime_error("empty processor specification: " + path.string());
    }
    return storage;
}

[[nodiscard]] StorageLocation parse_storage(const Element *element) {
    StorageLocation result;
    if (element->getName() == "register") {
        result.kind = StorageLocation::Kind::register_name;
        result.name = required_attribute(element, "name");
    }
    else if (element->getName() == "addr" || element->getName() == "varnode") {
        result.kind = StorageLocation::Kind::address;
        result.space = required_attribute(element, "space");
        result.offset = integer_attribute<std::uint64_t>(element, "offset");
        result.size = integer_attribute<std::uint32_t>(element, "size");
    }
    else if (element->getName() == "join") {
        result.kind = StorageLocation::Kind::join;
        for (const Element *child : element->getChildren()) {
            result.pieces.push_back(parse_storage(child));
        }
    }
    else {
        throw std::runtime_error("unsupported storage element <" + element->getName() + ">");
    }
    return result;
}

void collect_rule_names(const Element *element, std::vector<std::string> &result) {
    if (element->getName() != "rule") {
        result.push_back(element->getName());
    }
    for (const Element *child : element->getChildren()) {
        collect_rule_names(child, result);
    }
}

[[nodiscard]] ParameterEntry parse_parameter_entry(const Element *element) {
    ParameterEntry result;
    result.minimum_size = integer_attribute<std::uint32_t>(element, "minsize");
    result.maximum_size = integer_attribute<std::uint32_t>(element, "maxsize");
    result.alignment = integer_attribute<std::uint32_t>(element, "align");
    result.metatype = attribute(element, "metatype").value_or(std::string{});
    result.extension = attribute(element, "extension").has_value();
    for (const Element *child : element->getChildren()) {
        if (child->getName() == "register" || child->getName() == "addr" ||
            child->getName() == "varnode" || child->getName() == "join") {
            result.storage = parse_storage(child);
        }
        else {
            collect_rule_names(child, result.allocation_rules);
        }
    }
    return result;
}

void collect_parameter_entries(const Element *element,
                               std::vector<ParameterEntry> &entries,
                               std::vector<std::string> &rules) {
    for (const Element *child : element->getChildren()) {
        if (child->getName() == "pentry") {
            entries.push_back(parse_parameter_entry(child));
        }
        else if (child->getName() == "group") {
            collect_parameter_entries(child, entries, rules);
        }
        else if (child->getName() == "rule") {
            collect_rule_names(child, rules);
        }
    }
}

void collect_register_names(const Element *element, std::vector<std::string> &result) {
    for (const Element *child : element->getChildren()) {
        if (child->getName() == "register") {
            result.push_back(required_attribute(child, "name"));
        }
    }
}

[[nodiscard]] PrototypeModel parse_prototype(const Element *element) {
    PrototypeModel result;
    result.name = required_attribute(element, "name");
    const auto extrapop = attribute(element, "extrapop");
    result.extrapop = extrapop && *extrapop != "unknown"
                          ? integer_value<std::int64_t>(*extrapop, 0)
                          : std::numeric_limits<std::int64_t>::min();
    result.stack_shift = integer_attribute<std::int64_t>(element, "stackshift");
    result.has_this = boolean_attribute(element, "hasthis");
    result.constructor = boolean_attribute(element, "constructor");
    for (const Element *child : element->getChildren()) {
        if (child->getName() == "input") {
            collect_parameter_entries(child, result.inputs, result.input_rules);
        }
        else if (child->getName() == "output") {
            collect_parameter_entries(child, result.outputs, result.output_rules);
        }
        else if (child->getName() == "unaffected") {
            collect_register_names(child, result.unaffected_registers);
        }
        else if (child->getName() == "killedbycall") {
            collect_register_names(child, result.killed_by_call_registers);
        }
        else if (child->getName() == "likelytrash") {
            collect_register_names(child, result.likely_trash_registers);
        }
    }
    return result;
}

[[nodiscard]] DataOrganization parse_data_organization(const Element *element) {
    DataOrganization result;
    for (const Element *child : element->getChildren()) {
        const std::string &name = child->getName();
        const std::uint32_t value = integer_attribute<std::uint32_t>(child, "value");
        if (name == "absolute_max_alignment") result.absolute_max_alignment = value;
        else if (name == "machine_alignment") result.machine_alignment = value;
        else if (name == "default_alignment") result.default_alignment = value;
        else if (name == "default_pointer_alignment") result.default_pointer_alignment = value;
        else if (name == "pointer_size") result.pointer_size = value;
        else if (name == "pointer_shift") result.pointer_shift = value;
        else if (name == "char_size") result.char_size = value;
        else if (name == "wchar_size") result.wchar_size = value;
        else if (name == "short_size") result.short_size = value;
        else if (name == "integer_size") result.integer_size = value;
        else if (name == "long_size") result.long_size = value;
        else if (name == "long_long_size") result.long_long_size = value;
        else if (name == "float_size") result.float_size = value;
        else if (name == "double_size") result.double_size = value;
        else if (name == "long_double_size") result.long_double_size = value;
        else if (name == "char_type") {
            result.char_signed = attribute(child, "signed").value_or("true") != "false";
        }
        else if (name == "bitfield_packing") {
            // BitFieldPackingImpl.restoreXml() reads child elements.  Several
            // Windows compiler specs rely on this exact nesting to select the
            // MSVC allocation convention.
            for (const Element *option : child->getChildren()) {
                const std::string &option_name = option->getName();
                if (option_name == "use_MS_convention") {
                    result.bitfield_use_ms_convention =
                        boolean_attribute(option, "value");
                }
                else if (option_name == "type_alignment_enabled") {
                    result.bitfield_type_alignment_enabled =
                        boolean_attribute(option, "value", true);
                }
                else if (option_name == "zero_length_boundary") {
                    result.bitfield_zero_length_boundary =
                        integer_attribute<std::uint32_t>(option, "value");
                }
            }
        }
        else if (name == "size_alignment_map") {
            for (const Element *entry : child->getChildren()) {
                if (entry->getName() == "entry") {
                    result.size_alignment.insert_or_assign(
                        integer_attribute<std::uint32_t>(entry, "size"),
                        integer_attribute<std::uint32_t>(entry, "alignment"));
                }
            }
        }
    }
    return result;
}

void collect_context_settings(
    const Element *element,
    std::unordered_map<std::string, std::string> inherited,
    std::vector<std::unordered_map<std::string, std::string>> &context,
    std::vector<std::unordered_map<std::string, std::string>> &tracked) {
    for (int4 index = 0; index < element->getNumAttributes(); ++index) {
        inherited[element->getAttributeName(index)] = element->getAttributeValue(index);
    }
    for (const Element *child : element->getChildren()) {
        if (child->getName() == "set") {
            auto item = inherited;
            for (int4 index = 0; index < child->getNumAttributes(); ++index) {
                item[child->getAttributeName(index)] = child->getAttributeValue(index);
            }
            if (element->getName() == "tracked_set") tracked.push_back(std::move(item));
            else context.push_back(std::move(item));
        }
        else {
            collect_context_settings(child, inherited, context, tracked);
        }
    }
}

} // namespace

std::uint32_t DataOrganization::alignment_for_size(std::uint32_t size) const noexcept {
    auto found = size_alignment.upper_bound(size);
    std::uint32_t alignment = default_alignment;
    if (found != size_alignment.begin()) alignment = std::prev(found)->second;
    if (absolute_max_alignment != 0) {
        alignment = std::min(alignment, absolute_max_alignment);
    }
    return alignment;
}

bool DataOrganization::effective_bitfield_type_alignment() const noexcept {
    // MS convention takes precedence over the PCC/GCC switch.
    return bitfield_use_ms_convention || bitfield_type_alignment_enabled;
}

std::uint32_t DataOrganization::effective_zero_length_bitfield_boundary() const noexcept {
    // MS convention always derives zero-width alignment from the base type.
    return bitfield_use_ms_convention ? 0 : bitfield_zero_length_boundary;
}

LanguageRegistry::LanguageRegistry(std::filesystem::path processor_pack_root)
    : root_(std::move(processor_pack_root)) {}

void LanguageRegistry::discover() {
    languages_.clear();
    translations_.clear();
    legacy_languages_.clear();
    by_id_.clear();
    if (!std::filesystem::is_directory(root_)) {
        throw std::runtime_error("processor pack directory does not exist: " + root_.string());
    }

    std::vector<std::filesystem::path> definition_files;
    std::vector<std::filesystem::path> translation_files;
    std::vector<std::filesystem::path> legacy_language_files;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(root_)) {
        if (entry.is_regular_file() && entry.path().extension() == ".ldefs") {
            definition_files.push_back(entry.path());
        }
        else if (entry.is_regular_file() &&
                 entry.path().extension() == ".trans") {
            translation_files.push_back(entry.path());
        }
        else if (entry.is_regular_file() &&
                 entry.path().extension() == ".lang") {
            legacy_language_files.push_back(entry.path());
        }
    }
    std::ranges::sort(definition_files);
    for (const auto &path : definition_files) {
        Document *document = nullptr;
        auto storage = read_xml(path, document);
        const Element *root = document->getRoot();
        if (root->getName() != "language_definitions") {
            continue;
        }
        for (const Element *element : root->getChildren()) {
            if (element->getName() != "language") {
                continue;
            }
            LanguageDescription description;
            description.id = required_attribute(element, "id");
            description.processor = required_attribute(element, "processor");
            description.endian = parse_endian(required_attribute(element, "endian"));
            description.instruction_endian = parse_endian(
                attribute(element, "instructionEndian").value_or(
                    required_attribute(element, "endian")));
            description.size = integer_attribute<std::uint32_t>(element, "size");
            description.variant = required_attribute(element, "variant");
            const auto [version, minor] = parse_version(required_attribute(element, "version"));
            description.version = version;
            description.minor_version = minor;
            description.deprecated = boolean_attribute(element, "deprecated");
            description.sleigh_file = canonical_spec_path(
                path.parent_path(), required_attribute(element, "slafile"));
            description.processor_specification = canonical_spec_path(
                path.parent_path(), required_attribute(element, "processorspec"));
            for (const Element *child : element->getChildren()) {
                if (child->getName() == "description") {
                    description.description = child->getContent();
                }
                else if (child->getName() == "compiler") {
                    description.compiler_specs.push_back(
                        {required_attribute(child, "id"), required_attribute(child, "name"),
                         canonical_spec_path(path.parent_path(),
                                             required_attribute(child, "spec"))});
                }
                else if (child->getName() == "truncate_space") {
                    AddressSpaceTruncation truncation{
                        required_attribute(child, "space"),
                        integer_attribute<std::uint32_t>(child, "size")};
                    if (truncation.space.empty() || truncation.size == 0) {
                        throw std::runtime_error(
                            "invalid <truncate_space> in " + path.string());
                    }
                    const auto duplicate = std::ranges::find_if(
                        description.address_space_truncations,
                        [&](const auto &existing) {
                            return existing.space == truncation.space;
                        });
                    if (duplicate != description.address_space_truncations.end()) {
                        throw std::runtime_error(
                            "duplicate <truncate_space> for address space " +
                            truncation.space + " in " + path.string());
                    }
                    description.address_space_truncations.push_back(
                        std::move(truncation));
                }
                else if (child->getName() == "external_name") {
                    description.external_names[required_attribute(child, "tool")].push_back(
                        required_attribute(child, "name"));
                }
            }
            if (by_id_.contains(description.id)) {
                throw std::runtime_error("duplicate language id: " + description.id);
            }
            by_id_.emplace(description.id, languages_.size());
            languages_.push_back(std::move(description));
        }
    }
    std::ranges::sort(languages_, {}, &LanguageDescription::id);
    by_id_.clear();
    for (std::size_t index = 0; index < languages_.size(); ++index) {
        by_id_.emplace(languages_[index].id, index);
    }
    std::ranges::sort(translation_files);
    translations_.reserve(translation_files.size());
    for (const auto &path : translation_files) {
        translations_.push_back(parse_translation(path));
    }
    std::ranges::sort(translations_, [](const auto &left, const auto &right) {
        return std::tie(left.from_language_id, left.from_version,
                        left.to_language_id, left.to_version, left.source) <
               std::tie(right.from_language_id, right.from_version,
                        right.to_language_id, right.to_version, right.source);
    });

    std::ranges::sort(legacy_language_files);
    legacy_languages_.reserve(legacy_language_files.size());
    for (const auto &path : legacy_language_files) {
        legacy_languages_.push_back(parse_legacy_language(path));
    }
    for (auto &legacy : legacy_languages_) {
        for (const auto &translation : translations_) {
            if (translation.source.stem() == legacy.source.stem() &&
                translation.from_version == legacy.version &&
                std::ranges::find(legacy.aliases,
                                  translation.from_language_id) ==
                    legacy.aliases.end()) {
                legacy.aliases.push_back(translation.from_language_id);
            }
        }
        std::ranges::sort(legacy.aliases);
    }
    std::ranges::sort(legacy_languages_, [](const auto &left,
                                            const auto &right) {
        return std::tie(left.id, left.version, left.source) <
               std::tie(right.id, right.version, right.source);
    });
    for (std::size_t index = 1; index < legacy_languages_.size(); ++index) {
        const auto &previous = legacy_languages_[index - 1];
        const auto &current = legacy_languages_[index];
        if (previous.id == current.id && previous.version == current.version) {
            throw std::runtime_error(
                "duplicate historical language id/version: " + current.id +
                " version " + std::to_string(current.version));
        }
    }
}

const std::filesystem::path &LanguageRegistry::root() const noexcept { return root_; }
const std::vector<LanguageDescription> &LanguageRegistry::languages() const noexcept {
    return languages_;
}

const std::vector<LanguageTranslationDescription> &
LanguageRegistry::translations() const noexcept {
    return translations_;
}

const std::vector<LegacyLanguageDescription> &
LanguageRegistry::legacy_languages() const noexcept {
    return legacy_languages_;
}

const LegacyLanguageDescription &LanguageRegistry::legacy_language(
    const std::string &id,
    std::int32_t version) const {
    const LegacyLanguageDescription *match = nullptr;
    for (const auto &candidate : legacy_languages_) {
        if (candidate.version != version ||
            std::ranges::find(candidate.aliases, id) ==
                candidate.aliases.end()) {
            continue;
        }
        if (match != nullptr && match != &candidate) {
            throw std::runtime_error(
                "ambiguous historical language alias/version: " + id +
                " version " + std::to_string(version));
        }
        match = &candidate;
    }
    if (!match) {
        throw std::out_of_range(
            "unknown historical language id/version: " + id + " version " +
            std::to_string(version));
    }
    return *match;
}

const LanguageDescription &LanguageRegistry::language(const std::string &id) const {
    const auto found = by_id_.find(id);
    if (found == by_id_.end()) {
        throw std::out_of_range("unknown language id: " + id);
    }
    return languages_[found->second];
}

std::vector<const LanguageDescription *> LanguageRegistry::query(
    std::optional<std::string> processor,
    std::optional<Endian> endian,
    std::optional<std::uint32_t> size) const {
    std::vector<const LanguageDescription *> result;
    for (const auto &candidate : languages_) {
        if (processor && candidate.processor != *processor) continue;
        if (endian && candidate.endian != *endian) continue;
        if (size && candidate.size != *size) continue;
        result.push_back(&candidate);
    }
    return result;
}

CompilerSpec LanguageRegistry::load_compiler_spec(
    const std::string &language_id,
    const std::string &compiler_spec_id) const {
    const auto &language_description = language(language_id);
    const auto found = std::ranges::find(language_description.compiler_specs,
                                         compiler_spec_id,
                                         &CompilerSpecDescription::id);
    if (found == language_description.compiler_specs.end()) {
        throw std::out_of_range("unknown compiler spec '" + compiler_spec_id +
                                "' for language " + language_id);
    }

    Document *document = nullptr;
    auto storage = read_xml(found->specification, document);
    const Element *root = document->getRoot();
    if (root->getName() != "compiler_spec") {
        throw std::runtime_error("compiler spec root is not <compiler_spec>");
    }
    CompilerSpec result;
    result.description = *found;
    for (const Element *element : root->getChildren()) {
        if (element->getName() == "data_organization") {
            result.data_organization = parse_data_organization(element);
        }
        else if (element->getName() == "stackpointer") {
            result.stack_pointer_register = required_attribute(element, "register");
            result.stack_space = required_attribute(element, "space");
            result.stack_grows_negative =
                attribute(element, "growth").value_or("negative") != "positive";
        }
        else if (element->getName() == "returnaddress") {
            for (const Element *child : element->getChildren()) {
                result.return_address.push_back(parse_storage(child));
            }
        }
        else if (element->getName() == "default_proto") {
            if (const Element *prototype = first_child(element, "prototype")) {
                auto model = parse_prototype(prototype);
                result.default_prototype = model.name;
                result.prototypes.push_back(std::move(model));
            }
        }
        else if (element->getName() == "prototype") {
            result.prototypes.push_back(parse_prototype(element));
        }
        else if (element->getName() == "eval_current_prototype") {
            result.evaluation_current_prototype = required_attribute(element, "name");
        }
        else if (element->getName() == "eval_called_prototype") {
            result.evaluation_called_prototype = required_attribute(element, "name");
        }
        else if (element->getName() == "context_data") {
            collect_context_settings(element, {}, result.context_settings,
                                     result.tracked_settings);
        }
        else if (element->getName() == "properties") {
            for (const Element *property : element->getChildren()) {
                if (property->getName() == "property") {
                    result.properties[required_attribute(property, "key")] =
                        required_attribute(property, "value");
                }
            }
        }
    }
    return result;
}

ProcessorSpec LanguageRegistry::load_processor_spec(const std::string &language_id) const {
    const auto &description = language(language_id);
    Document *document = nullptr;
    auto storage = read_xml(description.processor_specification, document);
    const Element *root = document->getRoot();
    if (root->getName() != "processor_spec") {
        throw std::runtime_error("processor spec root is not <processor_spec>");
    }
    ProcessorSpec result;
    for (const Element *element : root->getChildren()) {
        if (element->getName() == "programcounter") {
            result.program_counter_register = required_attribute(element, "register");
        }
        else if (element->getName() == "segmented_address") {
            if (result.segmented_address_space) {
                throw std::runtime_error(
                    "processor spec contains multiple <segmented_address> elements");
            }
            result.segmented_address_space =
                required_attribute(element, "space");
            result.segmented_address_type =
                attribute(element, "type").value_or(std::string{});
        }
        else if (element->getName() == "properties") {
            for (const Element *property : element->getChildren()) {
                if (property->getName() == "property") {
                    result.properties[required_attribute(property, "key")] =
                        required_attribute(property, "value");
                }
            }
        }
        else if (element->getName() == "register_data") {
            for (const Element *reg : element->getChildren()) {
                if (reg->getName() != "register") continue;
                const std::string name = required_attribute(reg, "name");
                if (const auto group = attribute(reg, "group")) {
                    result.register_groups[name] = *group;
                }
                if (const auto lanes = attribute(reg, "vector_lane_sizes")) {
                    std::stringstream input(*lanes);
                    std::string item;
                    while (std::getline(input, item, ',')) {
                        result.register_lane_sizes[name].push_back(
                            integer_value<std::uint32_t>(item));
                    }
                }
            }
        }
        else if (element->getName() == "context_data") {
            collect_context_settings(element, {}, result.context_settings,
                                     result.tracked_settings);
        }
    }
    return result;
}

std::vector<const LanguageTranslationDescription *>
LanguageRegistry::translations_from(
    const std::string &language_id,
    std::int32_t version) const {
    std::vector<const LanguageTranslationDescription *> result;
    for (const auto &translation : translations_) {
        if (translation.from_language_id == language_id &&
            translation.from_version == version) {
            result.push_back(&translation);
        }
    }
    return result;
}

} // namespace llmghidra::program
