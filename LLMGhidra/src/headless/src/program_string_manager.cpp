#include "llmghidra/headless/program_string_manager.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/code_manager.hpp"
#include "llmghidra/program/data_type_manager.hpp"
#include "llmghidra/program/memory_manager.hpp"
#include "llmghidra/program/program.hpp"
#include "llmghidra/program/program_architecture.hpp"
#include "llmghidra/program/property_map_manager.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <ranges>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace llmghidra::headless {
namespace {

constexpr std::size_t maximum_program_string_bytes = 16 * 1024;

enum class StoredStringLayout {
    fixed,
    character_sequence,
    null_terminated_bounded,
    null_terminated_unbounded,
    pascal_255,
    pascal_64k,
};

struct StoredStringType {
    StoredStringLayout layout{StoredStringLayout::fixed};
    std::string charset{"US-ASCII"};
    ghidra::int4 character_size{1};
    ghidra::int4 padded_character_size{1};
    bool recognized{};
    bool character_type{};
    std::optional<bool> endian_override;
    bool show_translation{};
    std::optional<std::string> deprecated_translation;
};

} // namespace

// Keeps the public provider header independent of Program Model record
// definitions while carrying the resolved containing-data query.
class ProgramStringRecord {
public:
    program::Address requested_address;
    program::DefinedDataRecord data;
};

namespace {

[[nodiscard]] std::string ascii_lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] std::string simple_class_name(std::string value) {
    const auto separator = value.find_last_of("./$");
    if (separator != std::string::npos) value.erase(0, separator + 1);
    return value;
}

[[nodiscard]] bool contains(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
}

[[nodiscard]] std::string normalized_charset(std::string value) {
    value = ascii_lower(std::move(value));
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
                    return ch == '-' || ch == '_' || std::isspace(ch) != 0;
                }),
                value.end());
    return value;
}

void apply_settings(
    StoredStringType &type,
    const std::vector<program::DataTypeSetting> &settings) {
    for (const auto &setting : settings) {
        const auto name = ascii_lower(setting.name);
        if (name == "charset" && setting.string_value &&
            !setting.string_value->empty()) {
            type.charset = *setting.string_value;
        }
        else if (name == "endian") {
            if (setting.long_value == 1) type.endian_override = false;
            else if (setting.long_value == 2) type.endian_override = true;
        }
        else if (name == "translated") {
            type.show_translation = setting.long_value == 1;
        }
        else if (name == "translation" && setting.string_value) {
            type.deprecated_translation = setting.string_value;
        }
        else if (name == "terminated") {
            type.layout = setting.long_value == 1
                              ? StoredStringLayout::null_terminated_bounded
                              : StoredStringLayout::character_sequence;
        }
    }

    const auto charset = normalized_charset(type.charset);
    if (charset == "utf16" || charset == "utf16le" || charset == "utf16be") {
        type.character_size = 2;
        type.padded_character_size = std::max<ghidra::int4>(
            type.padded_character_size, type.character_size);
    }
    else if (charset == "utf32" || charset == "utf32le" ||
             charset == "utf32be") {
        type.character_size = 4;
        type.padded_character_size = std::max<ghidra::int4>(
            type.padded_character_size, type.character_size);
    }
}

[[nodiscard]] bool character_builtin(
    std::string_view class_name,
    ghidra::int4 &character_size) {
    if (class_name == "chardatatype" ||
        class_name == "signedchardatatype" ||
        class_name == "unsignedchardatatype") {
        character_size = 1;
        return true;
    }
    if (contains(class_name, "widechar16")) {
        character_size = 2;
        return true;
    }
    if (contains(class_name, "widechar32")) {
        character_size = 4;
        return true;
    }
    return class_name == "widechardatatype";
}

[[nodiscard]] StoredStringType resolve_string_type(
    const program::Program &program,
    std::int64_t id,
    unsigned depth = 0) {
    StoredStringType result;
    if (id <= 0 || depth > 64) return result;
    const auto encoded = program.data_types().data_type(id);
    if (!encoded) return result;

    if (const auto *alias = std::get_if<program::TypedefDataType>(&*encoded)) {
        result = resolve_string_type(program, alias->referenced_type_id, depth + 1);
        apply_settings(result, program.data_types().settings(false, id));
        return result;
    }
    if (const auto *array = std::get_if<program::ArrayDataType>(&*encoded)) {
        auto element = resolve_string_type(
            program, array->element_type_id, depth + 1);
        if (!element.character_type) return result;
        element.recognized = true;
        element.layout = StoredStringLayout::null_terminated_bounded;
        element.padded_character_size = std::max<ghidra::int4>(
            element.character_size, array->element_length);
        apply_settings(element, program.data_types().settings(false, id));
        return element;
    }

    const auto *builtin = std::get_if<program::BuiltinDataType>(&*encoded);
    if (builtin == nullptr) return result;
    const auto class_name = ascii_lower(simple_class_name(builtin->class_name));
    if (character_builtin(class_name, result.character_size)) {
        if (class_name == "widechardatatype") {
            const auto architecture = program.architecture();
            if (!architecture) return result;
            const auto metrics = program.data_types().data_type_metrics(
                id, architecture->data_organization);
            result.character_size = std::max<ghidra::int4>(1, metrics.length);
        }
        result.padded_character_size = result.character_size;
        result.character_type = true;
        if (result.character_size == 2) result.charset = "UTF-16";
        else if (result.character_size == 4) result.charset = "UTF-32";
        apply_settings(result, program.data_types().settings(false, id));
        return result;
    }

    if (class_name == "stringdatatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::fixed;
    }
    else if (class_name == "stringutf8datatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::fixed;
        result.charset = "UTF-8";
    }
    else if (class_name == "unicodedatatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::fixed;
        result.charset = "UTF-16";
        result.character_size = 2;
    }
    else if (class_name == "unicode32datatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::fixed;
        result.charset = "UTF-32";
        result.character_size = 4;
    }
    else if (class_name == "terminatedstringdatatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::null_terminated_unbounded;
    }
    else if (class_name == "terminatedunicodedatatype" ||
             class_name == "terminatedunicodestringdatatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::null_terminated_unbounded;
        result.charset = "UTF-16";
        result.character_size = 2;
    }
    else if (class_name == "terminatedunicode32datatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::null_terminated_unbounded;
        result.charset = "UTF-32";
        result.character_size = 4;
    }
    else if (class_name == "pascalstring255datatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::pascal_255;
    }
    else if (class_name == "pascalstringdatatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::pascal_64k;
    }
    else if (class_name == "pascalunicodedatatype") {
        result.recognized = true;
        result.layout = StoredStringLayout::pascal_64k;
        result.charset = "UTF-16";
        result.character_size = 2;
    }
    result.padded_character_size = result.character_size;
    apply_settings(result, program.data_types().settings(false, id));
    return result;
}

[[nodiscard]] program::Address to_program_address(
    const program::Program &program,
    const ghidra::Address &address) {
    if (address.isInvalid() || address.getSpace() == nullptr) return {};
    const auto space = program.address_factory()->space(
        address.getSpace()->getName());
    if (!space || address.getOffset() > space->max_offset()) return {};
    return space->address(static_cast<std::uint64_t>(address.getOffset()));
}

[[nodiscard]] bool has_terminator(
    std::span<const std::uint8_t> bytes,
    ghidra::int4 padded_size) {
    if (padded_size <= 0) return false;
    const auto width = static_cast<std::size_t>(padded_size);
    for (std::size_t offset = 0; offset + width <= bytes.size();
         offset += width) {
        if (std::ranges::all_of(
                bytes.subspan(offset, width),
                [](std::uint8_t value) { return value == 0; })) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::vector<std::uint8_t> remove_padding(
    std::span<const std::uint8_t> bytes,
    ghidra::int4 character_size,
    ghidra::int4 padded_size,
    bool big_endian) {
    std::vector<std::uint8_t> result;
    if (character_size <= 0 || padded_size < character_size) return result;
    const auto character_width = static_cast<std::size_t>(character_size);
    const auto field_width = static_cast<std::size_t>(padded_size);
    result.reserve((bytes.size() / field_width) * character_width);
    const auto inner_offset = big_endian ? field_width - character_width : 0;
    for (std::size_t offset = 0; offset + field_width <= bytes.size();
         offset += field_width) {
        result.insert(result.end(), bytes.begin() + offset + inner_offset,
                      bytes.begin() + offset + inner_offset + character_width);
    }
    return result;
}

[[nodiscard]] std::optional<std::uint32_t> windows_1252_codepoint(
    std::uint8_t value) {
    static constexpr std::uint16_t extension[32] = {
        0x20ac, 0,      0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021,
        0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0,      0x017d, 0,
        0,      0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
        0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0,      0x017e, 0x0178};
    if (value < 0x80 || value >= 0xa0) return value;
    const auto mapped = extension[value - 0x80];
    if (mapped == 0) return std::nullopt;
    return mapped;
}

} // namespace

ProgramStringManager::ProgramStringManager(
    program::Program &program,
    ghidra::int4 maximum_characters)
    : ghidra::StringManager(maximum_characters), program_(&program) {}

const std::vector<ghidra::uint1> &ProgramStringManager::getStringData(
    const ghidra::Address &address,
    ghidra::Datatype *character_type,
    bool &is_truncated) {
    if (const auto cached = stringMap.find(address); cached != stringMap.end()) {
        is_truncated = cached->second.isTruncated;
        return cached->second.byteData;
    }

    auto &result = stringMap[address];
    result.isTruncated = false;
    is_truncated = false;
    const auto requested = to_program_address(*program_, address);
    if (!requested.is_valid() || character_type == nullptr ||
        character_type->isOpaqueString()) {
        return result.byteData;
    }

    try {
        const auto unit = program_->code().containing(requested);
        if (unit && unit->data) {
            populate_defined_string(
                result, address, *character_type,
                ProgramStringRecord{requested, *unit->data});
        }
        else {
            populate_probed_string(result, address, *character_type);
        }
    }
    catch (const std::exception &) {
        result.byteData.clear();
        result.isTruncated = false;
    }
    is_truncated = result.isTruncated;
    return result.byteData;
}

void ProgramStringManager::populate_defined_string(
    StringData &destination,
    const ghidra::Address &decompiler_address,
    const ghidra::Datatype &,
    const ProgramStringRecord &record) {
    auto type = resolve_string_type(*program_, record.data.data_type_id);
    if (!type.recognized) return;

    const auto address_key = program_->address_map().key(
        record.data.address, false);
    if (address_key != program::PersistentAddressMap::invalid_key) {
        apply_settings(
            type, program_->data_types().settings(
                      true, std::bit_cast<std::int64_t>(address_key)));
    }
    if (type.padded_character_size <= 0) return;

    const auto displacement = record.requested_address.subtract(
        record.data.address);
    if (displacement < 0 ||
        static_cast<std::uint64_t>(displacement) >= record.data.length ||
        displacement % type.padded_character_size != 0) {
        return;
    }

    if (displacement == 0 && type.show_translation) {
        std::optional<std::string> translation;
        if (const auto property = program_->properties().get(
                "StringTranslations", record.data.address)) {
            if (const auto *text = std::get_if<std::string>(&*property)) {
                translation = *text;
            }
        }
        if (!translation) translation = type.deprecated_translation;
        if (translation) {
            auto bytes = std::vector<std::uint8_t>(
                translation->begin(), translation->end());
            bytes.push_back(0);
            const auto count = checkCharacters(
                bytes.data(), static_cast<ghidra::int4>(bytes.size()), 1,
                false);
            if (count >= 0) {
                assignStringData(
                    destination, bytes.data(),
                    static_cast<ghidra::int4>(bytes.size()), 1, count, false);
            }
            return;
        }
    }

    const auto remaining = record.data.length -
                           static_cast<std::uint64_t>(displacement);
    const auto source = record.data.address.add_no_wrap(displacement);
    std::size_t prefix_bytes = 0;
    std::uint64_t content_bytes = remaining;
    if (type.layout == StoredStringLayout::pascal_255 ||
        type.layout == StoredStringLayout::pascal_64k) {
        if (displacement != 0) {
            type.layout = StoredStringLayout::fixed;
        }
        else {
            prefix_bytes = type.layout == StoredStringLayout::pascal_255 ? 1 : 2;
            const auto prefix = program_->memory().read(source, prefix_bytes);
            std::uint64_t character_count = prefix.front();
            if (prefix_bytes == 2) {
                character_count = decompiler_address.isBigEndian()
                                      ? (static_cast<std::uint64_t>(prefix[0]) << 8) |
                                            prefix[1]
                                      : (static_cast<std::uint64_t>(prefix[1]) << 8) |
                                            prefix[0];
            }
            if (character_count >
                std::numeric_limits<std::uint64_t>::max() /
                    static_cast<std::uint64_t>(type.padded_character_size)) {
                return;
            }
            content_bytes = character_count *
                            static_cast<std::uint64_t>(
                                type.padded_character_size);
        }
    }

    const auto content_address = source.add_no_wrap(
        static_cast<std::int64_t>(prefix_bytes));
    std::vector<std::uint8_t> bytes;
    const bool unbounded =
        type.layout == StoredStringLayout::null_terminated_unbounded;
    if (unbounded) {
        const auto width = static_cast<std::size_t>(
            type.padded_character_size);
        while (bytes.size() < maximum_program_string_bytes) {
            if (width > maximum_program_string_bytes - bytes.size()) break;
            const auto cursor = content_address.add_no_wrap(
                static_cast<std::int64_t>(bytes.size()));
            const auto chunk = program_->memory().read(cursor, width);
            bytes.insert(bytes.end(), chunk.begin(), chunk.end());
            if (std::ranges::all_of(
                    chunk, [](std::uint8_t value) { return value == 0; })) {
                break;
            }
        }
    }
    else {
        const auto read_size = std::min<std::uint64_t>(
            content_bytes, maximum_program_string_bytes);
        if (read_size != 0) {
            bytes = program_->memory().read(
                content_address, static_cast<std::size_t>(read_size));
        }
    }

    if ((unbounded ||
         type.layout == StoredStringLayout::null_terminated_bounded) &&
        !has_terminator(bytes, type.padded_character_size)) {
        return;
    }

    const auto charset = normalized_charset(type.charset);
    bool big_endian = type.endian_override.value_or(
        decompiler_address.isBigEndian());
    if (charset.ends_with("le")) big_endian = false;
    else if (charset.ends_with("be")) big_endian = true;
    bytes = remove_padding(
        bytes, type.character_size, type.padded_character_size, big_endian);

    auto assign_utf = [&](ghidra::int4 character_size) {
        const auto element_size = static_cast<std::size_t>(character_size);
        bytes.resize(bytes.size() - (bytes.size() % element_size));
        if (!has_terminator(bytes, character_size)) {
            bytes.insert(bytes.end(), element_size, 0);
        }
        const auto logical_size = bytes.size();
        bytes.insert(bytes.end(), 4, 0);
        const auto count = checkCharacters(
            bytes.data(), static_cast<ghidra::int4>(logical_size),
            character_size, big_endian);
        if (count >= 0) {
            assignStringData(
                destination, bytes.data(),
                static_cast<ghidra::int4>(logical_size), character_size,
                count, big_endian);
        }
    };

    if (charset == "utf8") {
        if (bytes.size() >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb &&
            bytes[2] == 0xbf) {
            bytes.erase(bytes.begin(), bytes.begin() + 3);
        }
        assign_utf(1);
        return;
    }
    if (charset == "utf16" || charset == "utf16le" || charset == "utf16be") {
        if (bytes.size() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff) {
            big_endian = true;
            bytes.erase(bytes.begin(), bytes.begin() + 2);
        }
        else if (bytes.size() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe) {
            big_endian = false;
            bytes.erase(bytes.begin(), bytes.begin() + 2);
        }
        assign_utf(2);
        return;
    }
    if (charset == "utf32" || charset == "utf32le" || charset == "utf32be") {
        if (bytes.size() >= 4 && bytes[0] == 0 && bytes[1] == 0 &&
            bytes[2] == 0xfe && bytes[3] == 0xff) {
            big_endian = true;
            bytes.erase(bytes.begin(), bytes.begin() + 4);
        }
        else if (bytes.size() >= 4 && bytes[0] == 0xff && bytes[1] == 0xfe &&
                 bytes[2] == 0 && bytes[3] == 0) {
            big_endian = false;
            bytes.erase(bytes.begin(), bytes.begin() + 4);
        }
        assign_utf(4);
        return;
    }

    std::ostringstream utf8;
    ghidra::int4 count = 0;
    for (const auto value : bytes) {
        if (value == 0) break;
        std::optional<std::uint32_t> codepoint;
        if (charset == "usascii" || charset == "ascii") {
            if (value > 0x7f) return;
            codepoint = value;
        }
        else if (charset == "iso88591" || charset == "latin1") {
            codepoint = value;
        }
        else if (charset == "windows1252" || charset == "cp1252") {
            codepoint = windows_1252_codepoint(value);
            if (!codepoint) return;
        }
        else {
            return;
        }
        if (count < maximumChars) writeUtf8(utf8, *codepoint);
        ++count;
    }
    const auto encoded = utf8.str();
    destination.byteData.assign(encoded.begin(), encoded.end());
    destination.byteData.push_back(0);
    destination.isTruncated = count > maximumChars;
}

void ProgramStringManager::populate_probed_string(
    StringData &destination,
    const ghidra::Address &decompiler_address,
    const ghidra::Datatype &character_type) {
    const auto program_address = to_program_address(
        *program_, decompiler_address);
    const auto character_size = character_type.getSize();
    if (!program_address.is_valid() ||
        (character_size != 1 && character_size != 2 && character_size != 4)) {
        return;
    }

    std::vector<std::uint8_t> bytes;
    const auto limit = static_cast<std::size_t>(maximumChars);
    while (bytes.size() < limit) {
        const auto amount = static_cast<std::size_t>(character_size);
        if (amount > limit - bytes.size()) break;
        const auto cursor = program_address.add_no_wrap(
            static_cast<std::int64_t>(bytes.size()));
        const auto chunk = program_->memory().read(cursor, amount);
        bytes.insert(bytes.end(), chunk.begin(), chunk.end());
        if (std::ranges::all_of(
                chunk, [](std::uint8_t value) { return value == 0; })) {
            const auto logical_size = bytes.size();
            bytes.insert(bytes.end(), 4, 0);
            const auto count = checkCharacters(
                bytes.data(), static_cast<ghidra::int4>(logical_size),
                character_size, decompiler_address.isBigEndian());
            if (count >= 0) {
                assignStringData(
                    destination, bytes.data(),
                    static_cast<ghidra::int4>(logical_size), character_size,
                    count, decompiler_address.isBigEndian());
            }
            return;
        }
    }
}

} // namespace llmghidra::headless
