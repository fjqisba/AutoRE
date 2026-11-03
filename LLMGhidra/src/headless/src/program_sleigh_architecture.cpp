#include "llmghidra/headless/program_sleigh_architecture.hpp"

#include "llmghidra/headless/program_load_image.hpp"
#include "llmghidra/headless/program_constant_pool.hpp"
#include "llmghidra/headless/program_string_manager.hpp"
#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/comment_manager.hpp"
#include "llmghidra/program/data_type_manager.hpp"
#include "llmghidra/program/external_manager.hpp"
#include "llmghidra/program/function_manager.hpp"
#include "llmghidra/program/listing_manager.hpp"
#include "llmghidra/program/namespace_manager.hpp"
#include "llmghidra/program/program.hpp"
#include "llmghidra/program/program_architecture.hpp"
#include "llmghidra/program/program_context_database.hpp"
#include "llmghidra/program/property_map_manager.hpp"
#include "llmghidra/program/reference_manager.hpp"
#include "llmghidra/program/sleigh_context_metadata.hpp"
#include "llmghidra/program/symbol_manager.hpp"

#include "database.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "loadimage.hh"
#include "comment.hh"
#include "pcodeinject.hh"
#include "sleigh.hh"
#include "space.hh"
#include "translate.hh"
#include "type.hh"
#include "xml.hh"

#include <algorithm>
#include <bit>
#include <cctype>
#include <sstream>
#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <variant>
#include <utility>

namespace llmghidra::headless {
namespace {

class MetadataLoadImage final : public ghidra::LoadImage {
public:
    MetadataLoadImage() : ghidra::LoadImage("ProgramDB metadata bootstrap") {}

    void loadFill(ghidra::uint1 *, ghidra::int4,
                  const ghidra::Address &) override {
        throw ghidra::DataUnavailError(
            "metadata-only SLEIGH initialization cannot read program bytes");
    }
    void openSymbols() const override {}
    void closeSymbols() const override {}
    bool getNextSymbol(ghidra::LoadImageFunc &) const override { return false; }
    std::string getArchType() const override { return {}; }
    void adjustVma(long adjustment) override {
        if (adjustment != 0) {
            throw ghidra::LowlevelError(
                "metadata-only SLEIGH image has no movable address map");
        }
    }
};

[[nodiscard]] program::Address to_program_address(
    const program::Program &program,
    const ghidra::Address &address) {
    if (address.isInvalid() || address.getSpace() == nullptr) {
        return {};
    }
    const auto space = program.address_factory()->space(
        address.getSpace()->getName());
    if (!space || address.getOffset() > space->max_offset()) {
        return {};
    }
    return space->address(static_cast<std::uint64_t>(address.getOffset()));
}

[[nodiscard]] ghidra::Address to_decompiler_address(
    const ghidra::AddrSpaceManager &spaces,
    const program::Address &address) {
    if (!address.is_valid()) return {};
    auto *space = spaces.getSpaceByName(address.space()->name());
    if (space == nullptr || address.offset() > space->getHighest()) {
        return {};
    }
    return ghidra::Address(space, address.offset());
}

[[nodiscard]] ghidra::uint8 persistent_id(std::int64_t id) noexcept {
    return static_cast<ghidra::uint8>(id);
}

[[nodiscard]] bool is_default_parameter_name(std::string_view name) {
    constexpr std::string_view prefix = "param_";
    if (!name.starts_with(prefix) || name.size() == prefix.size()) return false;
    return std::ranges::all_of(name.substr(prefix.size()), [](unsigned char value) {
        return std::isdigit(value) != 0;
    });
}

[[nodiscard]] ghidra::Address variable_usepoint(
    const ghidra::Address &entry,
    std::int32_t first_use_offset) {
    return entry + static_cast<ghidra::int8>(first_use_offset);
}

[[nodiscard]] ghidra::ParameterPieces make_parameter_pieces(
    ProgramSleighArchitecture &architecture,
    const program::VariableStorage &storage,
    ghidra::Datatype *type,
    ghidra::uint4 flags = 0,
    bool force_logical_size = false) {
    if (type == nullptr) {
        throw ghidra::LowlevelError("ProgramDB variable has no native data-type");
    }

    ghidra::ParameterPieces result;
    result.type = type;
    result.flags = flags;
    if (storage.is_void()) {
        if (type->getMetatype() != ghidra::TYPE_VOID) {
            throw ghidra::LowlevelError(
                "ProgramDB VOID storage is attached to a non-void data-type");
        }
        result.addr = ghidra::Address();
        return result;
    }
    if (!storage.is_mapped() || storage.varnodes().empty()) {
        throw ghidra::LowlevelError(
            "ProgramDB variable storage is not mapped");
    }

    std::vector<ghidra::VarnodeData> pieces;
    pieces.reserve(storage.varnodes().size());
    ghidra::int4 physical_size = 0;
    for (const auto &varnode : storage.varnodes()) {
        const auto address = to_decompiler_address(architecture, varnode.address);
        if (address.isInvalid() || varnode.size <= 0) {
            throw ghidra::LowlevelError(
                "ProgramDB variable storage references an unavailable address space");
        }
        if (physical_size > std::numeric_limits<ghidra::int4>::max() -
                                varnode.size) {
            throw ghidra::LowlevelError(
                "ProgramDB variable storage size exceeds the native decompiler range");
        }
        physical_size += varnode.size;
        ghidra::VarnodeData piece;
        piece.space = address.getSpace();
        piece.offset = address.getOffset();
        piece.size = varnode.size;
        pieces.push_back(piece);
    }

    const auto logical_size = type->getSize();
    if (logical_size <= 0) {
        throw ghidra::LowlevelError(
            "ProgramDB mapped variable has a zero-sized data-type");
    }
    if (logical_size != physical_size && pieces.size() == 1 &&
        (force_logical_size || type->getMetatype() == ghidra::TYPE_FLOAT)) {
        // MappedEntry uses logicalsize for a widened float. Return symbols use
        // it for every size mismatch. Other mappings retain their physical
        // address and let the Symbol data-type define the logical extent.
        auto *join = architecture.findAddJoin(
            pieces, static_cast<ghidra::uint4>(logical_size));
        result.addr = join->getUnified().getAddr();
        return result;
    }

    // VariableStorage stores BE pieces most-to-least and LE pieces
    // least-to-most. ParameterPieces requires an explicit ordering flag.
    result.assignAddressFromPieces(
        pieces, architecture.translate->isBigEndian(), &architecture);
    return result;
}

class ProgramCommentDatabase final : public ghidra::CommentDatabase {
public:
    ProgramCommentDatabase(
        const program::Program &program,
        const ghidra::AddrSpaceManager &spaces)
        : program_(&program), spaces_(&spaces) {}

    void clear() override {
        cache_.clear();
        cached_function_.reset();
    }

    void clearType(const ghidra::Address &function, ghidra::uint4 type) override {
        cache_.clearType(function, type);
    }

    void addComment(
        ghidra::uint4 type,
        const ghidra::Address &function,
        const ghidra::Address &address,
        const std::string &text) override {
        // Decompiler-generated warning comments are intentionally session
        // local, matching CommentDatabaseGhidra.
        cache_.addComment(type, function, address, text);
    }

    bool addCommentNoDuplicate(
        ghidra::uint4 type,
        const ghidra::Address &function,
        const ghidra::Address &address,
        const std::string &text) override {
        return cache_.addCommentNoDuplicate(type, function, address, text);
    }

    void deleteComment(ghidra::Comment *) override {
        throw ghidra::LowlevelError(
            "persistent ProgramDB comments are changed through CommentManager");
    }

    ghidra::CommentSet::const_iterator beginComment(
        const ghidra::Address &function) const override {
        fill_cache(function);
        return cache_.beginComment(function);
    }

    ghidra::CommentSet::const_iterator endComment(
        const ghidra::Address &function) const override {
        fill_cache(function);
        return cache_.endComment(function);
    }

    void encode(ghidra::Encoder &) const override {
        throw ghidra::LowlevelError(
            "ProgramDB comment provider cannot be serialized independently");
    }

    void decode(ghidra::Decoder &) override {
        throw ghidra::LowlevelError(
            "ProgramDB comment provider cannot be replaced from a stream");
    }

private:
    void fill_cache(const ghidra::Address &function) const {
        if (cached_function_ && *cached_function_ == function) return;
        cache_.clear();
        cached_function_ = function;

        const auto program_entry = to_program_address(*program_, function);
        if (!program_entry.is_valid()) return;
        const auto owner = program_->functions().at(program_entry);
        if (!owner) return;

        constexpr ghidra::uint4 decompiler_types[] = {
            ghidra::Comment::user1,
            ghidra::Comment::user2,
            ghidra::Comment::user3,
            ghidra::Comment::header};
        for (const auto &record : program_->comments().all()) {
            if (!owner->body.contains(record.address)) continue;
            const auto address = to_decompiler_address(*spaces_, record.address);
            if (address.isInvalid()) continue;
            for (std::size_t index = 0;
                 index < std::size(decompiler_types); ++index) {
                if (record.comments[index]) {
                    cache_.addComment(
                        decompiler_types[index], function, address,
                        *record.comments[index]);
                }
            }
        }
    }

    const program::Program *program_{};
    const ghidra::AddrSpaceManager *spaces_{};
    mutable ghidra::CommentDatabaseInternal cache_;
    mutable std::optional<ghidra::Address> cached_function_;
};

[[nodiscard]] std::string xml_escape(const std::string &value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
        case '&':
            escaped += "&amp;";
            break;
        case '<':
            escaped += "&lt;";
            break;
        case '>':
            escaped += "&gt;";
            break;
        case '\"':
            escaped += "&quot;";
            break;
        case '\'':
            escaped += "&apos;";
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }
    return escaped;
}

void register_specification(
    ghidra::DocumentStorage &store,
    const std::filesystem::path &path,
    const char *kind) {
    if (path.empty()) {
        throw std::invalid_argument(
            std::string("missing ") + kind + " specification path");
    }
    try {
        ghidra::Document *document = store.openDocument(path.string());
        store.registerTag(document->getRoot());
    }
    catch (const ghidra::DecoderError &error) {
        throw ghidra::SleighError(
            std::string("XML error parsing ") + kind + " specification " +
            path.string() + ": " + error.explain);
    }
    catch (const ghidra::LowlevelError &error) {
        throw ghidra::SleighError(
            std::string("error reading ") + kind + " specification " +
            path.string() + ": " + error.explain);
    }
}

void register_sleigh_file(
    ghidra::DocumentStorage &store,
    const std::filesystem::path &path) {
    if (path.empty()) {
        throw std::invalid_argument("missing compiled SLEIGH specification path");
    }
    std::istringstream input(
        "<sleigh>" + xml_escape(path.string()) + "</sleigh>");
    try {
        ghidra::Document *document = store.parseDocument(input);
        store.registerTag(document->getRoot());
    }
    catch (const ghidra::LowlevelError &error) {
        throw ghidra::SleighError(
            "error registering compiled SLEIGH specification " +
            path.string() + ": " + error.explain);
    }
}

void apply_space_truncations(
    ghidra::Translate &translate,
    const program::LanguageDescription &language) {
    for (const auto &truncation : language.address_space_truncations) {
        translate.truncateSpace(
            ghidra::TruncationTag(truncation.space, truncation.size));
    }
}

struct MetadataArchitecture {
    std::shared_ptr<program::AddressFactory> address_factory;
    std::shared_ptr<const program::ProgramArchitecture> architecture;
};

[[nodiscard]] MetadataArchitecture build_metadata_architecture(
    const program::LanguageDescription &language,
    const program::ProcessorSpec &processor_spec,
    const program::CompilerSpec &compiler_spec) {
    MetadataLoadImage loader;
    program::SleighContextMetadataCollector context;
    ghidra::Sleigh translate(&loader, &context);
    ghidra::DocumentStorage store;
    register_sleigh_file(store, language.sleigh_file);
    translate.initialize(store);
    apply_space_truncations(translate, language);

    auto address_factory = program::AddressFactory::from_sleigh(
        translate, processor_spec, compiler_spec);
    auto architecture = std::make_shared<program::ProgramArchitecture>(
        program::ProgramArchitecture::from_sleigh(
            translate, *address_factory, compiler_spec.data_organization,
            language.endian, std::nullopt, context.fields()));
    return {std::move(address_factory), std::move(architecture)};
}

[[nodiscard]] std::string simple_class_name(std::string value) {
    const auto separator = value.find_last_of("./$");
    if (separator != std::string::npos) value.erase(0, separator + 1);
    return value;
}

[[nodiscard]] std::string ascii_lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] bool contains(std::string_view text, std::string_view needle) {
    return text.find(needle) != std::string_view::npos;
}

[[nodiscard]] std::string default_component_name(
    const program::CompositeComponent &component,
    bool is_union) {
    if (component.field_name && !component.field_name->empty()) {
        return *component.field_name;
    }
    std::string result = "field" + std::to_string(component.ordinal);
    if (!is_union) {
        std::ostringstream suffix;
        suffix << "_0x" << std::hex << component.offset;
        result += suffix.str();
    }
    return result;
}

[[nodiscard]] bool enum_is_signed(const program::EnumDataType &value) {
    if (value.values.empty()) return false;
    const auto minimum = std::ranges::min_element(
        value.values, {}, &program::EnumValue::value)->value;
    if (minimum >= 0) return false;
    const auto maximum = std::ranges::max_element(
        value.values, {}, &program::EnumValue::value)->value;
    if (value.size >= sizeof(std::int64_t)) return true;
    const auto bits = static_cast<unsigned>(value.size) * 8U;
    const auto signed_max = static_cast<std::uint64_t>((std::uint64_t{1}
                                                        << (bits - 1U)) - 1U);
    return static_cast<std::uint64_t>(maximum) <= signed_max;
}

[[nodiscard]] bool is_pointer_data_type(
    const program::DataTypeManager &manager,
    std::int64_t id,
    unsigned depth = 0) {
    if (id <= 0 || depth > 64) return false;
    const auto value = manager.data_type(id);
    if (!value) return false;
    if (std::holds_alternative<program::PointerDataType>(*value)) return true;
    if (const auto *alias = std::get_if<program::TypedefDataType>(&*value)) {
        return is_pointer_data_type(manager, alias->referenced_type_id, depth + 1);
    }
    return false;
}

[[nodiscard]] std::vector<std::string> category_components(
    const program::DataTypeManager &manager,
    std::int64_t category_id) {
    std::vector<std::string> reversed;
    std::unordered_set<std::int64_t> visited;
    while (category_id != program::DataTypeManager::root_category_id) {
        if (!visited.insert(category_id).second) {
            throw ghidra::LowlevelError(
                "ProgramDB data-type category graph contains a cycle");
        }
        const auto category = manager.category(category_id);
        if (!category) {
            throw ghidra::LowlevelError(
                "ProgramDB data-type references a missing category");
        }
        reversed.push_back(category->name);
        category_id = category->parent_id;
    }
    std::ranges::reverse(reversed);
    return reversed;
}

[[nodiscard]] std::vector<std::string> namespace_components(
    const program::Program &program,
    std::int64_t namespace_id) {
    std::vector<std::string> reversed;
    std::unordered_set<std::int64_t> visited;
    while (namespace_id != program::NamespaceManager::global_namespace_id) {
        if (!visited.insert(namespace_id).second) {
            throw ghidra::LowlevelError(
                "ProgramDB namespace graph contains a cycle");
        }
        const auto symbol = program.symbols().get(namespace_id);
        if (!symbol) {
            throw ghidra::LowlevelError(
                "ProgramDB namespace graph contains a missing symbol");
        }
        if (symbol->type == program::SymbolType::library) break;
        reversed.push_back(symbol->name);
        namespace_id = symbol->parent_id;
    }
    std::ranges::reverse(reversed);
    return reversed;
}

[[nodiscard]] bool path_ends_with(
    const std::vector<std::string> &path,
    const std::vector<std::string> &suffix) {
    if (suffix.size() > path.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), path.rbegin());
}

[[nodiscard]] std::vector<std::string> parse_category_path(
    std::string_view path) {
    std::vector<std::string> result;
    std::string component;
    bool escaped = false;
    for (const char ch : path) {
        if (escaped) {
            component.push_back(ch);
            escaped = false;
        }
        else if (ch == '\\') {
            escaped = true;
        }
        else if (ch == '/') {
            if (!component.empty()) {
                result.push_back(std::move(component));
                component.clear();
            }
        }
        else {
            component.push_back(ch);
        }
    }
    if (escaped) component.push_back('\\');
    if (!component.empty()) result.push_back(std::move(component));
    return result;
}

[[nodiscard]] std::optional<std::int64_t> class_structure_type(
    const program::Program &program,
    const program::Symbol &class_symbol) {
    const auto full_namespace = namespace_components(program, class_symbol.id);
    auto parent_namespace = full_namespace;
    if (!parent_namespace.empty()) parent_namespace.pop_back();
    std::vector<std::string> preferred_root;
    if (const auto preferred =
            program.preferred_root_namespace_category()) {
        preferred_root = parse_category_path(*preferred);
    }
    auto preferred_parent = preferred_root;
    preferred_parent.insert(
        preferred_parent.end(), parent_namespace.begin(),
        parent_namespace.end());
    auto preferred_full = preferred_root;
    preferred_full.insert(
        preferred_full.end(), full_namespace.begin(), full_namespace.end());

    struct Candidate {
        std::int64_t id{};
        int score{};
        std::vector<std::string> category;
    };
    std::vector<Candidate> candidates;
    for (const auto &encoded : program.data_types().all_data_types()) {
        const auto *composite = std::get_if<program::CompositeDataType>(&encoded);
        if (composite == nullptr || composite->is_union ||
            composite->name != class_symbol.name) {
            continue;
        }
        auto category = category_components(
            program.data_types(), composite->category_id);
        int score = 0;
        if (!preferred_root.empty() && category == preferred_parent) score = 4;
        else if (!preferred_root.empty() && category == preferred_full) score = 3;
        else if (path_ends_with(category, parent_namespace)) score = 2;
        else if (path_ends_with(category, full_namespace)) score = 1;
        if (score != 0) {
            candidates.push_back({composite->id, score, std::move(category)});
        }
    }
    if (candidates.empty()) return std::nullopt;
    std::ranges::sort(candidates, [](const Candidate &left,
                                    const Candidate &right) {
        if (left.score != right.score) return left.score > right.score;
        if (left.category.size() != right.category.size()) {
            return left.category.size() < right.category.size();
        }
        if (left.category != right.category) {
            return left.category < right.category;
        }
        return left.id < right.id;
    });
    return candidates.front().id;
}

} // namespace

// ProgramDB-backed replacement for the Java PcodeDataTypeManager callback.
// Types are materialized lazily and retain the complete 64-bit ProgramDB id.
class ProgramTypeFactory final : public ghidra::TypeFactory {
public:
    ProgramTypeFactory(
        ProgramSleighArchitecture &architecture,
        program::Program &program,
        const program::CompilerSpec &compiler_spec)
        : ghidra::TypeFactory(&architecture), program_(&program),
          architecture_(&architecture), compiler_spec_(&compiler_spec) {}

    [[nodiscard]] ghidra::Datatype *resolve_program_type(
        std::int64_t id,
        ghidra::int4 size_hint = 0) {
        if (id == -1) return getTypeVoid();
        if (id == 0 || id == -2) {
            return getBase(std::max<ghidra::int4>(1, size_hint),
                           ghidra::TYPE_UNKNOWN);
        }
        if (const auto cached = resolved_.find(id); cached != resolved_.end()) {
            return cached->second;
        }
        if (!resolving_.insert(id).second) {
            throw ghidra::LowlevelError(
                "ProgramDB data-type graph contains an unsupported direct cycle");
        }
        try {
            const auto value = program_->data_types().data_type(id);
            if (!value) {
                throw ghidra::LowlevelError(
                    "ProgramDB data-type id cannot be resolved: " +
                    std::to_string(id));
            }
            auto *result = materialize(*value, size_hint);
            resolved_.insert_or_assign(id, result);
            resolving_.erase(id);
            return result;
        }
        catch (...) {
            resolving_.erase(id);
            throw;
        }
    }

    [[nodiscard]] bool is_default_program_type(std::int64_t id) const {
        const auto encoded = program_->data_types().data_type(id);
        if (!encoded ||
            !std::holds_alternative<program::BuiltinDataType>(*encoded)) {
            return false;
        }
        const auto &builtin = std::get<program::BuiltinDataType>(*encoded);
        return ascii_lower(simple_class_name(builtin.class_name)) ==
               "defaultdatatype";
    }

protected:
    ghidra::Datatype *findById(
        const std::string &name,
        ghidra::uint8 id,
        ghidra::int4 size) override {
        if (auto *local = ghidra::TypeFactory::findById(name, id, size)) {
            return local;
        }
        const auto program_id = std::bit_cast<std::int64_t>(
            static_cast<std::uint64_t>(id));
        if (const auto cached = resolved_.find(program_id);
            cached != resolved_.end()) {
            return cached->second;
        }
        if (program_id <= 0 ||
            !program_->data_types().contains_data_type(program_id)) {
            return nullptr;
        }
        return resolve_program_type(program_id, size);
    }

private:
    [[nodiscard]] ghidra::Datatype *resolve_component_type(
        std::int64_t id,
        ghidra::int4 size_hint) {
        if (id <= 0) {
            return getBase(std::max<ghidra::int4>(1, size_hint),
                           ghidra::TYPE_UNKNOWN);
        }
        return resolve_program_type(id, size_hint);
    }

    [[nodiscard]] ghidra::Datatype *materialize_builtin(
        const program::BuiltinDataType &value,
        ghidra::int4 size_hint) {
        const auto metrics = program_->data_types().data_type_metrics(
            value.id, compiler_spec_->data_organization);
        const ghidra::int4 size = metrics.length > 0
                                      ? metrics.length
                                      : std::max<ghidra::int4>(1, size_hint);
        const auto class_name = ascii_lower(simple_class_name(value.class_name));
        const auto name = value.name.empty()
                              ? simple_class_name(value.class_name)
                              : value.name;
        const auto id = static_cast<ghidra::uint8>(value.id);

        if (contains(class_name, "voiddatatype")) return getTypeVoid();
        if (contains(class_name, "pointerdatatype")) {
            const auto word_size = std::max<ghidra::uint4>(
                1, architecture_->getDefaultDataSpace()->getWordSize());
            return getTypePointer(
                size, getBase(1, ghidra::TYPE_UNKNOWN), word_size);
        }
        if (contains(class_name, "widechar")) {
            return getTypeUnicode(name, size, ghidra::TYPE_INT, id);
        }
        if (class_name == "chardatatype") {
            const auto meta = compiler_spec_->data_organization.char_signed
                                  ? ghidra::TYPE_INT
                                  : ghidra::TYPE_UINT;
            if (size == 1) return getTypeChar(name, id, meta);
            return getTypeUnicode(name, size, meta, id);
        }
        if (contains(class_name, "booleandatatype")) {
            return getBase(size, ghidra::TYPE_BOOL, name, id);
        }
        if (contains(class_name, "float") || contains(class_name, "double")) {
            return getBase(size, ghidra::TYPE_FLOAT, name, id);
        }
        if (contains(class_name, "unsigned") ||
            contains(class_name, "qword") ||
            contains(class_name, "dword") ||
            contains(class_name, "worddatatype") ||
            contains(class_name, "bytedatatype")) {
            return getBase(size, ghidra::TYPE_UINT, name, id);
        }
        if (contains(class_name, "integer") || contains(class_name, "short") ||
            contains(class_name, "long") || contains(class_name, "signed")) {
            return getBase(size, ghidra::TYPE_INT, name, id);
        }
        return getBase(size, ghidra::TYPE_UNKNOWN, name, id);
    }

    [[nodiscard]] ghidra::Datatype *materialize_composite(
        const program::CompositeDataType &value) {
        const auto id = static_cast<ghidra::uint8>(value.id);
        if (value.is_union) {
            auto *result = getTypeUnion(value.name, id);
            resolved_.insert_or_assign(value.id, result);
            std::vector<ghidra::TypeField> fields;
            fields.reserve(value.components.size());
            for (const auto &component : value.components) {
                if (component.length <= 0) continue;
                ghidra::Datatype *field_type{};
                if (component.data_type_id > 0 &&
                    program::DataTypeManager::kind(component.data_type_id) ==
                        program::DataTypeKind::bitfield) {
                    field_type = getBase(component.length, ghidra::TYPE_UNKNOWN);
                }
                else {
                    field_type = resolve_component_type(
                        component.data_type_id, component.length);
                }
                fields.emplace_back(
                    component.ordinal, component.offset,
                    default_component_name(component, true), field_type);
            }
            assignProgramFields(
                result, fields, value.length, std::max(1, value.alignment));
            return result;
        }

        auto *result = getTypeStruct(value.name, id);
        resolved_.insert_or_assign(value.id, result);
        std::vector<ghidra::TypeField> fields;
        std::vector<ghidra::TypeBitField> bitfields;
        fields.reserve(value.components.size());
        bitfields.reserve(value.components.size());
        const bool big_endian =
            architecture_->getDefaultDataSpace()->isBigEndian();
        for (const auto &component : value.components) {
            if (component.length <= 0) continue;
            if (component.data_type_id > 0 &&
                program::DataTypeManager::kind(component.data_type_id) ==
                    program::DataTypeKind::bitfield) {
                const auto encoded = program_->data_types().data_type(
                    component.data_type_id);
                if (!encoded ||
                    !std::holds_alternative<program::BitFieldDataType>(*encoded)) {
                    throw ghidra::LowlevelError(
                        "ProgramDB structure references an invalid bitfield type");
                }
                const auto &bitfield =
                    std::get<program::BitFieldDataType>(*encoded);
                auto *base = resolve_component_type(
                    bitfield.base_type_id, component.length);
                const auto available_bits = std::max(0, base->getSize()) * 8;
                const auto width = std::min<ghidra::int4>(
                    bitfield.declared_bit_size, available_bits);
                if (width <= 0) continue;
                bitfields.emplace_back(
                    component.ordinal, component.offset, component.length,
                    bitfield.bit_offset, width, big_endian,
                    default_component_name(component, false), base);
                continue;
            }
            fields.emplace_back(
                component.ordinal, component.offset,
                default_component_name(component, false),
                resolve_component_type(
                    component.data_type_id, component.length));
        }
        assignProgramFields(
            result, fields, bitfields, value.length,
            std::max(1, value.alignment));
        return result;
    }

    [[nodiscard]] ghidra::Datatype *materialize_function_definition(
        const program::FunctionDefinitionDataType &value) {
        ghidra::PrototypePieces pieces;
        pieces.model = architecture_->defaultfp;
        if (const auto convention =
                program_->data_types().calling_convention_name(
                    value.calling_convention_id)) {
            if (auto *model = architecture_->getModel(*convention)) {
                pieces.model = model;
            }
        }
        pieces.name = value.name;
        pieces.outtype = value.return_type_id == -1
                             ? getTypeVoid()
                             : resolve_component_type(value.return_type_id, 1);
        pieces.intypes.reserve(value.parameters.size());
        pieces.innames.reserve(value.parameters.size());
        for (const auto &parameter : value.parameters) {
            pieces.intypes.push_back(resolve_component_type(
                parameter.data_type_id, parameter.data_type_length));
            pieces.innames.push_back(parameter.name);
        }
        pieces.firstVarArgSlot = value.variadic
                                     ? static_cast<ghidra::int4>(
                                           value.parameters.size())
                                     : -1;
        return getTypeCode(
            value.name, static_cast<ghidra::uint8>(value.id), pieces,
            value.no_return);
    }

    [[nodiscard]] ghidra::Datatype *materialize(
        const program::DataType &value,
        ghidra::int4 size_hint) {
        return std::visit(
            [&](const auto &item) -> ghidra::Datatype * {
                using T = std::decay_t<decltype(item)>;
                if constexpr (std::is_same_v<T, program::BuiltinDataType>) {
                    return materialize_builtin(item, size_hint);
                }
                else if constexpr (std::is_same_v<T, program::ArrayDataType>) {
                    auto *element = resolve_component_type(
                        item.element_type_id, item.element_length);
                    return getTypeArray(item.element_count, element);
                }
                else if constexpr (std::is_same_v<T, program::PointerDataType>) {
                    const auto metrics = program_->data_types().data_type_metrics(
                        item.id, compiler_spec_->data_organization);
                    const auto pointer_size = metrics.length > 0
                                                  ? metrics.length
                                                  : std::max<ghidra::int4>(
                                                        1, size_hint);
                    auto *referenced = resolve_component_type(
                        item.referenced_type_id, 1);
                    const auto word_size = std::max<ghidra::uint4>(
                        1, architecture_->getDefaultDataSpace()->getWordSize());
                    return getTypePointer(pointer_size, referenced, word_size);
                }
                else if constexpr (std::is_same_v<T, program::TypedefDataType>) {
                    auto *referenced = resolve_component_type(
                        item.referenced_type_id, size_hint);
                    return getTypedef(
                        referenced, item.name,
                        static_cast<ghidra::uint8>(item.id), 0);
                }
                else if constexpr (std::is_same_v<T, program::EnumDataType>) {
                    const auto meta = enum_is_signed(item)
                                          ? ghidra::TYPE_ENUM_INT
                                          : ghidra::TYPE_ENUM_UINT;
                    auto *result = getTypeEnum(
                        item.name, item.size, meta,
                        static_cast<ghidra::uint8>(item.id));
                    std::map<ghidra::uintb, std::string> values;
                    for (const auto &entry : item.values) {
                        values[static_cast<ghidra::uintb>(entry.value)] =
                            entry.name;
                    }
                    setEnumValues(values, result);
                    return result;
                }
                else if constexpr (std::is_same_v<T, program::CompositeDataType>) {
                    return materialize_composite(item);
                }
                else if constexpr (
                    std::is_same_v<T, program::FunctionDefinitionDataType>) {
                    return materialize_function_definition(item);
                }
                else if constexpr (std::is_same_v<T, program::BitFieldDataType>) {
                    return resolve_component_type(item.base_type_id, size_hint);
                }
            },
            value);
    }

    program::Program *program_{};
    ProgramSleighArchitecture *architecture_{};
    const program::CompilerSpec *compiler_spec_{};
    std::unordered_map<std::int64_t, ghidra::Datatype *> resolved_;
    std::unordered_set<std::int64_t> resolving_;
};

ProgramSleighArchitecture::ProgramSleighArchitecture(
    program::Program &program,
    program::LanguageDescription language,
    program::ProcessorSpec processor_spec,
    program::CompilerSpec compiler_spec,
    std::ostream &errors)
    : ghidra::SleighArchitecture(
          program.name(),
          language.id + ":" + compiler_spec.description.id,
          &errors),
      program_(&program),
      language_(std::move(language)),
      processor_spec_(std::move(processor_spec)),
      compiler_spec_(std::move(compiler_spec)) {}

ProgramSleighArchitecture::~ProgramSleighArchitecture() {
    // SleighArchitecture assumes its translators come from its static cache
    // and nulls this pointer in its destructor.  This subclass creates a
    // program-specific translator, so release it before that base destructor.
    delete const_cast<ghidra::Translate *>(translate);
    translate = nullptr;
}

program::Program &ProgramSleighArchitecture::program() noexcept {
    return *program_;
}

const program::Program &ProgramSleighArchitecture::program() const noexcept {
    return *program_;
}

const program::LanguageDescription &
ProgramSleighArchitecture::language() const noexcept {
    return language_;
}

const program::ProcessorSpec &
ProgramSleighArchitecture::processor_spec() const noexcept {
    return processor_spec_;
}

const program::CompilerSpec &
ProgramSleighArchitecture::compiler_spec() const noexcept {
    return compiler_spec_;
}

ghidra::Datatype *ProgramSleighArchitecture::resolve_program_data_type(
    std::int64_t id, ghidra::int4 size_hint) {
    if (program_types_ == nullptr) {
        throw ghidra::LowlevelError(
            "ProgramDB data-type provider is not initialized");
    }
    return program_types_->resolve_program_type(id, size_hint);
}

void ProgramSleighArchitecture::buildLoader(ghidra::DocumentStorage &) {
    auto owned = std::make_unique<ProgramLoadImage>(*program_);
    program_loader_ = owned.get();
    loader = owned.release();
}

ghidra::Scope *ProgramSleighArchitecture::buildDatabase(
    ghidra::DocumentStorage &store) {
    return ghidra::Architecture::buildDatabase(store);
}

ghidra::Translate *ProgramSleighArchitecture::buildTranslator(
    ghidra::DocumentStorage &) {
    return new ghidra::Sleigh(loader, context);
}

void ProgramSleighArchitecture::buildContext(ghidra::DocumentStorage &) {
    auto owned =
        std::make_unique<program::SleighContextMetadataCollector>();
    metadata_context_ = owned.get();
    context = owned.release();
}

void ProgramSleighArchitecture::buildTypegrp(ghidra::DocumentStorage &) {
    auto owned = std::make_unique<ProgramTypeFactory>(
        *this, *program_, compiler_spec_);
    program_types_ = owned.get();
    types = owned.release();
}

void ProgramSleighArchitecture::buildCommentDB(ghidra::DocumentStorage &) {
    commentdb = new ProgramCommentDatabase(*program_, *this);
}

void ProgramSleighArchitecture::buildStringManager(ghidra::DocumentStorage &) {
    stringManager = new ProgramStringManager(*program_, 2048);
}

void ProgramSleighArchitecture::buildConstantPool(ghidra::DocumentStorage &) {
    cpool = build_program_constant_pool(*this).release();
}

void ProgramSleighArchitecture::buildSymbols(
    ghidra::DocumentStorage &store) {
    populate_program_symbols();
    ghidra::SleighArchitecture::buildSymbols(store);
}

void ProgramSleighArchitecture::buildSpecFile(
    ghidra::DocumentStorage &store) {
    register_specification(
        store, language_.processor_specification, "processor");
    register_specification(
        store, compiler_spec_.description.specification, "compiler");
    register_sleigh_file(store, language_.sleigh_file);
}

void ProgramSleighArchitecture::modifySpaces(ghidra::Translate *selected) {
    if (selected == nullptr) {
        throw ghidra::LowlevelError(
            "cannot apply language truncations to a null translator");
    }
    apply_space_truncations(*selected, language_);
}

void ProgramSleighArchitecture::resolveArchitecture() {
    archid = language_.id + ":" + compiler_spec_.description.id;
}

void ProgramSleighArchitecture::install_program_overlays() {
    for (const auto &space : program_->address_factory()->all_spaces()) {
        if (!space->is_overlay_space()) continue;
        if (getSpaceByName(space->name()) != nullptr) {
            throw ghidra::LowlevelError(
                "ProgramDB overlay conflicts with decompiler address space: " +
                space->name());
        }
        const auto base = space->overlayed_space();
        if (!base || getSpaceByName(base->name()) == nullptr) {
            throw ghidra::LowlevelError(
                "ProgramDB overlay base is unavailable in decompiler: " +
                space->name());
        }

        std::istringstream input(
            "<space_overlay name=\"" + xml_escape(space->name()) +
            "\" index=\"" + std::to_string(numSpaces()) +
            "\" base=\"" + xml_escape(base->name()) + "\"/>");
        ghidra::DocumentStorage store;
        ghidra::Document *document = store.parseDocument(input);
        auto overlay = std::make_unique<ghidra::OverlaySpace>(this, translate);
        ghidra::XmlDecode decoder(this, document->getRoot());
        overlay->decode(decoder);
        insertSpace(overlay.release());
    }
}

void ProgramSleighArchitecture::populate_program_symbols() {
    if (program_symbols_populated_) return;
    if (symboltab == nullptr || types == nullptr || translate == nullptr ||
        program_types_ == nullptr || defaultfp == nullptr) {
        throw ghidra::LowlevelError(
            "ProgramDB symbols require initialized decompiler database and types");
    }

    auto *global = symboltab->getGlobalScope();
    for (const auto &space : program_->address_factory()->physical_spaces()) {
        auto *native = getSpaceByName(space->name());
        if (native != nullptr) {
            symboltab->addRange(
                global, native, space->min_offset(), space->max_offset());
        }
    }

    const auto persistent_symbols = program_->symbols().all();
    std::unordered_map<std::int64_t, ghidra::Scope *> scopes;
    scopes.emplace(program::NamespaceManager::global_namespace_id, global);
    std::vector<const program::Symbol *> pending_namespaces;
    for (const auto &symbol : persistent_symbols) {
        if (symbol.type == program::SymbolType::name_space ||
            symbol.type == program::SymbolType::class_type ||
            symbol.type == program::SymbolType::library) {
            pending_namespaces.push_back(&symbol);
        }
    }
    while (!pending_namespaces.empty()) {
        bool progressed = false;
        for (auto item = pending_namespaces.begin();
             item != pending_namespaces.end();) {
            const auto parent = scopes.find((*item)->parent_id);
            if (parent == scopes.end()) {
                ++item;
                continue;
            }
            auto *scope = symboltab->findCreateScope(
                static_cast<ghidra::uint8>((*item)->id),
                (*item)->name, parent->second);
            scopes.emplace((*item)->id, scope);
            item = pending_namespaces.erase(item);
            progressed = true;
        }
        if (!progressed) {
            throw ghidra::LowlevelError(
                "ProgramDB namespace graph contains an unresolved parent or cycle");
        }
    }

    const auto functions = program_->functions().all();
    std::unordered_map<std::int64_t, const program::Function *> functions_by_id;
    functions_by_id.reserve(functions.size());
    for (const auto &function : functions) {
        functions_by_id.emplace(function.symbol_id, &function);
    }

    struct NativeFunction {
        const program::Function *persistent{};
        ghidra::FunctionSymbol *symbol{};
        ghidra::Funcdata *data{};
        ghidra::Address entry;
    };
    std::vector<NativeFunction> native_functions;
    native_functions.reserve(functions.size());

    // Create every function shell first. This allows thunk targets and calls
    // to resolve regardless of ProgramDB record order.
    for (const auto &function : functions) {
        if (!function.symbol.address.is_memory_address()) continue;
        const auto entry = to_decompiler_address(
            *this, function.symbol.address);
        if (entry.isInvalid()) continue;
        const auto parent = scopes.find(function.symbol.parent_id);
        auto *scope = parent == scopes.end() ? global : parent->second;
        auto *function_symbol = scope->addFunction(
            entry, function.symbol.name);
        scope->assignPersistentSymbolId(
            function_symbol, persistent_id(function.symbol_id));
        auto *function_data = function_symbol->getFunction();
        native_functions.push_back(
            {&function, function_symbol, function_data, entry});
    }

    // Java's HighExternalSymbol does not map the synthetic EXTERNAL-space
    // address into the decompiler.  A primary external reference on defined
    // pointer data is instead mounted at the pointer's physical address, and
    // an external Function is resolved at that same unique placeholder.
    std::map<ghidra::Address, std::int64_t> mounted_external_functions;
    for (const auto &data : program_->listing().defined_data()) {
        if (!is_pointer_data_type(program_->data_types(), data.data_type_id)) {
            continue;
        }
        const auto refs = program_->references().references_from(data.address);
        const program::Reference *external_reference{};
        for (const auto &reference : refs) {
            if (reference.operand_index == 0 && reference.primary &&
                reference.to.is_external_address()) {
                external_reference = &reference;
                break;
            }
        }
        if (external_reference == nullptr) continue;
        const auto location = program_->externals().at(external_reference->to);
        if (!location) continue;
        const auto physical = to_decompiler_address(*this, data.address);
        if (physical.isInvalid()) continue;

        if (location->function) {
            const auto persistent = functions_by_id.find(location->symbol.id);
            if (persistent == functions_by_id.end()) {
                throw ghidra::LowlevelError(
                    "ProgramDB external function has no indexed Function record");
            }
            const auto mounted = mounted_external_functions.find(physical);
            if (mounted != mounted_external_functions.end() &&
                mounted->second != location->symbol.id) {
                throw ghidra::LowlevelError(
                    "ProgramDB external references collide at one physical address");
            }
            if (mounted == mounted_external_functions.end()) {
                auto *function_symbol = global->addFunction(
                    physical, location->symbol.name);
                global->assignPersistentSymbolId(
                    function_symbol, persistent_id(location->symbol.id));
                native_functions.push_back(
                    {persistent->second, function_symbol,
                     function_symbol->getFunction(), physical});
                mounted_external_functions.emplace(
                    physical, location->symbol.id);
            }
        }

        // HighExternalSymbol appends this suffix before marshaling. Preserve
        // it here because Scope::addExternalRef accepts the final native name.
        global->addExternalRef(
            physical, physical, location->symbol.name + "_exref");
    }

    const auto semantic_function = [&](const program::Function &function)
        -> const program::Function & {
        const program::Function *current = &function;
        std::unordered_set<std::int64_t> visited;
        while (visited.insert(current->symbol_id).second) {
            const auto target = program_->functions().thunk_target(
                current->symbol_id);
            if (!target) return *current;
            const auto found = functions_by_id.find(*target);
            if (found == functions_by_id.end()) {
                throw ghidra::LowlevelError(
                    "ProgramDB thunk references a missing function");
            }
            current = found->second;
        }
        throw ghidra::LowlevelError(
            "ProgramDB thunk graph contains a cycle");
    };

    const auto model_for = [&](const program::Function &function) {
        if (function.calling_convention_id <=
            program::FunctionManager::default_calling_convention_id) {
            return defaultfp;
        }
        const auto convention = program_->data_types().calling_convention_name(
            function.calling_convention_id);
        if (!convention) {
            throw ghidra::LowlevelError(
                "ProgramDB function references an unknown calling convention");
        }
        auto *model = getModel(*convention);
        if (model == nullptr) {
            throw ghidra::LowlevelError(
                "ProgramDB calling convention has no compiler-spec prototype: " +
                *convention);
        }
        return model;
    };

    const auto this_pointer_type = [&](const program::Function &function) {
        ghidra::Datatype *referenced = types->getTypeVoid();
        const auto parent = program_->symbols().get(function.symbol.parent_id);
        if (parent && parent->type == program::SymbolType::class_type) {
            if (const auto candidate = class_structure_type(*program_, *parent)) {
                referenced = program_types_->resolve_program_type(*candidate);
            }
        }
        const auto pointer_size = static_cast<ghidra::int4>(
            std::max<std::uint32_t>(
                1, compiler_spec_.data_organization.pointer_size));
        return types->getTypePointer(
            pointer_size, referenced,
            std::max<ghidra::uint4>(
                1, getDefaultDataSpace()->getWordSize()));
    };

    for (const auto &native : native_functions) {
        const auto &function = semantic_function(*native.persistent);
        auto *model = model_for(function);
        auto &prototype = native.data->getFuncProto();
        prototype.setModel(model);
        prototype.setCustomStorage(function.custom_parameter_storage);
        prototype.setInline(function.inline_hint);
        prototype.setNoReturn(function.no_return);
        prototype.setDotdotdot(function.variadic);
        prototype.setModelLock(
            function.calling_convention_id !=
            program::FunctionManager::unknown_calling_convention_id);

        if (const auto call_fixup = program_->properties().get(
                "CallFixup", function.symbol.address)) {
            if (const auto *name = std::get_if<std::string>(&*call_fixup);
                name != nullptr && !name->empty()) {
                const auto inject_id = pcodeinjectlib->getPayloadId(
                    ghidra::InjectPayload::CALLFIXUP_TYPE, *name);
                if (inject_id >= 0) prototype.setInjectId(inject_id);
            }
        }

        const bool signature_locked =
            function.signature_source != program::SignatureSource::default_source;
        const auto parameters = program_->functions().parameters(
            function.symbol_id);
        auto *return_type = program_types_->resolve_program_type(
            function.return_data_type_id);

        std::vector<std::pair<ghidra::ProtoParameter *,
                              const program::FunctionVariable *>>
            persistent_parameters;
        bool inputs_complete = true;
        bool output_has_valid_storage = true;

        if (!function.custom_parameter_storage) {
            ghidra::PrototypePieces pieces;
            pieces.model = model;
            pieces.name = function.symbol.name;
            pieces.outtype = return_type;
            if (model->hasThisPointer()) {
                // A thunk inherits the target's prototype but its synthesized
                // this-pointer type is adjusted to the thunk's own class.
                pieces.intypes.push_back(
                    this_pointer_type(*native.persistent));
                pieces.innames.emplace_back("this");
            }
            for (const auto &parameter : parameters) {
                const auto type_id = parameter.symbol.data_type_id.value_or(0);
                pieces.intypes.push_back(program_types_->resolve_program_type(
                    type_id, parameter.storage.size()));
                pieces.innames.push_back(parameter.symbol.name);
            }
            pieces.firstVarArgSlot = function.variadic
                                         ? static_cast<ghidra::int4>(
                                               pieces.intypes.size())
                                         : -1;
            prototype.updateAllTypes(pieces);
            inputs_complete = !prototype.hasInputErrors();
            const auto *native_output = prototype.getOutput();
            output_has_valid_storage = native_output != nullptr &&
                (return_type->getMetatype() == ghidra::TYPE_VOID ||
                 !native_output->getAddress().isInvalid());

            std::size_t persistent_index = 0;
            for (ghidra::int4 index = 0; index < prototype.numParams(); ++index) {
                auto *parameter = prototype.getParam(index);
                if (parameter == nullptr || parameter->isThisPointer() ||
                    parameter->isHiddenReturn()) {
                    continue;
                }
                if (persistent_index >= parameters.size()) {
                    inputs_complete = false;
                    break;
                }
                persistent_parameters.emplace_back(
                    parameter, &parameters[persistent_index++]);
            }
            if (persistent_index != parameters.size()) inputs_complete = false;
        }
        else {
            prototype.clearInput();
            for (std::size_t index = 0; index < parameters.size(); ++index) {
                const auto &parameter = parameters[index];
                if (!parameter.storage.is_mapped() ||
                    parameter.storage.is_hash_storage()) {
                    inputs_complete = false;
                    break;
                }
                const auto type_id = parameter.symbol.data_type_id.value_or(0);
                auto *parameter_type = program_types_->resolve_program_type(
                    type_id, parameter.storage.size());
                auto pieces = make_parameter_pieces(
                    *this, parameter.storage, parameter_type);
                prototype.setParam(
                    static_cast<ghidra::int4>(index),
                    parameter.symbol.name, pieces);
                persistent_parameters.emplace_back(
                    prototype.getParam(static_cast<ghidra::int4>(index)),
                    &parameter);
            }

            program::VariableStorage return_storage =
                program::VariableStorage::unassigned();
            if (function.return_storage) {
                try {
                    return_storage = program::VariableStorage::deserialize(
                        *program_->address_factory(), *function.return_storage);
                }
                catch (const std::exception &) {
                    return_storage = program::VariableStorage::bad();
                }
            }
            if (return_storage.is_mapped()) {
                return_type = program_types_->resolve_program_type(
                    function.return_data_type_id, return_storage.size());
                prototype.setOutput(make_parameter_pieces(
                    *this, return_storage, return_type, 0, true));
            }
            else if (return_storage.is_void()) {
                ghidra::ParameterPieces output;
                output.addr = ghidra::Address();
                output.type = types->getTypeVoid();
                output.flags = 0;
                prototype.setOutput(output);
            }
            else {
                ghidra::ParameterPieces output;
                output.addr = ghidra::Address();
                output.type = types->getTypeVoid();
                output.flags = 0;
                prototype.setOutput(output);
                output_has_valid_storage = false;
            }
        }

        prototype.setInputErrors(!inputs_complete);
        prototype.setOutputErrors(!output_has_valid_storage);
        prototype.setInputLock(signature_locked && inputs_complete);
        for (const auto &[native_parameter, persistent_parameter] :
             persistent_parameters) {
            if (native_parameter == nullptr) continue;
            native_parameter->setNameLock(
                !is_default_parameter_name(
                    persistent_parameter->symbol.name));
            native_parameter->getSymbol()->getScope()->assignPersistentSymbolId(
                native_parameter->getSymbol(),
                persistent_id(persistent_parameter->symbol.id));
        }

        const bool output_locked =
            signature_locked && output_has_valid_storage &&
            !program_types_->is_default_program_type(
                function.return_data_type_id);
        prototype.setOutputLock(output_locked);

        if (function.stack_purge ==
                program::FunctionManager::unknown_stack_depth_change ||
            function.stack_purge ==
                std::numeric_limits<std::int32_t>::max() - 1) {
            prototype.setExtraPop(model->getExtraPop());
        }
        else {
            const std::int64_t extrapop =
                static_cast<std::int64_t>(function.stack_purge) +
                model->getStackShift();
            if (extrapop < std::numeric_limits<ghidra::int4>::min() ||
                extrapop > std::numeric_limits<ghidra::int4>::max()) {
                throw ghidra::LowlevelError(
                    "ProgramDB function stack purge exceeds native range");
            }
            prototype.setExtraPop(static_cast<ghidra::int4>(extrapop));
        }

        auto *local_scope = native.data->getScopeLocal();
        const bool is_thunk = program_->functions().thunk_target(
                                  native.persistent->symbol_id).has_value();
        const auto locals = is_thunk
                                ? std::vector<program::FunctionVariable>{}
                                : program_->functions().local_variables(
                                      function.symbol_id);
        for (const auto &local : locals) {
            if ((!local.storage.is_mapped()) ||
                local.storage.varnodes().empty()) {
                continue;
            }
            const auto type_id = local.symbol.data_type_id.value_or(0);
            auto *local_type = program_types_->resolve_program_type(
                type_id, local.storage.size());
            const auto usepoint = variable_usepoint(
                native.entry, local.symbol.variable_offset.value_or(0));
            ghidra::Symbol *local_symbol{};
            if (local.storage.is_hash_storage()) {
                local_symbol = local_scope->addDynamicSymbol(
                    local.symbol.name, local_type, usepoint,
                    static_cast<ghidra::uint8>(
                        local.storage.varnodes().front().address.offset()));
            }
            else {
                const auto pieces = make_parameter_pieces(
                    *this, local.storage, local_type);
                ghidra::Address restricted_usepoint;
                const auto &first = local.storage.varnodes().front().address;
                if (!first.is_stack_address() && !first.is_memory_address()) {
                    restricted_usepoint = usepoint;
                }
                local_symbol = local_scope->addSymbol(
                    local.symbol.name, local_type, pieces.addr,
                    restricted_usepoint)->getSymbol();
            }
            local_scope->assignPersistentSymbolId(
                local_symbol, persistent_id(local.symbol.id));
            local_scope->setAttribute(local_symbol, ghidra::Varnode::namelock);
            if (local_type->getMetatype() != ghidra::TYPE_UNKNOWN) {
                local_scope->setAttribute(
                    local_symbol, ghidra::Varnode::typelock);
            }
        }
    }

    for (const auto &symbol : persistent_symbols) {
        if (symbol.type != program::SymbolType::label &&
            symbol.type != program::SymbolType::global_variable) {
            continue;
        }
        if (!symbol.address.is_memory_address()) continue;
        const auto address = to_decompiler_address(*this, symbol.address);
        if (address.isInvalid()) continue;
        const auto parent = scopes.find(symbol.parent_id);
        if (parent == scopes.end()) continue;
        if (symbol.type == program::SymbolType::label) {
            auto *label = parent->second->addCodeLabel(address, symbol.name);
            parent->second->assignPersistentSymbolId(
                label, persistent_id(symbol.id));
            continue;
        }

        auto *data_type = symbol.data_type_id
                              ? program_types_->resolve_program_type(
                                    *symbol.data_type_id)
                              : types->getBase(1, ghidra::TYPE_UNKNOWN);
        auto *entry = parent->second->addSymbol(
            symbol.name, data_type, address, ghidra::Address());
        parent->second->assignPersistentSymbolId(
            entry->getSymbol(), persistent_id(symbol.id));
    }
    program_symbols_populated_ = true;
}

void ProgramSleighArchitecture::postSpecFile() {
    auto *sleigh = dynamic_cast<ghidra::Sleigh *>(
        const_cast<ghidra::Translate *>(translate));
    if (sleigh == nullptr || program_loader_ == nullptr ||
        metadata_context_ == nullptr) {
        throw ghidra::LowlevelError(
            "ProgramDB SLEIGH runtime was not initialized in lifecycle order");
    }

    install_program_overlays();
    program_loader_->attach_address_spaces(*this);

    auto persistent_context = program_->create_sleigh_context_database(
        *translate, processor_spec_, compiler_spec_);
    sleigh->reset(loader, persistent_context.get());
    delete context;
    context = persistent_context.release();
    metadata_context_ = nullptr;

    symboltab->adjustCaches();
    ghidra::Architecture::postSpecFile();
}

std::unique_ptr<HeadlessRuntime> HeadlessRuntime::open(
    std::shared_ptr<db::DatabaseHandle> database,
    program::ProgramOpenMode mode,
    const std::filesystem::path &processor_pack_root,
    std::ostream &errors) {
    if (!database) {
        throw std::invalid_argument("headless runtime requires a database");
    }
    if (mode == program::ProgramOpenMode::create) {
        throw std::invalid_argument(
            "HeadlessRuntime::open cannot create a new ProgramDB");
    }

    const auto stored = program::Program::inspect_stored_spec(database);
    if (stored.language_id.empty() || stored.compiler_spec_id.empty()) {
        throw std::runtime_error(
            "ProgramDB does not identify a language and compiler spec");
    }

    program::LanguageRegistry registry(processor_pack_root);
    registry.discover();
    auto language = registry.language(stored.language_id);
    auto processor_spec = registry.load_processor_spec(language.id);
    auto compiler_spec = registry.load_compiler_spec(
        language.id, stored.compiler_spec_id);
    auto metadata = build_metadata_architecture(
        language, processor_spec, compiler_spec);

    auto opened_program = program::Program::open(
        database, mode, std::move(metadata.address_factory),
        std::move(metadata.architecture));
    auto architecture = std::make_unique<ProgramSleighArchitecture>(
        *opened_program, std::move(language), std::move(processor_spec),
        std::move(compiler_spec), errors);
    ghidra::DocumentStorage store;
    architecture->init(store);

    return std::unique_ptr<HeadlessRuntime>(new HeadlessRuntime(
        std::move(opened_program), std::move(architecture)));
}

HeadlessRuntime::HeadlessRuntime(
    std::unique_ptr<program::Program> program,
    std::unique_ptr<ProgramSleighArchitecture> architecture)
    : program_(std::move(program)), architecture_(std::move(architecture)) {}

HeadlessRuntime::~HeadlessRuntime() = default;

program::Program &HeadlessRuntime::program() noexcept { return *program_; }

const program::Program &HeadlessRuntime::program() const noexcept {
    return *program_;
}

ProgramSleighArchitecture &HeadlessRuntime::architecture() noexcept {
    return *architecture_;
}

const ProgramSleighArchitecture &HeadlessRuntime::architecture() const noexcept {
    return *architecture_;
}

} // namespace llmghidra::headless
