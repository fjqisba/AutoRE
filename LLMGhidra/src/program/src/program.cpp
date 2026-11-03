#include "llmghidra/program/program.hpp"

#include "llmghidra/program/bookmark_manager.hpp"
#include "llmghidra/program/comment_manager.hpp"
#include "llmghidra/program/code_manager.hpp"
#include "llmghidra/program/data_type_manager.hpp"
#include "llmghidra/program/equate_manager.hpp"
#include "llmghidra/program/external_manager.hpp"
#include "llmghidra/program/function_manager.hpp"
#include "llmghidra/program/legacy_function_upgrade.hpp"
#include "llmghidra/program/legacy_program_upgrade.hpp"
#include "llmghidra/program/listing_manager.hpp"
#include "llmghidra/program/language_translator.hpp"
#include "llmghidra/program/memory_manager.hpp"
#include "llmghidra/program/namespace_manager.hpp"
#include "llmghidra/program/overlay_space_manager.hpp"
#include "llmghidra/program/program_architecture.hpp"
#include "llmghidra/program/program_context_database.hpp"
#include "llmghidra/program/property_map_manager.hpp"
#include "llmghidra/program/reference_manager.hpp"
#include "llmghidra/program/register_context_manager.hpp"
#include "llmghidra/program/relocation_manager.hpp"
#include "llmghidra/program/symbol_manager.hpp"
#include "llmghidra/program/variable_storage_manager.hpp"

#include <charconv>
#include <exception>
#include <stdexcept>
#include <utility>
#include <vector>

namespace llmghidra::program {
namespace {

constexpr const char *program_table_name = "Program";
constexpr const char *program_name_key = "Program Name";
constexpr const char *database_version_key = "DB Version";
constexpr const char *language_version_key = "Language Version";
constexpr const char *old_language_name_key = "Language Name";
constexpr const char *language_id_key = "Language ID";
constexpr const char *compiler_spec_id_key = "Compiler Spec ID";
constexpr const char *image_offset_key = "Image Offset";
constexpr const char *executable_path_key = "Executable Location";
constexpr const char *executable_format_key = "Executable Format";
constexpr const char *executable_md5_key = "Executable MD5";
constexpr const char *executable_sha256_key = "Executable SHA256";
constexpr const char *preferred_root_namespace_category_key =
    "Preferred Root Namespace Category";

[[nodiscard]] std::pair<std::int32_t, std::int32_t> parse_language_version(
    const std::optional<std::string> &text) noexcept {
    if (!text) {
        return {1, 0};
    }
    const std::size_t dot = text->find('.');
    if (dot == std::string::npos) {
        return {1, 0};
    }
    std::int32_t major{};
    std::int32_t minor{};
    const auto [major_end, major_error] =
        std::from_chars(text->data(), text->data() + dot, major);
    const auto [minor_end, minor_error] =
        std::from_chars(text->data() + dot + 1, text->data() + text->size(), minor);
    if (major_error != std::errc{} || minor_error != std::errc{} ||
        major_end != text->data() + dot || minor_end != text->data() + text->size()) {
        return {1, 0};
    }
    return {major, minor};
}

[[nodiscard]] std::optional<std::uint64_t> parse_image_offset(
    const std::optional<std::string> &text) noexcept {
    if (!text) return std::nullopt;
    std::uint64_t parsed{};
    const auto [end, error] = std::from_chars(
        text->data(), text->data() + text->size(), parsed);
    if (error != std::errc{} || end != text->data() + text->size()) {
        return std::nullopt;
    }
    return parsed;
}

[[nodiscard]] ProgramSpec read_program_spec(const StringMap &program_info) {
    ProgramSpec spec;
    spec.name = program_info.get(program_name_key).value_or(std::string{});
    spec.language_id = program_info.get(language_id_key).value_or(
        program_info.get(old_language_name_key).value_or(std::string{}));
    spec.compiler_spec_id =
        program_info.get(compiler_spec_id_key).value_or(std::string{});
    const auto [major, minor] =
        parse_language_version(program_info.get(language_version_key));
    spec.language_version = major;
    spec.language_minor_version = minor;
    spec.image_base_offset =
        parse_image_offset(program_info.get(image_offset_key)).value_or(0);
    return spec;
}

} // namespace

Program::Transaction::Transaction(Program &program, std::string)
    : program_(&program), id_(program.database_->start_transaction()), active_(true) {}

Program::Transaction::~Transaction() {
    if (active_) {
        try {
            (void)program_->database_->end_transaction(id_, false);
            program_->invalidate_caches();
        }
        catch (...) {
        }
    }
}

Program::Transaction::Transaction(Transaction &&other) noexcept
    : program_(std::exchange(other.program_, nullptr)),
      id_(std::exchange(other.id_, 0)),
      active_(std::exchange(other.active_, false)) {}

Program::Transaction &Program::Transaction::operator=(Transaction &&other) noexcept {
    if (this == &other) {
        return *this;
    }
    if (active_) {
        try {
            (void)program_->database_->end_transaction(id_, false);
            program_->invalidate_caches();
        }
        catch (...) {
        }
    }
    program_ = std::exchange(other.program_, nullptr);
    id_ = std::exchange(other.id_, 0);
    active_ = std::exchange(other.active_, false);
    return *this;
}

void Program::Transaction::commit() {
    if (!active_) {
        throw std::logic_error("program transaction is no longer active");
    }
    (void)program_->database_->end_transaction(id_, true);
    active_ = false;
}

void Program::Transaction::rollback(bool invalidate_caches) {
    if (!active_) {
        throw std::logic_error("program transaction is no longer active");
    }
    (void)program_->database_->end_transaction(id_, false);
    active_ = false;
    if (invalidate_caches) program_->invalidate_caches();
}

bool Program::Transaction::active() const noexcept { return active_; }

std::unique_ptr<Program> Program::create(
    std::shared_ptr<db::DatabaseHandle> database,
    ProgramSpec spec,
    std::shared_ptr<AddressFactory> address_factory,
    std::shared_ptr<const ProgramArchitecture> architecture) {
    if (spec.name.empty() || spec.language_id.empty() || spec.compiler_spec_id.empty()) {
        throw std::invalid_argument(
            "program creation requires name, language id, and compiler-spec id");
    }
    if (!database || !address_factory) {
        throw std::invalid_argument("program requires a database and address factory");
    }
    const std::int64_t transaction_id = database->start_transaction();
    try {
        auto result = std::unique_ptr<Program>(new Program(
            database, ProgramOpenMode::create, std::move(address_factory),
            std::move(architecture),
            std::move(spec), true));
        (void)database->end_transaction(transaction_id, true);
        return result;
    }
    catch (...) {
        (void)database->end_transaction(transaction_id, false);
        throw;
    }
}

std::unique_ptr<Program> Program::open(
    std::shared_ptr<db::DatabaseHandle> database,
    ProgramOpenMode mode,
    std::shared_ptr<AddressFactory> address_factory,
    std::shared_ptr<const ProgramArchitecture> architecture) {
    if (mode == ProgramOpenMode::create) {
        throw std::invalid_argument("use Program::create for new databases");
    }
    if (!database || !address_factory) {
        throw std::invalid_argument("program requires a database and address factory");
    }
    if (mode != ProgramOpenMode::upgrade) {
        return std::unique_ptr<Program>(new Program(
            std::move(database), mode, std::move(address_factory),
            std::move(architecture), ProgramSpec{}, false));
    }
    const std::int64_t transaction_id = database->start_transaction();
    try {
        auto result = std::unique_ptr<Program>(new Program(
            database, mode, std::move(address_factory), std::move(architecture),
            ProgramSpec{}, false));
        (void)database->end_transaction(transaction_id, true);
        return result;
    }
    catch (...) {
        (void)database->end_transaction(transaction_id, false);
        throw;
    }
}

ProgramSpec Program::inspect_stored_spec(
    const std::shared_ptr<db::DatabaseHandle> &database) {
    if (!database) {
        throw std::invalid_argument(
            "program specification inspection requires a database");
    }
    const StringMap program_info(database, program_table_name, false);
    return read_program_spec(program_info);
}

Program::Program(std::shared_ptr<db::DatabaseHandle> database,
                 ProgramOpenMode mode,
                 std::shared_ptr<AddressFactory> address_factory,
                 std::shared_ptr<const ProgramArchitecture> architecture,
                 ProgramSpec spec,
                 bool create)
    : database_(std::move(database)),
      address_factory_(std::move(address_factory)),
      architecture_(std::move(architecture)),
      program_info_(database_, program_table_name, create),
      overlay_spaces_(std::make_unique<OverlaySpaceManager>(
          database_, address_factory_, mode, create)),
      address_map_(database_, mode, address_factory_, spec.image_base_offset),
      mode_(mode),
      spec_(std::move(spec)) {
    if (!database_ || !address_factory_) {
        throw std::invalid_argument("program requires a database and address factory");
    }
    if (create) {
        create_program_info();
    }
    else {
        read_program_info();
    }
    memory_ = std::make_unique<MemoryManager>(
        database_, address_map_, mode_, create);
    reconcile_overlay_regions();
    data_types_ = std::make_unique<DataTypeManager>(
        database_, mode_, create, &address_map_, architecture_.get());
    variable_storage_ = std::make_unique<VariableStorageManager>(
        database_, address_factory_, mode_, create);
    symbols_ = std::make_unique<SymbolManager>(database_, address_map_, mode_, create);
    namespaces_ = std::make_unique<NamespaceManager>(
        database_, address_map_, *symbols_, mode_);
    comments_ = std::make_unique<CommentManager>(
        database_, address_map_, mode_, create);
    properties_ = std::make_unique<PropertyMapManager>(
        database_, address_map_, mode_, create);
    bookmarks_ = std::make_unique<BookmarkManager>(
        database_, address_map_, *properties_, mode_, create);
    references_ = std::make_unique<ReferenceManager>(
        database_, address_map_, mode_, create);
    equates_ = std::make_unique<EquateManager>(
        database_, address_map_, mode_, create);
    listing_ = std::make_unique<ListingManager>(
        database_, address_map_, mode_, create);
    register_context_ = std::make_unique<RegisterContextManager>(
        database_, address_map_, mode_, architecture_);
    listing_->set_data_type_length_resolver(
        [this](std::int64_t data_type_id, const Address &) -> std::int64_t {
            if (data_type_id == 0) return 1;
            if (!data_types_->contains_data_type(data_type_id)) {
                throw std::runtime_error(
                    "Listing data record references a missing data type");
            }
            const auto organization = architecture_
                ? architecture_->data_organization
                : DataOrganization{};
            return data_types_->data_type_metrics(
                data_type_id, organization).length;
        });
    listing_->set_available_length_resolver(
        [this](const Address &address) -> std::uint64_t {
            const auto block = memory_->block_containing(address);
            if (!block) return 1;
            return static_cast<std::uint64_t>(
                       block->end().subtract(address)) + 1;
        });
    code_ = std::make_unique<CodeManager>(
        *listing_, *memory_, *comments_, *references_, *register_context_);
    const auto default_pointer_size = architecture_
                                          ? architecture_->data_organization.pointer_size
                                          : DataOrganization{}.pointer_size;
    relocations_ = std::make_unique<RelocationManager>(
        database_, address_map_, *memory_, mode_, create,
        default_pointer_size);
    const bool legacy_functions =
        !create && mode_ == ProgramOpenMode::upgrade &&
        LegacyFunctionUpgrade::present(database_);
    functions_ = std::make_unique<FunctionManager>(
        database_, *symbols_, *data_types_, *variable_storage_, *namespaces_,
        mode_, create, legacy_functions);
    externals_ = std::make_unique<ExternalManager>(
        *symbols_, *functions_, *namespaces_);
    symbols_->set_external_removal_handler([this](std::int64_t symbol_id) {
        (void)references_->remove_symbol_associations(symbol_id);
    });
    if (mode_ == ProgramOpenMode::upgrade) {
        LegacyProgramUpgradeCoordinator coordinator(
            database_, address_map_, *symbols_, *namespaces_, *functions_,
            *data_types_, *comments_, *variable_storage_, *references_,
            architecture_.get());
        coordinator.upgrade();
    }
    data_types_->set_external_replacement_handler(
        [this](std::int64_t replaced_id, std::int64_t replacement_id) {
            (void)symbols_->replace_data_type(replaced_id, replacement_id);
            (void)functions_->replace_data_type(replaced_id, replacement_id);
            (void)listing_->replace_data_type(replaced_id, replacement_id);
        });
    data_types_->set_external_deletion_handler([this](std::int64_t deleted_id) {
        (void)symbols_->replace_data_type(deleted_id, 0);
        (void)functions_->replace_data_type(deleted_id, 0);
        (void)listing_->replace_data_type(deleted_id, 0);
    });
    if (mode_ == ProgramOpenMode::upgrade) {
        data_types_->finish_legacy_source_archive_upgrade();
        if (upgrade_source_version_ < 26) {
            relocations_->refine_pre_v6_statuses(default_pointer_size);
        }
    }
    memory_->set_external_move_handler(
        [this](const Address &from, const Address &to, std::uint64_t length) {
            references_->move_address_range(from, to, length);
            namespaces_->move_address_range(from, to, length);
            symbols_->move_address_range(from, to, length);
            comments_->move_address_range(from, to, length);
            bookmarks_->move_address_range(from, to, length);
            equates_->move_address_range(from, to, length);
            listing_->move_address_range(from, to, length);
            register_context_->move_address_range(from, to, length);
            properties_->move_address_range(from, to, length);
        });
    memory_->set_external_delete_handler(
        [this](const Address &start, const Address &end) {
            (void)references_->remove_references_from_range(start, end);
            (void)functions_->remove_overlapping_range(start, end);
            namespaces_->delete_address_range(start, end);
            (void)symbols_->remove_range(start, end, true);
            comments_->delete_address_range(start, end);
            bookmarks_->delete_address_range(start, end);
            equates_->delete_address_range(start, end);
            listing_->delete_address_range(start, end);
            register_context_->delete_address_range(start, end);
            properties_->delete_address_range(start, end);
        });
    memory_->set_external_overlay_creation_handler(
        [this](const std::string &block_name, const Address &start,
               std::uint64_t length) {
            if (!start.is_memory_address() || length == 0) {
                throw std::invalid_argument("invalid overlay memory range");
            }
            (void)start.add_no_wrap(static_cast<std::int64_t>(length - 1));
            std::string base_name;
            base_name.reserve(block_name.size());
            for (const unsigned char value : block_name) {
                base_name.push_back(value == ':' || value <= 0x20
                                        ? '_'
                                        : static_cast<char>(value));
            }
            if (base_name.empty()) {
                throw std::invalid_argument(
                    "overlay memory block name must not be empty");
            }
            std::string candidate = base_name;
            std::uint64_t suffix = 1;
            while (address_factory_->space(candidate)) {
                candidate = base_name + "." + std::to_string(suffix++);
            }
            const auto overlay = create_overlay_space(
                std::move(candidate), start.space());
            return overlay->address_in_this_space(start.offset());
        });
    memory_->set_external_region_change_handler(
        [this]() { reconcile_overlay_regions(); });
    memory_->set_external_overlay_cleanup_handler(
        [this](const std::string &name) {
            (void)remove_overlay_space(name);
        });
    code_->activate_context_locking();
    if (mode_ == ProgramOpenMode::upgrade &&
        upgrade_source_version_ < database_version) {
        program_info_.put(database_version_key, std::to_string(database_version));
        stored_version_ = database_version;
        needs_upgrade_ = false;
    }
}

Program::~Program() = default;

void Program::create_program_info() {
    stored_version_ = database_version;
    upgrade_source_version_ = database_version;
    program_info_.put(program_name_key, spec_.name);
    // Retained for Ghidra backward compatibility, matching ProgramDB.
    program_info_.put(old_language_name_key, spec_.language_id);
    program_info_.put(language_id_key, spec_.language_id);
    program_info_.put(compiler_spec_id_key, spec_.compiler_spec_id);
    program_info_.put(language_version_key,
                      std::to_string(spec_.language_version) + "." +
                          std::to_string(spec_.language_minor_version));
    program_info_.put(database_version_key, std::to_string(database_version));
    program_info_.put(image_offset_key, std::to_string(spec_.image_base_offset));
}

void Program::read_program_info() {
    spec_ = read_program_spec(program_info_);
    if (const auto parsed = parse_image_offset(program_info_.get(image_offset_key))) {
        address_map_.set_image_base(
            address_factory_->default_space()->address(*parsed));
    }
    stored_version_ = program_info_.get_int(database_version_key, 1);
    upgrade_source_version_ = stored_version_;
    if (stored_version_ > database_version) {
        throw std::runtime_error("program database was created by a newer Ghidra schema");
    }
    needs_upgrade_ = stored_version_ < minimum_upgrade_free_version ||
                     (mode_ == ProgramOpenMode::update && stored_version_ < database_version);
    if (needs_upgrade_ && mode_ == ProgramOpenMode::update) {
        throw std::runtime_error("program database requires upgrade");
    }
}

Program::Transaction Program::transaction(std::string description) {
    return Transaction(*this, std::move(description));
}

const std::string &Program::name() const noexcept { return spec_.name; }

void Program::set_name(std::string name) {
    if (name.empty()) {
        throw std::invalid_argument("program name must not be empty");
    }
    write_property(program_name_key, name);
    spec_.name = std::move(name);
}

const std::string &Program::language_id() const noexcept { return spec_.language_id; }
const std::string &Program::compiler_spec_id() const noexcept { return spec_.compiler_spec_id; }
std::int32_t Program::language_version() const noexcept { return spec_.language_version; }
std::int32_t Program::language_minor_version() const noexcept {
    return spec_.language_minor_version;
}
std::int32_t Program::stored_database_version() const noexcept { return stored_version_; }
bool Program::needs_upgrade() const noexcept { return needs_upgrade_; }

const std::shared_ptr<db::DatabaseHandle> &Program::database() const noexcept {
    return database_;
}
const std::shared_ptr<AddressFactory> &Program::address_factory() const noexcept {
    return address_factory_;
}
const std::shared_ptr<const ProgramArchitecture> &
Program::architecture() const noexcept {
    return architecture_;
}
PersistentAddressMap &Program::address_map() noexcept { return address_map_; }
const PersistentAddressMap &Program::address_map() const noexcept { return address_map_; }
SymbolManager &Program::symbols() noexcept { return *symbols_; }
const SymbolManager &Program::symbols() const noexcept { return *symbols_; }
FunctionManager &Program::functions() noexcept { return *functions_; }
const FunctionManager &Program::functions() const noexcept { return *functions_; }
DataTypeManager &Program::data_types() noexcept { return *data_types_; }
const DataTypeManager &Program::data_types() const noexcept { return *data_types_; }
VariableStorageManager &Program::variable_storage() noexcept {
    return *variable_storage_;
}
const VariableStorageManager &Program::variable_storage() const noexcept {
    return *variable_storage_;
}
NamespaceManager &Program::namespaces() noexcept { return *namespaces_; }
const NamespaceManager &Program::namespaces() const noexcept {
    return *namespaces_;
}
CommentManager &Program::comments() noexcept { return *comments_; }
const CommentManager &Program::comments() const noexcept { return *comments_; }
BookmarkManager &Program::bookmarks() noexcept { return *bookmarks_; }
const BookmarkManager &Program::bookmarks() const noexcept {
    return *bookmarks_;
}
ReferenceManager &Program::references() noexcept { return *references_; }
const ReferenceManager &Program::references() const noexcept {
    return *references_;
}
MemoryManager &Program::memory() noexcept { return *memory_; }
const MemoryManager &Program::memory() const noexcept { return *memory_; }
EquateManager &Program::equates() noexcept { return *equates_; }
const EquateManager &Program::equates() const noexcept { return *equates_; }

ExternalManager &Program::externals() noexcept { return *externals_; }

const ExternalManager &Program::externals() const noexcept { return *externals_; }
RegisterContextManager &Program::register_context() noexcept {
    return *register_context_;
}
const RegisterContextManager &Program::register_context() const noexcept {
    return *register_context_;
}
void Program::initialize_context_defaults(
    const ProcessorSpec &processor_spec,
    const CompilerSpec &compiler_spec) {
    register_context_->initialize_default_values(processor_spec, compiler_spec);
}

std::unique_ptr<ProgramContextDatabase>
Program::create_sleigh_context_database(
    const ghidra::Translate &translate,
    const ProcessorSpec &processor_spec,
    const CompilerSpec &compiler_spec) {
    if (!architecture_) {
        throw std::logic_error(
            "SLEIGH context binding requires ProgramArchitecture");
    }
    initialize_context_defaults(processor_spec, compiler_spec);
    auto context = std::make_unique<ProgramContextDatabase>(
        *register_context_, *address_factory_, *architecture_, translate);
    context->initialize_tracked_values(processor_spec, compiler_spec);
    return context;
}
CodeManager &Program::code() noexcept { return *code_; }
const CodeManager &Program::code() const noexcept { return *code_; }
RelocationManager &Program::relocations() noexcept { return *relocations_; }
const RelocationManager &Program::relocations() const noexcept {
    return *relocations_;
}
PropertyMapManager &Program::properties() noexcept { return *properties_; }
const PropertyMapManager &Program::properties() const noexcept {
    return *properties_;
}
ListingManager &Program::listing() noexcept { return *listing_; }
const ListingManager &Program::listing() const noexcept { return *listing_; }

std::shared_ptr<AddressSpace> Program::create_overlay_space(
    std::string name,
    const std::shared_ptr<AddressSpace> &base_space) {
    require_mutation_transaction();
    return overlay_spaces_->create(std::move(name), base_space);
}

void Program::rename_overlay_space(
    const std::string &old_name, std::string new_name) {
    require_mutation_transaction();
    const std::string persisted_name = new_name;
    if (!overlay_spaces_->rename(old_name, std::move(new_name))) {
        throw std::out_of_range("overlay address space does not exist");
    }
    address_map_.rename_overlay_space(old_name, persisted_name);
    reconcile_overlay_regions();
}

bool Program::remove_overlay_space(const std::string &name) {
    require_mutation_transaction();
    for (const auto &block : memory_->blocks()) {
        if (block.start.space()->is_overlay_space() &&
            block.start.space()->name() == name) {
            return false;
        }
    }
    if (!overlay_spaces_->remove(name)) return false;
    address_map_.delete_overlay_space(name);
    return true;
}

std::optional<std::string> Program::executable_path() const {
    return program_info_.get(executable_path_key);
}
void Program::set_executable_path(std::optional<std::string> value) {
    write_property(executable_path_key, std::move(value));
}
std::optional<std::string> Program::executable_format() const {
    return program_info_.get(executable_format_key);
}
void Program::set_executable_format(std::optional<std::string> value) {
    write_property(executable_format_key, std::move(value));
}
std::optional<std::string> Program::executable_md5() const {
    return program_info_.get(executable_md5_key);
}
void Program::set_executable_md5(std::optional<std::string> value) {
    write_property(executable_md5_key, std::move(value));
}
std::optional<std::string> Program::executable_sha256() const {
    return program_info_.get(executable_sha256_key);
}
void Program::set_executable_sha256(std::optional<std::string> value) {
    write_property(executable_sha256_key, std::move(value));
}

std::optional<std::string> Program::preferred_root_namespace_category() const {
    return program_info_.get(preferred_root_namespace_category_key);
}

void Program::set_preferred_root_namespace_category(
    std::optional<std::string> value) {
    write_property(preferred_root_namespace_category_key, std::move(value));
}

std::unordered_map<std::string, std::string> Program::metadata() const {
    std::unordered_map<std::string, std::string> result;
    result.emplace("Program Name", spec_.name);
    result.emplace("Language ID", spec_.language_id);
    result.emplace("Compiler Spec ID", spec_.compiler_spec_id);
    result.emplace("Language Version",
                   std::to_string(spec_.language_version) + "." +
                       std::to_string(spec_.language_minor_version));
    result.emplace("Database Version", std::to_string(stored_version_));
    if (const auto value = executable_path()) result.emplace("Executable Location", *value);
    if (const auto value = executable_format()) result.emplace("Executable Format", *value);
    if (const auto value = executable_md5()) result.emplace("Executable MD5", *value);
    if (const auto value = executable_sha256()) result.emplace("Executable SHA256", *value);
    return result;
}

void Program::change_language(
    const LanguageDescription &new_language,
    std::string new_compiler_spec_id,
    std::shared_ptr<AddressFactory> new_address_factory,
    std::shared_ptr<const ProgramArchitecture> new_architecture,
    const ProcessorSpec &old_processor_spec,
    const CompilerSpec &old_compiler_spec,
    const ProcessorSpec &new_processor_spec,
    const CompilerSpec &new_compiler_spec,
    const LanguageTranslator *translator,
    bool force_redisassembly,
    ProgramLanguageChangeServices &services) {
    if (!new_address_factory || !new_architecture || new_language.id.empty()) {
        throw std::invalid_argument(
            "language change requires a complete target language runtime");
    }
    if (!architecture_ || !address_factory_) {
        throw std::logic_error(
            "language change requires an initialized Program architecture");
    }
    if (new_compiler_spec_id.empty()) {
        new_compiler_spec_id = translator
            ? translator->new_compiler_spec_id(spec_.compiler_spec_id)
            : spec_.compiler_spec_id;
    }
    if (new_compiler_spec_id.empty() ||
        new_compiler_spec.description.id != new_compiler_spec_id) {
        throw std::invalid_argument(
            "target compiler specification does not match the requested ID");
    }
    if (translator) {
        if (translator->old_language_id() != spec_.language_id ||
            translator->old_language_version() != spec_.language_version ||
            translator->new_language_id() != new_language.id ||
            translator->new_language_version() != new_language.version ||
            &translator->old_architecture() != architecture_.get() ||
            &translator->new_architecture() != new_architecture.get() ||
            &translator->old_address_factory() != address_factory_.get() ||
            &translator->new_address_factory() != new_address_factory.get()) {
            throw std::invalid_argument(
                "language translator endpoints do not match Program metadata/runtime");
        }
    }
    else {
        if (new_language.id != spec_.language_id ||
            new_address_factory.get() != address_factory_.get()) {
            throw std::invalid_argument(
                "a cross-language/address-factory change requires a translator");
        }
    }

    AddressSet program_memory;
    for (const auto &block : memory_->blocks()) {
        program_memory.add(block.start, block.end());
    }
    const auto old_spec = spec_;
    const auto old_address_factory = address_factory_;
    const auto old_architecture = architecture_;
    auto transaction_value = transaction("Change Program language");
    bool runtime_change_started = false;
    try {
        const bool redisassembly_required =
            force_redisassembly || translator != nullptr ||
            spec_.language_version != new_language.version ||
            spec_.language_minor_version != new_language.minor_version;
        if (spec_.language_id != new_language.id ||
            spec_.compiler_spec_id != new_compiler_spec_id) {
            services.reset_compiler_spec_options(
                *this, old_compiler_spec, new_compiler_spec);
        }

        if (translator) {
            // Translate address-bearing strings while both endpoint factories
            // still expose the old Program overlays. Overlay migration then
            // installs matching overlays into the target factory before the
            // ADDRESS MAP and range managers switch over.
            symbols_->set_language(*translator);
            overlay_spaces_->set_language(new_address_factory, *translator);
            functions_->set_language(*new_address_factory, *translator);
            variable_storage_->set_language(new_address_factory, *translator);
        }

        register_context_->set_language(
            new_architecture, new_address_factory, translator,
            new_processor_spec, new_compiler_spec, program_memory);
        address_factory_ = new_address_factory;
        architecture_ = new_architecture;
        data_types_->language_changed(*architecture_);

        spec_.language_id = new_language.id;
        spec_.compiler_spec_id = std::move(new_compiler_spec_id);
        spec_.language_version = new_language.version;
        spec_.language_minor_version = new_language.minor_version;

        invalidate_caches();
        runtime_change_started = true;
        services.runtime_changed(
            *this, new_language, new_processor_spec, new_compiler_spec);
        if (redisassembly_required) {
            services.repair_context(
                *this, old_spec.language_version,
                old_spec.language_minor_version, translator);
            services.redisassemble_all_instructions(*this);
        }
        services.reconcile_calling_conventions(*this, new_compiler_spec);
        if (translator) {
            for (const auto &handler : translator->post_upgrade_handlers()) {
                services.run_post_upgrade_handler(*this, handler, *translator);
            }
        }
        services.apply_processor_spec_fixups(*this, new_processor_spec);

        // Services may have changed ProgramDB state while repairing context,
        // instructions, prototypes, and markup.  Refresh every manager while
        // the transaction can still roll back; after commit there must be no
        // fallible cache operation that could pretend the committed language
        // switch was aborted.
        invalidate_caches();

        // Persist identity only after every architecture-dependent manager and
        // native SLEIGH callback has succeeded.
        program_info_.put(old_language_name_key, spec_.language_id);
        program_info_.put(language_id_key, spec_.language_id);
        program_info_.put(compiler_spec_id_key, spec_.compiler_spec_id);
        program_info_.put(
            language_version_key,
            std::to_string(spec_.language_version) + "." +
                std::to_string(spec_.language_minor_version));
        transaction_value.commit();
    }
    catch (...) {
        const auto failure = std::current_exception();
        const auto restore_noexcept = [](auto &&operation) noexcept {
            try {
                operation();
            }
            catch (...) {
            }
        };
        if (transaction_value.active()) {
            restore_noexcept(
                [&] { transaction_value.rollback(false); });
        }

        restore_noexcept([&] { spec_ = old_spec; });
        architecture_ = old_architecture;
        address_factory_ = old_address_factory;
        restore_noexcept([&] {
            overlay_spaces_->rebind_address_factory(old_address_factory);
        });
        restore_noexcept([&] {
            address_map_.set_address_factory(old_address_factory);
        });
        restore_noexcept([&] {
            variable_storage_->rebind_address_factory(old_address_factory);
        });
        restore_noexcept([&] {
            data_types_->rebind_architecture(old_architecture.get());
        });
        restore_noexcept([&] {
            register_context_->rebind_language(
                old_architecture, old_processor_spec, old_compiler_spec);
        });
        if (runtime_change_started) {
            restore_noexcept([&] {
                services.runtime_change_rolled_back(
                    *this, old_processor_spec, old_compiler_spec);
            });
        }
        restore_noexcept([&] { invalidate_caches(); });
        std::rethrow_exception(failure);
    }
}

void Program::set_image_base(Address base) {
    require_mutation_transaction();
    address_map_.set_image_base(base);
    spec_.image_base_offset = base.offset();
    program_info_.put(image_offset_key, std::to_string(spec_.image_base_offset));
}

void Program::invalidate_caches() {
    overlay_spaces_->invalidate_cache();
    address_map_.invalidate_cache();
    memory_->invalidate_caches();
    reconcile_overlay_regions();
    data_types_->invalidate_caches();
    symbols_->invalidate_cache();
    variable_storage_->invalidate_cache();
    namespaces_->invalidate_cache();
    comments_->invalidate_cache();
    bookmarks_->invalidate_cache();
    references_->invalidate_cache();
    equates_->invalidate_cache();
    listing_->invalidate_cache();
    register_context_->invalidate_cache();
    relocations_->invalidate_cache();
    properties_->invalidate_cache();
    functions_->invalidate_cache();
}

void Program::reconcile_overlay_regions() {
    std::vector<AddressRange> ranges;
    for (const auto &block : memory_->blocks()) {
        ranges.emplace_back(block.start, block.end());
    }
    overlay_spaces_->reconcile_regions(ranges);
}

void Program::require_mutation_transaction() const {
    if (mode_ == ProgramOpenMode::read_only || database_->read_only()) {
        throw db::ReadOnlyDatabaseError();
    }
    database_->check_transaction();
}

void Program::write_property(const std::string &key, std::optional<std::string> value) {
    require_mutation_transaction();
    program_info_.put(key, std::move(value));
}

} // namespace llmghidra::program
