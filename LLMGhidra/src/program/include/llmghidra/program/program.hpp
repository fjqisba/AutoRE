#pragma once

#include "llmghidra/program/persistent_address_map.hpp"
#include "llmghidra/program/string_map.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace ghidra {
class Translate;
}

namespace llmghidra::program {

class DataTypeManager;
class EquateManager;
class ExternalManager;
class FunctionManager;
class ListingManager;
class CommentManager;
class BookmarkManager;
class CodeManager;
struct CompilerSpec;
class MemoryManager;
class NamespaceManager;
class OverlaySpaceManager;
class ProgramArchitecture;
class ProgramContextDatabase;
class LanguageTranslator;
class ReferenceManager;
class RegisterContextManager;
class RelocationManager;
class PropertyMapManager;
struct ProcessorSpec;
struct LanguageDescription;
class SymbolManager;
class VariableStorageManager;

struct ProgramSpec {
    std::string name;
    std::string language_id;
    std::string compiler_spec_id;
    std::int32_t language_version{1};
    std::int32_t language_minor_version{};
    std::uint64_t image_base_offset{};
};

class Program;

// Architecture-dependent operations supplied by the native headless SLEIGH
// runtime.  The ProgramDB transaction owns all persistent manager updates;
// this interface prevents a language change from silently skipping the
// instruction/runtime work that Java ProgramDB performed after its managers.
class ProgramLanguageChangeServices {
public:
    virtual ~ProgramLanguageChangeServices() = default;
    virtual void runtime_changed(
        Program &program,
        const LanguageDescription &language,
        const ProcessorSpec &processor_spec,
        const CompilerSpec &compiler_spec) = 0;
    virtual void runtime_change_rolled_back(
        Program &program,
        const ProcessorSpec &processor_spec,
        const CompilerSpec &compiler_spec) = 0;
    virtual void reset_compiler_spec_options(
        Program &program,
        const CompilerSpec &old_compiler_spec,
        const CompilerSpec &new_compiler_spec) = 0;
    virtual void repair_context(
        Program &program,
        std::int32_t old_language_version,
        std::int32_t old_language_minor_version,
        const LanguageTranslator *translator) = 0;
    virtual void redisassemble_all_instructions(Program &program) = 0;
    virtual void reconcile_calling_conventions(
        Program &program,
        const CompilerSpec &compiler_spec) = 0;
    virtual void run_post_upgrade_handler(
        Program &program,
        const std::string &handler,
        const LanguageTranslator &translator) = 0;
    virtual void apply_processor_spec_fixups(
        Program &program,
        const ProcessorSpec &processor_spec) = 0;
};

class Program {
public:
    static constexpr std::int32_t database_version = 32;
    static constexpr std::int32_t minimum_upgrade_free_version = 19;

    ~Program();
    Program(const Program &) = delete;
    Program &operator=(const Program &) = delete;

    class Transaction {
    public:
        Transaction() = default;
        Transaction(Program &program, std::string description);
        ~Transaction();
        Transaction(Transaction &&other) noexcept;
        Transaction &operator=(Transaction &&other) noexcept;
        Transaction(const Transaction &) = delete;
        Transaction &operator=(const Transaction &) = delete;

        void commit();
        void rollback(bool invalidate_caches = true);
        [[nodiscard]] bool active() const noexcept;

    private:
        Program *program_{};
        std::int64_t id_{};
        bool active_{};
    };

    [[nodiscard]] static std::unique_ptr<Program> create(
        std::shared_ptr<db::DatabaseHandle> database,
        ProgramSpec spec,
        std::shared_ptr<AddressFactory> address_factory,
        std::shared_ptr<const ProgramArchitecture> architecture = {});
    [[nodiscard]] static std::unique_ptr<Program> open(
        std::shared_ptr<db::DatabaseHandle> database,
        ProgramOpenMode mode,
        std::shared_ptr<AddressFactory> address_factory,
        std::shared_ptr<const ProgramArchitecture> architecture = {});
    // Read the architecture-identifying ProgramDB properties before an
    // AddressFactory exists.  The native headless runtime uses this to select
    // the exact .sla/.pspec/.cspec tuple and only then constructs Program.
    [[nodiscard]] static ProgramSpec inspect_stored_spec(
        const std::shared_ptr<db::DatabaseHandle> &database);

    [[nodiscard]] Transaction transaction(std::string description = {});
    [[nodiscard]] const std::string &name() const noexcept;
    void set_name(std::string name);
    [[nodiscard]] const std::string &language_id() const noexcept;
    [[nodiscard]] const std::string &compiler_spec_id() const noexcept;
    [[nodiscard]] std::int32_t language_version() const noexcept;
    [[nodiscard]] std::int32_t language_minor_version() const noexcept;
    [[nodiscard]] std::int32_t stored_database_version() const noexcept;
    [[nodiscard]] bool needs_upgrade() const noexcept;

    [[nodiscard]] const std::shared_ptr<db::DatabaseHandle> &database() const noexcept;
    [[nodiscard]] const std::shared_ptr<AddressFactory> &address_factory() const noexcept;
    [[nodiscard]] const std::shared_ptr<const ProgramArchitecture> &
    architecture() const noexcept;
    [[nodiscard]] PersistentAddressMap &address_map() noexcept;
    [[nodiscard]] const PersistentAddressMap &address_map() const noexcept;
    [[nodiscard]] SymbolManager &symbols() noexcept;
    [[nodiscard]] const SymbolManager &symbols() const noexcept;
    [[nodiscard]] FunctionManager &functions() noexcept;
    [[nodiscard]] const FunctionManager &functions() const noexcept;
    [[nodiscard]] DataTypeManager &data_types() noexcept;
    [[nodiscard]] const DataTypeManager &data_types() const noexcept;
    [[nodiscard]] VariableStorageManager &variable_storage() noexcept;
    [[nodiscard]] const VariableStorageManager &variable_storage() const noexcept;
    [[nodiscard]] NamespaceManager &namespaces() noexcept;
    [[nodiscard]] const NamespaceManager &namespaces() const noexcept;
    [[nodiscard]] CommentManager &comments() noexcept;
    [[nodiscard]] const CommentManager &comments() const noexcept;
    [[nodiscard]] BookmarkManager &bookmarks() noexcept;
    [[nodiscard]] const BookmarkManager &bookmarks() const noexcept;
    [[nodiscard]] ReferenceManager &references() noexcept;
    [[nodiscard]] const ReferenceManager &references() const noexcept;
    [[nodiscard]] MemoryManager &memory() noexcept;
    [[nodiscard]] const MemoryManager &memory() const noexcept;
    [[nodiscard]] EquateManager &equates() noexcept;
    [[nodiscard]] const EquateManager &equates() const noexcept;
    [[nodiscard]] ExternalManager &externals() noexcept;
    [[nodiscard]] const ExternalManager &externals() const noexcept;
    [[nodiscard]] RegisterContextManager &register_context() noexcept;
    [[nodiscard]] const RegisterContextManager &register_context() const noexcept;
    void initialize_context_defaults(const ProcessorSpec &processor_spec,
                                     const CompilerSpec &compiler_spec);
    [[nodiscard]] std::unique_ptr<ProgramContextDatabase>
    create_sleigh_context_database(
        const ghidra::Translate &translate,
        const ProcessorSpec &processor_spec,
        const CompilerSpec &compiler_spec);
    [[nodiscard]] CodeManager &code() noexcept;
    [[nodiscard]] const CodeManager &code() const noexcept;
    [[nodiscard]] RelocationManager &relocations() noexcept;
    [[nodiscard]] const RelocationManager &relocations() const noexcept;
    [[nodiscard]] PropertyMapManager &properties() noexcept;
    [[nodiscard]] const PropertyMapManager &properties() const noexcept;
    [[nodiscard]] ListingManager &listing() noexcept;
    [[nodiscard]] const ListingManager &listing() const noexcept;
    [[nodiscard]] std::shared_ptr<AddressSpace> create_overlay_space(
        std::string name,
        const std::shared_ptr<AddressSpace> &base_space);
    void rename_overlay_space(const std::string &old_name,
                              std::string new_name);
    [[nodiscard]] bool remove_overlay_space(const std::string &name);

    [[nodiscard]] std::optional<std::string> executable_path() const;
    void set_executable_path(std::optional<std::string> value);
    [[nodiscard]] std::optional<std::string> executable_format() const;
    void set_executable_format(std::optional<std::string> value);
    [[nodiscard]] std::optional<std::string> executable_md5() const;
    void set_executable_md5(std::optional<std::string> value);
    [[nodiscard]] std::optional<std::string> executable_sha256() const;
    void set_executable_sha256(std::optional<std::string> value);
    [[nodiscard]] std::optional<std::string>
    preferred_root_namespace_category() const;
    void set_preferred_root_namespace_category(
        std::optional<std::string> value);
    [[nodiscard]] std::unordered_map<std::string, std::string> metadata() const;

    void change_language(
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
        ProgramLanguageChangeServices &services);

    void set_image_base(Address base);
    void invalidate_caches();

private:
    Program(std::shared_ptr<db::DatabaseHandle> database,
            ProgramOpenMode mode,
            std::shared_ptr<AddressFactory> address_factory,
            std::shared_ptr<const ProgramArchitecture> architecture,
            ProgramSpec spec,
            bool create);
    void create_program_info();
    void read_program_info();
    void require_mutation_transaction() const;
    void write_property(const std::string &key, std::optional<std::string> value);
    void reconcile_overlay_regions();

    std::shared_ptr<db::DatabaseHandle> database_;
    std::shared_ptr<AddressFactory> address_factory_;
    std::shared_ptr<const ProgramArchitecture> architecture_;
    StringMap program_info_;
    std::unique_ptr<OverlaySpaceManager> overlay_spaces_;
    PersistentAddressMap address_map_;
    ProgramOpenMode mode_;
    ProgramSpec spec_;
    std::int32_t stored_version_{};
    std::int32_t upgrade_source_version_{};
    bool needs_upgrade_{};
    std::unique_ptr<MemoryManager> memory_;
    std::unique_ptr<DataTypeManager> data_types_;
    std::unique_ptr<VariableStorageManager> variable_storage_;
    std::unique_ptr<SymbolManager> symbols_;
    std::unique_ptr<NamespaceManager> namespaces_;
    std::unique_ptr<CommentManager> comments_;
    std::unique_ptr<BookmarkManager> bookmarks_;
    std::unique_ptr<ReferenceManager> references_;
    std::unique_ptr<EquateManager> equates_;
    std::unique_ptr<ListingManager> listing_;
    std::unique_ptr<FunctionManager> functions_;
    std::unique_ptr<ExternalManager> externals_;
    std::unique_ptr<RegisterContextManager> register_context_;
    std::unique_ptr<CodeManager> code_;
    std::unique_ptr<RelocationManager> relocations_;
    std::unique_ptr<PropertyMapManager> properties_;
};

} // namespace llmghidra::program
