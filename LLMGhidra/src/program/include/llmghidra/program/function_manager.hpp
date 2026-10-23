#pragma once

#include "llmghidra/program/address_set.hpp"
#include "llmghidra/program/symbol_manager.hpp"
#include "llmghidra/program/variable_storage.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Record;
class Schema;
class Table;
}

namespace llmghidra::program {

class DataTypeManager;
class NamespaceManager;
class VariableStorageManager;
class AddressFactory;
class LanguageTranslator;

enum class SignatureSource : std::uint8_t {
    analysis = 0,
    user_defined = 1,
    default_source = 2,
    imported = 3,
    ai = 4,
};

struct Function {
    std::int64_t symbol_id{};
    Symbol symbol;
    std::int64_t return_data_type_id{};
    std::int32_t stack_purge{0x7fffffff};
    std::int32_t stack_return_offset{};
    std::int32_t stack_local_size{};
    bool variadic{};
    bool inline_hint{};
    bool no_return{};
    bool custom_parameter_storage{};
    SignatureSource signature_source{SignatureSource::default_source};
    std::uint8_t calling_convention_id{};
    std::optional<std::string> return_storage;
    AddressSet body;
};

struct FunctionSpec {
    std::string name;
    Address entry;
    std::int64_t parent_namespace_id{};
    SourceType symbol_source{SourceType::analysis};
    std::int64_t return_data_type_id{};
    SignatureSource signature_source{SignatureSource::default_source};
    std::uint8_t calling_convention_id{};
    bool external{};
    std::optional<std::string> original_imported_name;
    std::optional<std::string> external_program_address;
    AddressSet body;
};

struct FunctionTag {
    std::int64_t id{};
    std::string name;
    std::optional<std::string> comment;
};

struct FunctionVariable {
    Symbol symbol;
    VariableStorage storage;
};

struct FunctionVariableSpec {
    std::string name;
    std::int64_t data_type_id{};
    VariableStorage storage;
    SourceType source{SourceType::analysis};
    std::optional<std::string> comment;
};

class FunctionManager final {
public:
    static constexpr int schema_version = 3;
    static constexpr std::int32_t unknown_stack_depth_change = 0x7fffffff;
    static constexpr std::uint8_t unknown_calling_convention_id = 0;
    static constexpr std::uint8_t default_calling_convention_id = 1;

    FunctionManager(std::shared_ptr<db::DatabaseHandle> database,
                    SymbolManager &symbols,
                    DataTypeManager &data_types,
                    VariableStorageManager &variable_storage,
                    NamespaceManager &namespaces,
                    ProgramOpenMode mode,
                    bool create,
                    bool create_missing_for_legacy_upgrade = false);

    [[nodiscard]] Function create(FunctionSpec spec);
    [[nodiscard]] Function promote_external_symbol(
        std::int64_t symbol_id,
        std::int64_t return_data_type_id,
        SignatureSource signature_source = SignatureSource::default_source,
        std::uint8_t calling_convention_id = default_calling_convention_id);
    [[nodiscard]] std::optional<Function> get(std::int64_t symbol_id) const;
    [[nodiscard]] std::optional<Function> at(const Address &entry) const;
    [[nodiscard]] std::vector<Function> all() const;
    [[nodiscard]] std::size_t size() const;

    [[nodiscard]] std::optional<std::int64_t> thunk_target(
        std::int64_t function_id) const;
    [[nodiscard]] std::vector<std::int64_t> thunks_to(
        std::int64_t referenced_function_id) const;
    void set_thunk(std::int64_t function_id,
                   std::optional<std::int64_t> referenced_function_id);

    [[nodiscard]] FunctionTag create_tag(
        std::string name,
        std::optional<std::string> comment = std::nullopt);
    [[nodiscard]] std::optional<FunctionTag> tag(std::int64_t id) const;
    [[nodiscard]] std::optional<FunctionTag> tag(const std::string &name) const;
    [[nodiscard]] std::vector<FunctionTag> tags() const;
    void update_tag(FunctionTag value);
    [[nodiscard]] bool remove_tag(std::int64_t id);
    [[nodiscard]] bool apply_tag(std::int64_t function_id, std::int64_t tag_id);
    [[nodiscard]] bool unapply_tag(std::int64_t function_id, std::int64_t tag_id);
    [[nodiscard]] std::vector<FunctionTag> function_tags(
        std::int64_t function_id) const;

    [[nodiscard]] std::optional<FunctionVariable> variable(
        std::int64_t symbol_id) const;
    [[nodiscard]] std::vector<FunctionVariable> parameters(
        std::int64_t function_id) const;
    [[nodiscard]] std::vector<FunctionVariable> local_variables(
        std::int64_t function_id) const;
    [[nodiscard]] FunctionVariable add_parameter(
        std::int64_t function_id,
        std::int32_t ordinal,
        FunctionVariableSpec spec);
    [[nodiscard]] FunctionVariable add_local_variable(
        std::int64_t function_id,
        std::int32_t first_use_offset,
        FunctionVariableSpec spec);
    void update_variable(FunctionVariable value);
    void reorder_parameter(std::int64_t symbol_id, std::int32_t ordinal);
    [[nodiscard]] bool remove_variable(std::int64_t symbol_id);

    void update(const Function &function);
    void set_body(std::int64_t function_id, AddressSet body);
    [[nodiscard]] bool remove(std::int64_t symbol_id);
    [[nodiscard]] std::size_t remove_overlapping_range(
        const Address &start,
        const Address &end);
    [[nodiscard]] std::size_t replace_data_type(std::int64_t replaced_id,
                                                std::int64_t replacement_id);
    void set_language(const AddressFactory &new_address_factory,
                      const LanguageTranslator &translator);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> current_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> thunk_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> tag_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> tag_mapping_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_schema(int version);
    [[nodiscard]] std::unique_ptr<db::Record> translate_legacy_record(
        const db::Record &record) const;
    [[nodiscard]] Function decode(const db::Record &record) const;
    [[nodiscard]] std::unique_ptr<db::Record> encode(const Function &function) const;
    void validate(const Function &function) const;
    void require_mutation() const;
    [[nodiscard]] std::shared_ptr<db::Table> require_tag_table();
    [[nodiscard]] std::shared_ptr<db::Table> require_tag_mapping_table();
    void remove_function_tag_mappings(std::int64_t function_id);
    [[nodiscard]] std::int64_t effective_function_id(
        std::int64_t function_id) const;
    [[nodiscard]] FunctionVariable decode_variable(const Symbol &symbol) const;
    void require_unique_variable_name(std::int64_t function_id,
                                      const std::string &name,
                                      std::int64_t except_symbol_id = 0) const;
    void normalize_parameter_ordinals(std::int64_t function_id,
                                      std::optional<std::int64_t> moved_symbol_id,
                                      std::optional<std::int32_t> requested_ordinal);

    std::shared_ptr<db::DatabaseHandle> database_;
    SymbolManager *symbols_{};
    DataTypeManager *data_types_{};
    VariableStorageManager *variable_storage_{};
    NamespaceManager *namespaces_{};
    std::shared_ptr<db::Table> table_;
    std::shared_ptr<db::Table> thunk_table_;
    std::shared_ptr<db::Table> tag_table_;
    std::shared_ptr<db::Table> tag_mapping_table_;
    std::shared_ptr<const db::Schema> schema_;
    int stored_schema_version_{schema_version};
    ProgramOpenMode mode_{};
};

} // namespace llmghidra::program
