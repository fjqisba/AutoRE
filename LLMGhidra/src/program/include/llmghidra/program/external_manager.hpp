#pragma once

#include "llmghidra/program/function_manager.hpp"
#include "llmghidra/program/symbol_manager.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::program {

class NamespaceManager;

struct ExternalLocation {
    Symbol symbol;
    std::optional<Function> function;

    [[nodiscard]] bool is_function() const noexcept {
        return function.has_value();
    }
};

struct ExternalLocationSpec {
    std::int64_t parent_namespace_id{};
    std::optional<std::string> label;
    std::optional<std::string> external_program_address;
    std::optional<std::string> original_imported_name;
    std::optional<std::int64_t> data_type_id;
    SourceType source{SourceType::analysis};
    bool function{};
    bool reuse_existing{true};
    std::int64_t return_data_type_id{};
    SignatureSource signature_source{SignatureSource::default_source};
    std::uint8_t calling_convention_id{
        FunctionManager::default_calling_convention_id};
};

// ExternalManagerDB has no current-schema table of its own. Ghidra persists
// libraries and locations in Symbols V4 and external functions in Function
// Data V3. This manager owns the cross-manager invariants and address
// allocation that would otherwise be scattered across callers.
class ExternalManager final {
public:
    static constexpr const char *unknown_library_name = "<EXTERNAL>";

    ExternalManager(SymbolManager &symbols,
                    FunctionManager &functions,
                    NamespaceManager &namespaces);

    [[nodiscard]] Symbol add_library(
        std::string name,
        SourceType source = SourceType::analysis,
        std::optional<std::string> path = std::nullopt);
    [[nodiscard]] std::optional<Symbol> library(const std::string &name) const;
    [[nodiscard]] std::vector<Symbol> libraries() const;
    [[nodiscard]] bool contains_library(const std::string &name) const;
    void rename_library(const std::string &old_name,
                        std::string new_name,
                        SourceType source);
    void set_library_path(const std::string &name,
                          std::optional<std::string> path,
                          bool user_defined);
    [[nodiscard]] bool remove_library(const std::string &name);

    [[nodiscard]] ExternalLocation add_location(ExternalLocationSpec spec);
    [[nodiscard]] std::optional<ExternalLocation> at(
        const Address &external_address) const;
    [[nodiscard]] std::optional<ExternalLocation> unique(
        std::int64_t namespace_id,
        const std::string &label) const;
    [[nodiscard]] std::vector<ExternalLocation> named(
        std::int64_t namespace_id,
        const std::string &label) const;
    [[nodiscard]] std::vector<ExternalLocation> in_library(
        const std::string &library_name) const;
    [[nodiscard]] std::vector<ExternalLocation> locations_for_program_address(
        const std::string &external_program_address) const;
    [[nodiscard]] bool remove_location(const Address &external_address);

private:
    [[nodiscard]] bool is_external_namespace(std::int64_t id) const;
    [[nodiscard]] std::optional<std::int64_t> containing_library_id(
        std::int64_t namespace_id) const;
    [[nodiscard]] Address next_external_address() const;
    [[nodiscard]] ExternalLocation materialize(const Symbol &symbol) const;
    [[nodiscard]] std::optional<ExternalLocation> reusable_location(
        const ExternalLocationSpec &spec) const;
    static void require_explicit_source(SourceType source);
    static void validate_name(const std::string &name);

    SymbolManager *symbols_{};
    FunctionManager *functions_{};
    NamespaceManager *namespaces_{};
};

} // namespace llmghidra::program
