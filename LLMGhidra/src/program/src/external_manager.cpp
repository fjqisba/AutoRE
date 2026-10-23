#include "llmghidra/program/external_manager.hpp"

#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/namespace_manager.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace llmghidra::program {

ExternalManager::ExternalManager(SymbolManager &symbols,
                                 FunctionManager &functions,
                                 NamespaceManager &namespaces)
    : symbols_(&symbols), functions_(&functions), namespaces_(&namespaces) {}

void ExternalManager::require_explicit_source(SourceType source) {
    if (source == SourceType::default_source) {
        throw std::invalid_argument(
            "external libraries require a non-default source");
    }
}

void ExternalManager::validate_name(const std::string &name) {
    if (name.empty() || std::ranges::any_of(name, [](unsigned char value) {
            return value <= 0x20 || value == 0x7f;
        })) {
        throw std::invalid_argument(
            "external library and explicit label names must be non-empty and contain no whitespace");
    }
}

std::optional<Symbol> ExternalManager::library(const std::string &name) const {
    for (const auto &candidate : symbols_->named_in_namespace(
             name, SymbolManager::global_namespace_id)) {
        if (candidate.type == SymbolType::library) return candidate;
    }
    return std::nullopt;
}

std::vector<Symbol> ExternalManager::libraries() const {
    std::vector<Symbol> result;
    for (const auto &candidate : symbols_->in_namespace(
             SymbolManager::global_namespace_id)) {
        if (candidate.type == SymbolType::library) result.push_back(candidate);
    }
    std::ranges::sort(result, {}, &Symbol::name);
    return result;
}

bool ExternalManager::contains_library(const std::string &name) const {
    return library(name).has_value();
}

Symbol ExternalManager::add_library(std::string name,
                                    SourceType source,
                                    std::optional<std::string> path) {
    validate_name(name);
    require_explicit_source(source);
    if (auto existing = library(name)) return *existing;
    for (const auto &candidate : symbols_->named_in_namespace(
             name, SymbolManager::global_namespace_id)) {
        if (candidate.type != SymbolType::library) {
            throw std::invalid_argument(
                "external library name conflicts with a global symbol");
        }
    }
    SymbolSpec spec;
    spec.name = std::move(name);
    spec.address = Address::no_address();
    spec.parent_id = SymbolManager::global_namespace_id;
    spec.type = SymbolType::library;
    spec.source = source;
    spec.library_path = std::move(path);
    return symbols_->create(std::move(spec));
}

void ExternalManager::rename_library(const std::string &old_name,
                                     std::string new_name,
                                     SourceType source) {
    validate_name(new_name);
    require_explicit_source(source);
    auto value = library(old_name);
    if (!value) throw std::out_of_range("external library does not exist");
    if (const auto duplicate = library(new_name); duplicate && duplicate->id != value->id) {
        throw std::invalid_argument("external library name already exists");
    }
    for (const auto &candidate : symbols_->named_in_namespace(
             new_name, SymbolManager::global_namespace_id)) {
        if (candidate.id != value->id) {
            throw std::invalid_argument(
                "external library name conflicts with a global symbol");
        }
    }
    symbols_->rename(value->id, std::move(new_name), source);
}

void ExternalManager::set_library_path(const std::string &name,
                                       std::optional<std::string> path,
                                       bool user_defined) {
    if (name == unknown_library_name) return;
    if (path && path->empty()) path.reset();
    auto value = library(name);
    if (!value) {
        (void)add_library(name,
                          user_defined ? SourceType::user_defined
                                       : SourceType::imported,
                          std::move(path));
        return;
    }
    value->library_path = std::move(path);
    if (user_defined) value->source = SourceType::user_defined;
    symbols_->update(*value);
}

bool ExternalManager::remove_library(const std::string &name) {
    const auto value = library(name);
    if (!value) return true;
    if (!symbols_->in_namespace(value->id).empty()) return false;
    return symbols_->remove(value->id);
}

std::optional<std::int64_t> ExternalManager::containing_library_id(
    std::int64_t namespace_id) const {
    std::set<std::int64_t> visited;
    auto current = symbols_->get(namespace_id);
    while (current) {
        if (!visited.insert(current->id).second) {
            throw std::runtime_error("external namespace hierarchy contains a cycle");
        }
        if (current->type == SymbolType::library) return current->id;
        if (current->parent_id == SymbolManager::global_namespace_id) break;
        current = symbols_->get(current->parent_id);
    }
    return std::nullopt;
}

bool ExternalManager::is_external_namespace(std::int64_t id) const {
    return containing_library_id(id).has_value();
}

Address ExternalManager::next_external_address() const {
    std::uint64_t maximum = 0;
    bool found = false;
    for (const auto &symbol : symbols_->all()) {
        if (!symbol.address.is_external_address()) continue;
        maximum = std::max(maximum, symbol.address.offset());
        found = true;
    }
    if (found && maximum == external_space()->max_offset()) {
        throw std::overflow_error("Ghidra external address space is exhausted");
    }
    return external_space()->address(found ? maximum + 1 : 1);
}

ExternalLocation ExternalManager::materialize(const Symbol &symbol) const {
    if (!symbol.address.is_external_address() ||
        (symbol.type != SymbolType::label && symbol.type != SymbolType::function) ||
        !is_external_namespace(symbol.parent_id)) {
        throw std::invalid_argument("symbol is not an external location");
    }
    ExternalLocation result;
    result.symbol = symbol;
    if (symbol.type == SymbolType::function) {
        result.function = functions_->get(symbol.id);
        if (!result.function) {
            throw std::runtime_error(
                "external function symbol has no Function Data record");
        }
    }
    return result;
}

std::optional<ExternalLocation> ExternalManager::at(
    const Address &external_address) const {
    if (!external_address.is_external_address()) {
        throw std::invalid_argument("external address required");
    }
    std::optional<ExternalLocation> result;
    for (const auto &symbol : symbols_->at(external_address)) {
        if (symbol.type != SymbolType::label &&
            symbol.type != SymbolType::function) {
            continue;
        }
        if (result) {
            throw std::runtime_error(
                "multiple external locations occupy one external address");
        }
        result = materialize(symbol);
    }
    return result;
}

std::vector<ExternalLocation> ExternalManager::named(
    std::int64_t namespace_id,
    const std::string &label) const {
    std::vector<ExternalLocation> result;
    for (const auto &symbol : symbols_->all()) {
        if ((symbol.type != SymbolType::label &&
             symbol.type != SymbolType::function) ||
            !symbol.address.is_external_address()) {
            continue;
        }
        const bool namespace_match = namespace_id == 0
            ? true
            : (symbol.parent_id == namespace_id ||
               containing_library_id(symbol.parent_id) == namespace_id);
        const bool name_match = symbol.name == label ||
            symbol.original_imported_name == label;
        if (namespace_match && name_match) result.push_back(materialize(symbol));
    }
    return result;
}

std::optional<ExternalLocation> ExternalManager::unique(
    std::int64_t namespace_id,
    const std::string &label) const {
    auto values = named(namespace_id, label);
    return values.size() == 1
        ? std::optional<ExternalLocation>(std::move(values.front()))
        : std::nullopt;
}

std::vector<ExternalLocation> ExternalManager::in_library(
    const std::string &library_name) const {
    const auto owner = library(library_name);
    if (!owner) return {};
    std::vector<ExternalLocation> result;
    for (const auto &symbol : symbols_->all()) {
        if (!symbol.address.is_external_address() ||
            (symbol.type != SymbolType::label &&
             symbol.type != SymbolType::function)) {
            continue;
        }
        if (containing_library_id(symbol.parent_id) == owner->id) {
            result.push_back(materialize(symbol));
        }
    }
    return result;
}

std::vector<ExternalLocation>
ExternalManager::locations_for_program_address(
    const std::string &external_program_address) const {
    std::vector<ExternalLocation> result;
    for (const auto &symbol : symbols_->all()) {
        if (symbol.external_program_address == external_program_address &&
            symbol.address.is_external_address() &&
            (symbol.type == SymbolType::label ||
             symbol.type == SymbolType::function)) {
            result.push_back(materialize(symbol));
        }
    }
    return result;
}

std::optional<ExternalLocation> ExternalManager::reusable_location(
    const ExternalLocationSpec &spec) const {
    for (const auto &symbol : symbols_->all()) {
        if (!symbol.address.is_external_address() ||
            (symbol.type != SymbolType::label &&
             symbol.type != SymbolType::function) ||
            symbol.parent_id != spec.parent_namespace_id) {
            continue;
        }
        const bool exact_name = spec.label &&
            (symbol.name == *spec.label ||
             symbol.original_imported_name == *spec.label);
        const bool exact_address = spec.external_program_address &&
            symbol.external_program_address == spec.external_program_address;
        const bool addressless_name_match = exact_name &&
            !symbol.external_program_address && spec.reuse_existing;
        if (exact_address || addressless_name_match ||
            (exact_name && !spec.external_program_address)) {
            return materialize(symbol);
        }
    }
    return std::nullopt;
}

ExternalLocation ExternalManager::add_location(ExternalLocationSpec spec) {
    if (spec.parent_namespace_id == SymbolManager::global_namespace_id) {
        auto unknown = library(unknown_library_name);
        if (!unknown) {
            unknown = add_library(unknown_library_name, SourceType::analysis);
        }
        spec.parent_namespace_id = unknown->id;
    }
    if (!is_external_namespace(spec.parent_namespace_id)) {
        throw std::invalid_argument(
            "external location parent must be a library or its namespace");
    }
    if (!spec.label && !spec.external_program_address) {
        throw std::invalid_argument(
            "external location requires a label or program address");
    }
    if (spec.label) validate_name(*spec.label);
    if (!spec.label) spec.source = SourceType::default_source;

    if (spec.reuse_existing) {
        if (auto existing = reusable_location(spec)) {
            auto symbol = existing->symbol;
            if (spec.label && symbol.name != *spec.label) {
                symbol.name = *spec.label;
                symbol.source = spec.source;
            }
            if (spec.external_program_address) {
                symbol.external_program_address = spec.external_program_address;
            }
            if (spec.original_imported_name) {
                symbol.original_imported_name = spec.original_imported_name;
            }
            if (spec.data_type_id) symbol.data_type_id = spec.data_type_id;
            symbols_->update(symbol);
            if (spec.function && symbol.type == SymbolType::label) {
                existing->function = functions_->promote_external_symbol(
                    symbol.id, spec.return_data_type_id,
                    spec.signature_source, spec.calling_convention_id);
                existing->symbol = existing->function->symbol;
            }
            else {
                existing->symbol = std::move(symbol);
            }
            return *existing;
        }
    }

    const auto address = next_external_address();
    const std::string persisted_name = spec.label.value_or(std::string{});
    if (spec.function) {
        FunctionSpec function_spec;
        function_spec.name = persisted_name;
        function_spec.entry = address;
        function_spec.parent_namespace_id = spec.parent_namespace_id;
        function_spec.symbol_source = spec.source;
        function_spec.return_data_type_id = spec.return_data_type_id;
        function_spec.signature_source = spec.signature_source;
        function_spec.calling_convention_id = spec.calling_convention_id;
        function_spec.external = true;
        function_spec.original_imported_name =
            std::move(spec.original_imported_name);
        function_spec.external_program_address =
            std::move(spec.external_program_address);
        auto function = functions_->create(std::move(function_spec));
        return ExternalLocation{function.symbol, std::move(function)};
    }

    SymbolSpec symbol_spec;
    symbol_spec.name = persisted_name;
    symbol_spec.address = address;
    symbol_spec.parent_id = spec.parent_namespace_id;
    symbol_spec.type = SymbolType::label;
    symbol_spec.source = spec.source;
    symbol_spec.primary = true;
    symbol_spec.data_type_id = spec.data_type_id;
    symbol_spec.original_imported_name =
        std::move(spec.original_imported_name);
    symbol_spec.external_program_address =
        std::move(spec.external_program_address);
    return ExternalLocation{symbols_->create(std::move(symbol_spec)), std::nullopt};
}

bool ExternalManager::remove_location(const Address &external_address) {
    auto location = at(external_address);
    if (!location) return false;
    return location->is_function()
        ? functions_->remove(location->symbol.id)
        : symbols_->remove(location->symbol.id);
}

} // namespace llmghidra::program
