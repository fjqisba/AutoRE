#include "llmghidra/program/legacy_program_upgrade.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/comment_manager.hpp"
#include "llmghidra/program/data_type_manager.hpp"
#include "llmghidra/program/function_manager.hpp"
#include "llmghidra/program/legacy_function_upgrade.hpp"
#include "llmghidra/program/legacy_variable_storage_upgrade.hpp"
#include "llmghidra/program/namespace_manager.hpp"
#include "llmghidra/program/persistent_address_map.hpp"
#include "llmghidra/program/program_architecture.hpp"
#include "llmghidra/program/reference_manager.hpp"
#include "llmghidra/program/symbol_manager.hpp"
#include "llmghidra/program/variable_storage_manager.hpp"

#include <algorithm>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace llmghidra::program {
namespace {

struct LegacyTypeLayout {
    std::int64_t id{};
    std::int32_t length{1};
};

[[nodiscard]] std::string default_function_name(const Address &address) {
    std::string text = address.to_string();
    std::replace(text.begin(), text.end(), ':', '_');
    return "FUN_" + text;
}

[[nodiscard]] bool is_stack_parameter(std::int32_t offset,
                                      std::int32_t parameter_start) noexcept {
    return (offset >= 0) == (parameter_start >= 0);
}

[[nodiscard]] std::string unused_variable_name(FunctionManager &functions,
                                               std::int64_t function_id,
                                               std::string name) {
    if (name.empty()) name = "param";
    const auto in_use = [&](const std::string &candidate) {
        const auto parameter = std::ranges::any_of(
            functions.parameters(function_id), [&](const FunctionVariable &value) {
                return value.symbol.name == candidate;
            });
        return parameter || std::ranges::any_of(
            functions.local_variables(function_id),
            [&](const FunctionVariable &value) {
                return value.symbol.name == candidate;
            });
    };
    while (in_use(name)) name += ".dup";
    return name;
}

[[nodiscard]] LegacyTypeLayout legacy_type_layout(
    DataTypeManager &data_types,
    const ProgramArchitecture &architecture,
    std::int64_t requested_id) {
    if (requested_id == 0 || !data_types.contains_data_type(requested_id)) {
        return {};
    }
    try {
        const auto metrics = data_types.data_type_metrics(
            requested_id, architecture.data_organization);
        if (!metrics.dynamic && metrics.length > 0) {
            return {requested_id, metrics.length};
        }
    }
    catch (const std::exception &) {
        // OldFunctionManager substitutes DataType.DEFAULT when a historical
        // type is missing, deleted, zero-length, or otherwise unusable.
    }
    return {};
}

[[nodiscard]] VariableStorage stack_storage(
    const AddressFactory &factory,
    std::int32_t offset,
    std::int32_t length) {
    const auto space = factory.stack_space();
    if (!space) throw std::runtime_error("program architecture has no stack space");
    return VariableStorage::mapped(
        factory, {{space->address(static_cast<std::uint64_t>(
                       static_cast<std::int64_t>(offset))),
                   length}});
}

} // namespace

LegacyProgramUpgradeCoordinator::LegacyProgramUpgradeCoordinator(
    std::shared_ptr<db::DatabaseHandle> database,
    PersistentAddressMap &address_map,
    SymbolManager &symbols,
    NamespaceManager &namespaces,
    FunctionManager &functions,
    DataTypeManager &data_types,
    CommentManager &comments,
    VariableStorageManager &variable_storage,
    ReferenceManager &references,
    const ProgramArchitecture *architecture)
    : database_(std::move(database)), address_map_(&address_map),
      symbols_(&symbols), namespaces_(&namespaces), functions_(&functions),
      data_types_(&data_types), comments_(&comments),
      variable_storage_(&variable_storage), references_(&references),
      architecture_(architecture) {
    if (!database_) {
        throw std::invalid_argument(
            "legacy Program upgrade coordinator requires a database");
    }
}

void LegacyProgramUpgradeCoordinator::upgrade() {
    database_->check_transaction();
    upgrade_variable_symbols();
    if (LegacyFunctionUpgrade::present(database_)) {
        if (!architecture_) {
            throw std::runtime_error(
                "pre-Function-Data upgrade requires the selected native "
                "language/compiler architecture binding");
        }
        LegacyFunctionUpgrade legacy(database_, *address_map_);
        upgrade_functions(legacy);
        legacy.delete_source_tables();
    }
    if (symbols_->has_deferred_legacy_local_symbols()) {
        symbols_->finalize_legacy_local_symbols(*namespaces_);
    }
}

void LegacyProgramUpgradeCoordinator::upgrade_variable_symbols() {
    const bool has_legacy_storage =
        LegacyVariableStorageUpgrade::present(database_);
    const auto snapshot = symbols_->all();
    const bool has_old_namespace_variables = std::ranges::any_of(
        snapshot, [](const Symbol &symbol) {
            const bool variable = symbol.type == SymbolType::parameter ||
                                  symbol.type == SymbolType::local_variable ||
                                  symbol.type == SymbolType::global_variable;
            return variable && !symbol.address.is_variable_address();
        });
    if (!has_legacy_storage && !has_old_namespace_variables) return;
    if (!architecture_) {
        throw std::runtime_error(
            "legacy variable storage upgrade requires the selected native "
            "language/compiler architecture binding");
    }

    // Rewriting from semantic References first strips obsolete namespace bits
    // from register/stack destinations while preserving every reference field.
    references_->normalize_address_encodings();

    std::unique_ptr<LegacyVariableStorageUpgrade> legacy;
    if (has_legacy_storage) {
        legacy = std::make_unique<LegacyVariableStorageUpgrade>(
            database_, *address_map_);
    }
    const auto &factory = *address_map_->factory();
    for (auto symbol : snapshot) {
        if (symbol.type != SymbolType::parameter &&
            symbol.type != SymbolType::local_variable &&
            symbol.type != SymbolType::global_variable) {
            continue;
        }

        Address physical = Address::no_address();
        if (symbol.address.is_variable_address()) {
            if (!legacy || symbol.address.offset() >
                               static_cast<std::uint64_t>(
                                   std::numeric_limits<std::int64_t>::max())) {
                continue;
            }
            const auto source = legacy->record(
                static_cast<std::int64_t>(symbol.address.offset()));
            if (source) physical = source->storage_address;
        }
        else if (symbol.address.is_register_address() ||
                 symbol.address.is_stack_address()) {
            physical = symbol.address;
        }
        else {
            continue;
        }

        if (symbol.address.is_variable_address()) {
            if (physical.is_valid()) {
                (void)references_->move_references_to(
                    symbol.address, physical);
            }
            else {
                (void)references_->remove_all_to(symbol.address);
            }
        }

        VariableStorage storage = VariableStorage::bad();
        const auto type = legacy_type_layout(
            *data_types_, *architecture_, symbol.data_type_id.value_or(0));
        if (physical.is_valid()) {
            try {
                storage = VariableStorage::mapped(
                    factory, {{physical, type.length}});
            }
            catch (const std::exception &) {
                storage = VariableStorage::bad();
            }
        }
        const auto variable_address =
            variable_storage_->address_for(storage, true);
        if (!variable_address) {
            throw std::runtime_error(
                "failed to allocate current Variable Storage address");
        }
        symbol.address = *variable_address;
        symbol.data_type_id = type.id;
        symbols_->update(symbol);
    }
    if (legacy) legacy->delete_source_table();
}

void LegacyProgramUpgradeCoordinator::upgrade_functions(
    LegacyFunctionUpgrade &legacy) {
    const auto snapshot = legacy.records();
    const auto &factory = *address_map_->factory();
    for (const auto &source : snapshot) {
        std::string function_name = default_function_name(source.entry);
        if (const auto primary = symbols_->primary_at(source.entry);
            primary && primary->source != SourceType::default_source) {
            function_name = primary->name;
            if (!symbols_->remove(primary->id)) {
                throw std::runtime_error(
                    "legacy function primary symbol disappeared during upgrade");
            }
        }

        FunctionSpec spec;
        spec.name = std::move(function_name);
        spec.entry = source.entry;
        spec.parent_namespace_id = NamespaceManager::global_namespace_id;
        spec.symbol_source = SourceType::user_defined;
        spec.return_data_type_id = legacy_type_layout(
            *data_types_, *architecture_, source.return_data_type_id).id;
        spec.signature_source = SignatureSource::analysis;
        spec.body = source.body;
        auto function = functions_->create(std::move(spec));
        function.custom_parameter_storage = true;
        function.stack_purge = source.stack_depth;
        function.stack_return_offset = source.stack_return_offset;
        function.stack_local_size = source.stack_local_size;
        functions_->update(function);

        comments_->set(source.entry, CommentType::repeatable,
                       source.repeatable_comment);

        std::int32_t ordinal = 0;
        for (const auto &parameter : source.register_parameters) {
            const auto type = legacy_type_layout(
                *data_types_, *architecture_, parameter.data_type_id);
            const auto native_register = architecture_->register_named(
                parameter.register_name);
            if (!native_register || !native_register->address.is_register_address() ||
                type.length > native_register->size) {
                continue;
            }
            try {
                FunctionVariableSpec variable;
                variable.name = unused_variable_name(
                    *functions_, function.symbol_id, parameter.name);
                variable.data_type_id = type.id;
                variable.storage = VariableStorage::mapped(
                    factory, {{native_register->address, type.length}});
                variable.source = SourceType::user_defined;
                variable.comment = parameter.comment;
                (void)functions_->add_parameter(
                    function.symbol_id, ordinal++, std::move(variable));
            }
            catch (const std::invalid_argument &) {
                // Fixed upstream behavior discards register parameters whose
                // historical register or storage is no longer valid.
            }
            catch (const AddressError &) {
                // A register whose persisted extent no longer fits is BAD.
            }
        }

        std::vector<const LegacyStackVariableRecord *> stack_parameters;
        std::vector<const LegacyStackVariableRecord *> stack_locals;
        for (const auto &variable : source.stack_variables) {
            (is_stack_parameter(variable.offset,
                                source.stack_parameter_offset)
                 ? stack_parameters
                 : stack_locals)
                .push_back(&variable);
        }
        const auto ascending_offset = [](const auto *left, const auto *right) {
            return left->offset != right->offset
                       ? left->offset < right->offset
                       : left->record_id < right->record_id;
        };
        std::ranges::sort(stack_parameters, ascending_offset);
        std::ranges::sort(stack_locals, ascending_offset);
        if (source.stack_parameter_offset < 0) {
            std::ranges::reverse(stack_parameters);
        }
        if (source.stack_parameter_offset >= 0) {
            std::ranges::reverse(stack_locals);
        }

        for (const auto *parameter : stack_parameters) {
            const auto type = legacy_type_layout(
                *data_types_, *architecture_, parameter->data_type_id);
            try {
                FunctionVariableSpec variable;
                variable.name = unused_variable_name(
                    *functions_, function.symbol_id, parameter->name);
                variable.data_type_id = type.id;
                variable.storage = stack_storage(
                    factory, parameter->offset, type.length);
                variable.source = SourceType::user_defined;
                variable.comment = parameter->comment;
                (void)functions_->add_parameter(
                    function.symbol_id, ordinal++, std::move(variable));
            }
            catch (const std::invalid_argument &) {
                // Upstream discards BAD_STORAGE parameters during this upgrade.
            }
            catch (const AddressError &) {
                // Upstream discards out-of-range stack parameters as BAD.
            }
        }

        for (const auto *local : stack_locals) {
            const auto type = legacy_type_layout(
                *data_types_, *architecture_, local->data_type_id);
            VariableStorage storage = VariableStorage::bad();
            try {
                storage = stack_storage(factory, local->offset, type.length);
            }
            catch (const std::invalid_argument &) {
                // OldStackFrameDB retained an invalid local as BAD_STORAGE.
            }
            catch (const AddressError &) {
                // OldStackFrameDB retained an out-of-range local as BAD_STORAGE.
            }
            FunctionVariableSpec variable;
            variable.name = unused_variable_name(
                *functions_, function.symbol_id, local->name.empty()
                                                    ? std::string("local")
                                                    : local->name);
            variable.data_type_id = type.id;
            variable.storage = std::move(storage);
            variable.source = SourceType::user_defined;
            variable.comment = local->comment;
            (void)functions_->add_local_variable(
                function.symbol_id, 0, std::move(variable));
        }
    }
}

} // namespace llmghidra::program
