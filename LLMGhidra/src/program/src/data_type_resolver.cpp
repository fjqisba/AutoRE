#include "llmghidra/program/data_type_manager.hpp"

#include <algorithm>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>

namespace llmghidra::program {
namespace {

void reset_foreign_child_ids(DataType &value) {
    std::visit(
        [](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, EnumDataType>) {
                for (auto &entry : item.values) entry.record_id = 0;
            }
            else if constexpr (std::is_same_v<T, CompositeDataType>) {
                for (auto &entry : item.components) entry.id = 0;
            }
            else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                for (auto &entry : item.parameters) entry.id = 0;
            }
        },
        value);
}

void remap_owner_ids(
    DataType &value,
    const std::function<std::int64_t(std::int64_t)> &category_mapper,
    const std::function<std::int64_t(std::int64_t)> &archive_mapper) {
    std::visit(
        [&](auto &item) {
            using T = std::decay_t<decltype(item)>;
            if constexpr (!std::is_same_v<T, BitFieldDataType>) {
                item.category_id = category_mapper(item.category_id);
            }
            if constexpr (std::is_same_v<T, TypedefDataType> ||
                          std::is_same_v<T, EnumDataType> ||
                          std::is_same_v<T, CompositeDataType> ||
                          std::is_same_v<T, FunctionDefinitionDataType>) {
                item.provenance.source_archive_id =
                    archive_mapper(item.provenance.source_archive_id);
            }
        },
        value);
}

[[nodiscard]] bool is_recursive_container(const DataType &value) noexcept {
    return std::holds_alternative<CompositeDataType>(value) ||
           std::holds_alternative<FunctionDefinitionDataType>(value);
}

} // namespace

DataType DataTypeManager::resolve_data_type_graph(
    DataType root,
    const std::function<std::optional<DataType>(std::int64_t)> &source_lookup,
    const std::function<std::int64_t(std::int64_t)> &category_mapper,
    const std::function<std::int64_t(std::int64_t)> &archive_mapper,
    DataTypeConflictPolicy policy) {
    require_mutation();
    if (!source_lookup || !category_mapper || !archive_mapper) {
        throw std::invalid_argument("datatype graph resolver requires all mapping callbacks");
    }

    std::unordered_map<std::int64_t, std::int64_t> resolved_ids;
    std::unordered_map<std::int64_t, DataType> source_values;
    std::unordered_map<std::int64_t, bool> completed;
    std::unordered_map<std::int64_t, std::int64_t> cross_kind_replacements;
    std::unordered_map<std::int64_t, std::string> requested_names;

    const auto load_source = [&](std::int64_t source_id) -> DataType {
        if (const auto found = source_values.find(source_id);
            found != source_values.end()) {
            return found->second;
        }
        const auto loaded = source_lookup(source_id);
        if (!loaded) {
            throw std::out_of_range(
                "source datatype graph contains an unresolved datatype ID");
        }
        source_values.emplace(source_id, *loaded);
        return *loaded;
    };

    const auto find_equivalent_family_member = [&](const DataType &value,
                                                    std::int64_t except_id)
        -> std::optional<DataType> {
        const auto category_id = data_type_category(value);
        const auto name = data_type_name(value);
        if (!category_id || !name) return std::nullopt;
        for (const auto &candidate : data_types_by_base_name(*category_id, *name)) {
            if (data_type_id(candidate) != except_id && equivalent(candidate, value)) {
                return candidate;
            }
        }
        return std::nullopt;
    };

    std::function<DataType(DataType)> resolve_node;
    resolve_node = [&](DataType source) -> DataType {
        const auto source_id = data_type_id(source);
        if (source_id > 0) {
            if (const auto found = resolved_ids.find(source_id);
                found != resolved_ids.end() && completed[source_id]) {
                const auto resolved = data_type(found->second);
                if (!resolved) {
                    throw std::runtime_error("resolved datatype graph node disappeared");
                }
                return *resolved;
            }
        }

        remap_owner_ids(source, category_mapper, archive_mapper);
        reset_foreign_child_ids(source);

        // Composite and function-definition placeholders establish an ID before
        // their children are traversed.  A Pointer can then refer to that ID,
        // providing the same legal recursion break as Ghidra's postPointerResolve
        // queue without persisting an invalid temporary child reference.
        if (is_recursive_container(source) && source_id > 0 &&
            !resolved_ids.contains(source_id)) {
            DataType placeholder = source;
            std::visit(
                [](auto &item) {
                    using T = std::decay_t<decltype(item)>;
                    if constexpr (std::is_same_v<T, CompositeDataType>) {
                        item.components.clear();
                        item.length = 0;
                        item.alignment = 1;
                    }
                    else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                        item.parameters.clear();
                        item.return_type_id = 0;
                    }
                },
                placeholder);
            set_data_type_id(placeholder, 0);

            const auto placeholder_category = data_type_category(placeholder);
            const auto placeholder_name = data_type_name(placeholder);
            std::optional<DataType> existing_by_identity;
            std::visit(
                [&](const auto &item) {
                    using T = std::decay_t<decltype(item)>;
                    if constexpr (std::is_same_v<T, CompositeDataType> ||
                                  std::is_same_v<T, FunctionDefinitionDataType>) {
                        existing_by_identity = data_type_by_universal_id(
                            item.provenance.source_archive_id,
                            item.provenance.universal_id);
                    }
                },
                placeholder);

            DataType stored_placeholder;
            bool use_existing_without_update = false;
            if (existing_by_identity) {
                if (existing_by_identity->index() != placeholder.index()) {
                    throw std::invalid_argument(
                        "source universal ID resolves to a different datatype kind");
                }
                stored_placeholder = *existing_by_identity;
                use_existing_without_update =
                    policy == DataTypeConflictPolicy::use_existing;
            }
            else if (placeholder_category && placeholder_name) {
                auto existing = data_type_named(*placeholder_category, *placeholder_name);
                if (existing && policy == DataTypeConflictPolicy::use_existing) {
                    stored_placeholder = *existing;
                    use_existing_without_update = true;
                }
                else if (existing &&
                         policy == DataTypeConflictPolicy::replace_existing &&
                         existing->index() == placeholder.index()) {
                    stored_placeholder = *existing;
                }
                else if (existing &&
                         policy == DataTypeConflictPolicy::replace_existing) {
                    cross_kind_replacements[source_id] = data_type_id(*existing);
                    requested_names[source_id] = *placeholder_name;
                    set_data_type_name(
                        placeholder,
                        unused_conflict_name(*placeholder_category, *placeholder_name));
                    stored_placeholder = create_data_type(std::move(placeholder));
                }
                else if (existing &&
                         policy == DataTypeConflictPolicy::
                                       replace_empty_composites_or_rename_and_add &&
                         std::holds_alternative<CompositeDataType>(*existing) &&
                         std::holds_alternative<CompositeDataType>(placeholder) &&
                         std::get<CompositeDataType>(*existing).components.empty() &&
                         std::get<CompositeDataType>(*existing).is_union ==
                             std::get<CompositeDataType>(placeholder).is_union) {
                    stored_placeholder = *existing;
                }
                else {
                    set_data_type_name(
                        placeholder,
                        unused_conflict_name(*placeholder_category, *placeholder_name));
                    stored_placeholder = create_data_type(std::move(placeholder));
                }
            }
            else {
                stored_placeholder = create_data_type(std::move(placeholder));
            }

            resolved_ids[source_id] = data_type_id(stored_placeholder);
            if (const auto stored_name = data_type_name(stored_placeholder)) {
                // A recursive placeholder may have been assigned a conflict
                // suffix before its children existed.  Preserve that selected
                // path when the complete definition is written in-place.
                set_data_type_name(source, *stored_name);
            }
            if (use_existing_without_update) {
                completed[source_id] = true;
                return stored_placeholder;
            }
        }

        const auto resolve_reference = [&](std::int64_t referenced_id) -> std::int64_t {
            if (referenced_id <= 0) return referenced_id;
            if (const auto found = resolved_ids.find(referenced_id);
                found != resolved_ids.end()) {
                return found->second;
            }
            auto resolved = resolve_node(load_source(referenced_id));
            return data_type_id(resolved);
        };

        std::visit(
            [&](auto &item) {
                using T = std::decay_t<decltype(item)>;
                if constexpr (std::is_same_v<T, ArrayDataType>) {
                    item.element_type_id = resolve_reference(item.element_type_id);
                }
                else if constexpr (std::is_same_v<T, PointerDataType> ||
                                   std::is_same_v<T, TypedefDataType>) {
                    item.referenced_type_id = resolve_reference(item.referenced_type_id);
                }
                else if constexpr (std::is_same_v<T, CompositeDataType>) {
                    for (auto &component : item.components) {
                        component.data_type_id = resolve_reference(component.data_type_id);
                    }
                }
                else if constexpr (std::is_same_v<T, FunctionDefinitionDataType>) {
                    item.return_type_id = resolve_reference(item.return_type_id);
                    for (auto &parameter : item.parameters) {
                        parameter.data_type_id = resolve_reference(parameter.data_type_id);
                    }
                }
                else if constexpr (std::is_same_v<T, BitFieldDataType>) {
                    item.base_type_id = resolve_reference(item.base_type_id);
                    item.base_kind = BitFieldBaseKind::none;
                }
            },
            source);

        DataType result;
        if (source_id > 0 && resolved_ids.contains(source_id)) {
            set_data_type_id(source, resolved_ids[source_id]);
            result = update_data_type(std::move(source),
                                      DataTypeUpdateMode::source_sync);
        }
        else {
            set_data_type_id(source, 0);
            result = resolve_data_type(std::move(source), policy);
            if (source_id > 0) resolved_ids[source_id] = data_type_id(result);
        }
        if (source_id > 0) completed[source_id] = true;

        if (source_id > 0 && cross_kind_replacements.contains(source_id)) {
            const auto replaced_id = cross_kind_replacements[source_id];
            auto replaced = data_type(replaced_id);
            if (!replaced) {
                throw std::runtime_error(
                    "cross-kind conflict target disappeared during graph resolve");
            }
            const auto category_id = data_type_category(*replaced);
            if (!category_id) {
                throw std::logic_error("named conflict has no category");
            }
            set_data_type_name(
                *replaced,
                unused_conflict_name(*category_id, requested_names[source_id]));
            (void)update_data_type(std::move(*replaced),
                                   DataTypeUpdateMode::local_change);
            set_data_type_name(result, requested_names[source_id]);
            result = update_data_type(std::move(result),
                                      DataTypeUpdateMode::source_sync);
            result = replace_data_type(replaced_id, data_type_id(result));
            resolved_ids[source_id] = data_type_id(result);
        }

        // Nested pointer resolution can reveal that a newly materialized
        // conflict is equivalent to an older family member.  Collapse it only
        // after the full recursive definition is present.
        if (const auto candidate =
                find_equivalent_family_member(result, data_type_id(result))) {
            const auto result_id = data_type_id(result);
            const auto candidate_id = data_type_id(*candidate);
            if (!depends_on(candidate_id, result_id)) {
                result = replace_data_type(result_id, candidate_id);
                if (source_id > 0) resolved_ids[source_id] = candidate_id;
            }
        }
        return result;
    };

    const auto root_id = data_type_id(root);
    if (root_id > 0) source_values.emplace(root_id, root);
    return resolve_node(std::move(root));
}

} // namespace llmghidra::program
