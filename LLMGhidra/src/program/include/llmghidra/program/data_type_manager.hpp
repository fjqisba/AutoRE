#pragma once

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/program/persistent_address_map.hpp"
#include "llmghidra/program/language.hpp"
#include "llmghidra/program/string_map.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace llmghidra::program {

struct ProgramArchitecture;

// Values are persisted in the high byte of every Ghidra DataTypeManagerDB ID.
enum class DataTypeKind : std::uint8_t {
    builtin = 0,
    composite = 1,
    component = 2,
    array = 3,
    pointer = 4,
    typedef_type = 5,
    function_definition = 6,
    function_parameter = 7,
    enumeration = 8,
    bitfield = 9,
};

enum class DataTypeTable : std::uint8_t {
    categories,
    builtins,
    arrays,
    pointers,
    typedefs,
    composites,
    components,
    function_definitions,
    function_parameters,
    enumerations,
    enumeration_values,
    calling_conventions,
    source_archives,
    parent_child,
    default_settings,
    default_setting_names,
    instance_settings,
    instance_setting_names,
};

struct CategoryRecord {
    std::int64_t id{};
    std::string name;
    std::int64_t parent_id{};
};

struct DataTypeSetting {
    std::int64_t association_id{};
    std::string name;
    std::int64_t long_value{};
    std::optional<std::string> string_value;
};

struct DataTypeProvenance {
    std::int64_t source_archive_id{};
    std::int64_t universal_id{};
    std::int64_t source_sync_time{};
    std::int64_t last_change_time{};
};

// Persisted ordinals match ghidra.program.model.data.ArchiveType.
enum class SourceArchiveType : std::uint8_t {
    built_in = 0,
    file = 1,
    project = 2,
    program = 3,
    temporary = 4,
};

struct SourceArchiveRecord {
    std::int64_t id{};
    std::optional<std::string> domain_file_id;
    std::optional<std::string> name;
    SourceArchiveType type{SourceArchiveType::file};
    std::int64_t last_sync_time{};
    bool dirty{};
};

struct BuiltinDataType {
    std::int64_t id{};
    std::string name;
    std::string class_name;
    std::int64_t category_id{};
};

struct ArrayDataType {
    std::int64_t id{};
    std::int64_t element_type_id{};
    std::int32_t element_count{};
    std::int32_t element_length{};
    std::int64_t category_id{};
};

struct PointerDataType {
    std::int64_t id{};
    std::int64_t referenced_type_id{};
    std::int64_t category_id{};
    std::int32_t length{-1};
};

struct TypedefDataType {
    std::int64_t id{};
    std::int64_t referenced_type_id{};
    std::uint16_t flags{};
    std::string name;
    std::int64_t category_id{};
    DataTypeProvenance provenance;
};

struct EnumValue {
    std::int64_t record_id{};
    std::string name;
    std::int64_t value{};
    std::optional<std::string> comment;
};

struct EnumDataType {
    std::int64_t id{};
    std::string name;
    std::optional<std::string> comment;
    std::int64_t category_id{};
    std::uint8_t size{1};
    DataTypeProvenance provenance;
    std::vector<EnumValue> values;
};

struct CompositeComponent {
    std::int64_t id{};
    std::int64_t data_type_id{};
    std::int32_t offset{};
    std::optional<std::string> field_name;
    std::optional<std::string> comment;
    std::int32_t length{};
    std::int32_t ordinal{};

    bool operator==(const CompositeComponent &) const = default;
};

struct CompositeDataType {
    static constexpr std::int32_t default_packing = 0;
    static constexpr std::int32_t no_packing = -1;
    static constexpr std::int32_t default_alignment = 0;
    static constexpr std::int32_t machine_alignment = -1;

    std::int64_t id{};
    std::string name;
    std::optional<std::string> comment;
    bool is_union{};
    std::int64_t category_id{};
    std::int32_t length{};
    std::int32_t alignment{1};
    DataTypeProvenance provenance;
    std::int32_t packing{no_packing};
    std::int32_t minimum_alignment{default_alignment};
    std::vector<CompositeComponent> components;
};

struct FunctionDefinitionParameter {
    std::int64_t id{};
    std::int64_t data_type_id{};
    std::string name;
    std::optional<std::string> comment;
    std::int32_t ordinal{};
    std::int32_t data_type_length{};
};

struct FunctionDefinitionDataType {
    std::int64_t id{};
    std::string name;
    std::optional<std::string> comment;
    std::int64_t category_id{};
    std::int64_t return_type_id{};
    bool variadic{};
    bool no_return{};
    std::uint8_t calling_convention_id{};
    DataTypeProvenance provenance;
    std::vector<FunctionDefinitionParameter> parameters;
};

enum class BitFieldBaseKind : std::uint8_t {
    none = 0,
    typedef_type = 1,
    enumeration = 2,
    integer = 3,
};

struct BitFieldDataType {
    std::int64_t id{};
    std::int64_t base_type_id{};
    BitFieldBaseKind base_kind{BitFieldBaseKind::none};
    std::uint8_t declared_bit_size{};
    std::uint8_t bit_offset{};
    bool extra_storage{};
};

using DataType = std::variant<BuiltinDataType, ArrayDataType, PointerDataType,
                              TypedefDataType, EnumDataType, CompositeDataType,
                              FunctionDefinitionDataType, BitFieldDataType>;

enum class DataTypeUpdateMode : std::uint8_t {
    local_change,
    source_sync,
    preserve_timestamps,
};

enum class DataTypeConflictPolicy : std::uint8_t {
    rename_and_add,
    use_existing,
    replace_existing,
    replace_empty_composites_or_rename_and_add,
};

// Language-dependent semantic size used by composite packing, function
// storage construction and Listing.  A negative length denotes a dynamic or
// factory type whose concrete size must come from its use site.
struct DataTypeMetrics {
    std::int32_t length{-1};
    std::int32_t aligned_length{-1};
    std::int32_t alignment{1};
    bool dynamic{true};
    bool zero_length{};
};

// Native current-schema adapter layer for ProgramDataTypeManager. The semantic
// graph is built on these exact Ghidra tables rather than on a replacement
// container, preserving Program DB and .gdt cross-open compatibility.
class DataTypeManager final {
public:
    static constexpr int manager_database_version = 2;
    static constexpr std::int64_t root_category_id = 0;
    static constexpr std::int64_t local_archive_id = 0;
    static constexpr std::int64_t builtin_archive_id = 1;
    static constexpr unsigned kind_shift = 56;

    DataTypeManager(std::shared_ptr<db::DatabaseHandle> database,
                    ProgramOpenMode mode,
                    bool create,
                    PersistentAddressMap *address_map = nullptr,
                    const ProgramArchitecture *architecture = nullptr);

    [[nodiscard]] static std::int64_t make_id(DataTypeKind kind,
                                              std::int64_t table_key) noexcept;
    [[nodiscard]] static DataTypeKind kind(std::int64_t id) noexcept;
    [[nodiscard]] static std::uint64_t table_key(std::int64_t id) noexcept;

    [[nodiscard]] std::shared_ptr<db::Table> table(DataTypeTable table) const;
    [[nodiscard]] std::unique_ptr<db::Record> record(DataTypeTable table,
                                                     std::int64_t id) const;
    [[nodiscard]] std::vector<std::unique_ptr<db::Record>> records(
        DataTypeTable table) const;
    [[nodiscard]] std::vector<std::int64_t> record_ids_by_index(
        DataTypeTable table,
        std::size_t column,
        const db::Field &value) const;
    [[nodiscard]] std::unique_ptr<db::Record> new_record(DataTypeTable table);
    void put(DataTypeTable table, db::Record &record);
    [[nodiscard]] bool erase(DataTypeTable table, std::int64_t id);

    [[nodiscard]] CategoryRecord create_category(std::string name,
                                                 std::int64_t parent_id);
    [[nodiscard]] std::optional<CategoryRecord> category(std::int64_t id) const;
    [[nodiscard]] std::vector<CategoryRecord> child_categories(
        std::int64_t parent_id) const;
    void update_category(CategoryRecord category);
    [[nodiscard]] bool remove_category(std::int64_t id);

    [[nodiscard]] std::uint8_t calling_convention_id(const std::string &name,
                                                     bool create);
    [[nodiscard]] std::optional<std::string> calling_convention_name(
        std::uint8_t id) const;

    [[nodiscard]] SourceArchiveRecord create_source_archive(
        SourceArchiveRecord value);
    [[nodiscard]] std::optional<SourceArchiveRecord> source_archive(
        std::int64_t id) const;
    [[nodiscard]] std::vector<SourceArchiveRecord> source_archives() const;
    void update_source_archive(SourceArchiveRecord value);
    [[nodiscard]] bool remove_source_archive(std::int64_t id);
    void replace_source_archive(std::int64_t old_id,
                                SourceArchiveRecord replacement);
    [[nodiscard]] DataType associate_data_type_with_archive(
        std::int64_t data_type_id,
        std::int64_t source_archive_id,
        std::int64_t source_universal_id,
        std::int64_t source_change_time = 0);
    [[nodiscard]] DataType disassociate_data_type(std::int64_t data_type_id);

    void set_setting(bool instance, DataTypeSetting setting);
    [[nodiscard]] std::vector<DataTypeSetting> settings(
        bool instance,
        std::int64_t association_id) const;
    void clear_settings(bool instance, std::int64_t association_id);

    [[nodiscard]] BuiltinDataType create_builtin(BuiltinDataType value);
    [[nodiscard]] ArrayDataType create_array(ArrayDataType value);
    [[nodiscard]] PointerDataType create_pointer(PointerDataType value);
    [[nodiscard]] TypedefDataType create_typedef(TypedefDataType value);
    [[nodiscard]] EnumDataType create_enum(EnumDataType value);
    [[nodiscard]] CompositeDataType create_composite(CompositeDataType value);
    [[nodiscard]] FunctionDefinitionDataType create_function_definition(
        FunctionDefinitionDataType value);
    [[nodiscard]] BitFieldDataType create_bitfield(BitFieldDataType value) const;
    [[nodiscard]] DataType update_data_type(
        DataType value,
        DataTypeUpdateMode mode = DataTypeUpdateMode::local_change);
    [[nodiscard]] DataType update_data_type(
        DataType value,
        const DataOrganization &organization,
        Endian endian,
        DataTypeUpdateMode mode = DataTypeUpdateMode::local_change);
    [[nodiscard]] DataType resolve_data_type(
        DataType value,
        DataTypeConflictPolicy policy = DataTypeConflictPolicy::rename_and_add);
    [[nodiscard]] DataType resolve_data_type_graph(
        DataType root,
        const std::function<std::optional<DataType>(std::int64_t)> &source_lookup,
        const std::function<std::int64_t(std::int64_t)> &category_mapper,
        const std::function<std::int64_t(std::int64_t)> &archive_mapper,
        DataTypeConflictPolicy policy = DataTypeConflictPolicy::rename_and_add);
    [[nodiscard]] DataType replace_data_type(std::int64_t replaced_id,
                                             std::int64_t replacement_id);
    [[nodiscard]] std::optional<DataType> data_type(std::int64_t id) const;
    [[nodiscard]] std::optional<DataType> data_type_named(
        std::int64_t category_id,
        const std::string &name) const;
    [[nodiscard]] std::optional<DataType> data_type_by_universal_id(
        std::int64_t source_archive_id,
        std::int64_t universal_id) const;
    [[nodiscard]] std::vector<DataType> all_data_types() const;
    [[nodiscard]] bool contains_data_type(std::int64_t id) const;
    [[nodiscard]] bool equivalent(const DataType &left,
                                  const DataType &right) const;
    [[nodiscard]] bool depends_on(std::int64_t parent_id,
                                  std::int64_t candidate_ancestor_id) const;
    [[nodiscard]] std::string unused_conflict_name(
        std::int64_t category_id,
        const std::string &name) const;
    [[nodiscard]] bool remove_data_type(std::int64_t id);
    [[nodiscard]] std::vector<std::int64_t> parent_data_types(
        std::int64_t child_id) const;
    [[nodiscard]] std::vector<std::int64_t> child_data_types(
        std::int64_t parent_id) const;

    // Layout is explicitly parameterized by the selected compiler spec and
    // language endian.  ProgramDB can exist before LanguageRegistry is bound,
    // so using a hidden host-ABI default here would corrupt cross-language
    // databases.
    [[nodiscard]] DataTypeMetrics data_type_metrics(
        std::int64_t id,
        const DataOrganization &organization) const;
    [[nodiscard]] CompositeDataType layout_composite(
        CompositeDataType value,
        const DataOrganization &organization,
        Endian endian) const;
    [[nodiscard]] CompositeDataType repack_composite(
        std::int64_t id,
        const DataOrganization &organization,
        Endian endian,
        DataTypeUpdateMode mode = DataTypeUpdateMode::local_change);
    [[nodiscard]] CompositeDataType insert_component(
        std::int64_t composite_id,
        std::size_t ordinal,
        CompositeComponent component,
        const DataOrganization &organization,
        Endian endian);
    [[nodiscard]] CompositeDataType delete_components(
        std::int64_t composite_id,
        std::vector<std::size_t> ordinals,
        const DataOrganization &organization,
        Endian endian);
    [[nodiscard]] CompositeDataType replace_component(
        std::int64_t composite_id,
        std::size_t ordinal,
        CompositeComponent replacement,
        const DataOrganization &organization,
        Endian endian);
    [[nodiscard]] CompositeDataType reorder_component(
        std::int64_t composite_id,
        std::size_t from_ordinal,
        std::size_t to_ordinal,
        const DataOrganization &organization,
        Endian endian);
    [[nodiscard]] CompositeDataType set_composite_packing(
        std::int64_t composite_id,
        std::int32_t packing,
        std::int32_t minimum_alignment,
        const DataOrganization &organization,
        Endian endian);
    void propagate_data_type_layout(
        std::int64_t changed_id,
        const DataOrganization &organization,
        Endian endian);

    // ProgramDB extends DataTypeManagerDB replacement into Listing, Symbols and
    // Functions. Managers already migrated to C++ register here; later managers
    // join the same callback without changing datatype replacement semantics.
    void set_external_replacement_handler(
        std::function<void(std::int64_t, std::int64_t)> handler);
    void set_external_deletion_handler(
        std::function<void(std::int64_t)> handler);

    // Complete historical source-archive replacement only after ProgramDB has
    // installed Symbol/Function datatype rewrite callbacks.
    void finish_legacy_source_archive_upgrade();

    void language_changed(const ProgramArchitecture &architecture);
    void rebind_architecture(const ProgramArchitecture *architecture) noexcept;

    [[nodiscard]] StringMap &properties() noexcept;
    [[nodiscard]] const StringMap &properties() const noexcept;
    void invalidate_caches() noexcept;

private:
    struct TableSlot;

    [[nodiscard]] static std::vector<std::unique_ptr<TableSlot>>
    table_descriptors();

    [[nodiscard]] TableSlot &slot(DataTypeTable table);
    [[nodiscard]] const TableSlot &slot(DataTypeTable table) const;
    [[nodiscard]] std::int64_t allocate_key(TableSlot &slot);
    [[nodiscard]] std::int16_t setting_name_index(bool instance,
                                                  const std::string &name,
                                                  bool create);
    [[nodiscard]] std::optional<std::string> setting_name(
        bool instance,
        std::int16_t index) const;
    void create_tables();
    void open_tables();
    void require_mutation() const;
    void require_category(std::int64_t id) const;
    void require_data_type(std::int64_t id) const;
    void require_unique_name(std::int64_t category_id,
                             const std::string &name,
                             std::optional<std::int64_t> except_id = std::nullopt) const;
    void require_source_archive(std::int64_t id) const;
    void validate_data_type(const DataType &value,
                            std::optional<std::int64_t> updating_id) const;
    [[nodiscard]] DataType create_data_type(DataType value);
    [[nodiscard]] std::vector<DataType> data_types_by_base_name(
        std::int64_t category_id,
        const std::string &name) const;
    [[nodiscard]] static std::int64_t data_type_id(const DataType &value) noexcept;
    [[nodiscard]] static std::optional<std::int64_t> data_type_category(
        const DataType &value) noexcept;
    [[nodiscard]] static std::optional<std::string> data_type_name(
        const DataType &value);
    static void set_data_type_id(DataType &value, std::int64_t id) noexcept;
    static void set_data_type_name(DataType &value, std::string name);
    static void apply_update_timestamp(DataType &value, DataTypeUpdateMode mode);
    void record_manager_change(const DataType *changed,
                               bool dirty_source_archive);
    [[nodiscard]] bool equivalent_impl(
        const DataType &left,
        const DataType &right,
        std::vector<std::pair<std::int64_t, std::int64_t>> &active) const;
    [[nodiscard]] bool dependency_reaches(
        std::int64_t current_id,
        std::int64_t target_id,
        std::vector<std::int64_t> &active) const;
    [[nodiscard]] DataTypeMetrics data_type_metrics_impl(
        std::int64_t id,
        const DataOrganization &organization,
        std::vector<std::int64_t> &active) const;
    void rewrite_bitfield_base(DataType &parent,
                               std::int64_t replaced_id,
                               std::int64_t replacement_id) const;
    void deduplicate_automatic_data_types(std::int64_t preferred_id);
    void add_dependency(std::int64_t parent_id, std::int64_t child_id);
    void remove_dependencies(std::int64_t parent_id);

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    const ProgramArchitecture *architecture_{};
    ProgramOpenMode mode_{};
    std::unique_ptr<StringMap> properties_;
    std::vector<std::unique_ptr<TableSlot>> tables_;
    std::function<void(std::int64_t, std::int64_t)> external_replacement_handler_;
    std::function<void(std::int64_t)> external_deletion_handler_;
    bool deduplicating_automatic_types_{};
};

} // namespace llmghidra::program
