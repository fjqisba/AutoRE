#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace llmghidra::program {

class AddressFactory;
struct ProgramArchitecture;

enum class Endian {
    little,
    big,
};

struct CompilerSpecDescription {
    std::string id;
    std::string name;
    std::filesystem::path specification;
};

struct AddressSpaceTruncation {
    std::string space;
    // Pointer/address size in bytes, matching Ghidra's <truncate_space size>.
    std::uint32_t size{};
};

struct LanguageDescription {
    std::string id;
    std::string processor;
    Endian endian{Endian::little};
    Endian instruction_endian{Endian::little};
    std::uint32_t size{};
    std::string variant;
    std::int32_t version{};
    std::int32_t minor_version{};
    std::string description;
    bool deprecated{};
    std::filesystem::path sleigh_file;
    std::filesystem::path processor_specification;
    std::vector<CompilerSpecDescription> compiler_specs;
    std::vector<AddressSpaceTruncation> address_space_truncations;
    std::unordered_map<std::string, std::vector<std::string>> external_names;
};

struct DataOrganization {
    std::uint32_t absolute_max_alignment{};
    std::uint32_t machine_alignment{8};
    std::uint32_t default_alignment{1};
    std::uint32_t default_pointer_alignment{4};
    std::uint32_t pointer_size{4};
    std::uint32_t pointer_shift{};
    std::uint32_t char_size{1};
    std::uint32_t wchar_size{2};
    std::uint32_t short_size{2};
    std::uint32_t integer_size{4};
    std::uint32_t long_size{4};
    std::uint32_t long_long_size{8};
    std::uint32_t float_size{4};
    std::uint32_t double_size{8};
    std::uint32_t long_double_size{8};
    bool char_signed{true};
    // These are the three independent controls persisted by Ghidra's
    // BitFieldPackingImpl.  Byte/bit traversal order is a Language property
    // and must not be conflated with the Microsoft allocation convention.
    bool bitfield_use_ms_convention{false};
    bool bitfield_type_alignment_enabled{true};
    std::uint32_t bitfield_zero_length_boundary{0};
    std::map<std::uint32_t, std::uint32_t> size_alignment{
        {1, 1}, {2, 2}, {4, 4}, {8, 8}};

    [[nodiscard]] std::uint32_t alignment_for_size(std::uint32_t size) const noexcept;
    [[nodiscard]] bool effective_bitfield_type_alignment() const noexcept;
    [[nodiscard]] std::uint32_t effective_zero_length_bitfield_boundary() const noexcept;
};

struct StorageLocation {
    enum class Kind {
        register_name,
        address,
        join,
    };

    Kind kind{Kind::register_name};
    std::string name;
    std::string space;
    std::uint64_t offset{};
    std::uint32_t size{};
    std::vector<StorageLocation> pieces;
};

struct ParameterEntry {
    std::uint32_t minimum_size{};
    std::uint32_t maximum_size{};
    std::uint32_t alignment{};
    std::string metatype;
    bool extension{};
    StorageLocation storage;
    std::vector<std::string> allocation_rules;
};

struct PrototypeModel {
    std::string name;
    std::int64_t extrapop{};
    std::int64_t stack_shift{};
    bool has_this{};
    bool constructor{};
    std::vector<ParameterEntry> inputs;
    std::vector<ParameterEntry> outputs;
    std::vector<std::string> input_rules;
    std::vector<std::string> output_rules;
    std::vector<std::string> unaffected_registers;
    std::vector<std::string> killed_by_call_registers;
    std::vector<std::string> likely_trash_registers;
};

struct CompilerSpec {
    CompilerSpecDescription description;
    DataOrganization data_organization;
    std::string stack_pointer_register;
    std::string stack_space;
    bool stack_grows_negative{true};
    std::vector<StorageLocation> return_address;
    std::vector<PrototypeModel> prototypes;
    std::string default_prototype;
    std::string evaluation_current_prototype;
    std::string evaluation_called_prototype;
    std::unordered_map<std::string, std::string> properties;
    std::vector<std::unordered_map<std::string, std::string>> context_settings;
    std::vector<std::unordered_map<std::string, std::string>> tracked_settings;
};

struct ProcessorSpec {
    std::string program_counter_register;
    std::optional<std::string> segmented_address_space;
    std::optional<std::string> segmented_address_type;
    std::unordered_map<std::string, std::string> properties;
    std::unordered_map<std::string, std::string> register_groups;
    std::unordered_map<std::string, std::vector<std::uint32_t>> register_lane_sizes;
    std::vector<std::unordered_map<std::string, std::string>> context_settings;
    std::vector<std::unordered_map<std::string, std::string>> tracked_settings;
};

// Native representation of Ghidra's SimpleLanguageTranslator .trans format.
// A null mapped space means <delete_space>; register mappings are explicit
// overrides on top of the default same-name mapping.
struct LanguageTranslationDescription {
    std::filesystem::path source;
    std::string from_language_id;
    std::int32_t from_version{};
    std::string to_language_id;
    std::int32_t to_version{};
    std::unordered_map<std::string, std::optional<std::string>> address_spaces;
    std::unordered_map<std::string, std::string> registers;
    std::unordered_map<std::string, std::uint64_t> context_values;
    std::unordered_map<std::string, std::string> compiler_specs;
    bool clear_all_context{};
    std::optional<std::string> post_upgrade_handler;
};

// Parsed form of Ghidra's historical *.lang snapshots.  These files are not
// executable processor specifications; they preserve precisely the address
// spaces and register construction needed to translate persisted ProgramDB
// addresses, register context, and VariableStorage into a current language.
struct LegacyLanguageDescription {
    std::filesystem::path source;
    std::string id;
    std::vector<std::string> aliases;
    std::string processor;
    std::string variant;
    Endian endian{Endian::little};
    std::int32_t version{};
    std::vector<CompilerSpecDescription> compiler_specs;
    std::shared_ptr<AddressFactory> address_factory;
    std::shared_ptr<const ProgramArchitecture> architecture;
};

class LanguageRegistry {
public:
    explicit LanguageRegistry(std::filesystem::path processor_pack_root);

    void discover();
    [[nodiscard]] const std::filesystem::path &root() const noexcept;
    [[nodiscard]] const std::vector<LanguageDescription> &languages() const noexcept;
    [[nodiscard]] const std::vector<LanguageTranslationDescription> &
    translations() const noexcept;
    [[nodiscard]] const std::vector<LegacyLanguageDescription> &
    legacy_languages() const noexcept;
    [[nodiscard]] const LegacyLanguageDescription &legacy_language(
        const std::string &id,
        std::int32_t version) const;
    [[nodiscard]] const LanguageDescription &language(const std::string &id) const;
    [[nodiscard]] std::vector<const LanguageDescription *> query(
        std::optional<std::string> processor = std::nullopt,
        std::optional<Endian> endian = std::nullopt,
        std::optional<std::uint32_t> size = std::nullopt) const;
    [[nodiscard]] CompilerSpec load_compiler_spec(const std::string &language_id,
                                                  const std::string &compiler_spec_id) const;
    [[nodiscard]] ProcessorSpec load_processor_spec(const std::string &language_id) const;
    [[nodiscard]] std::vector<const LanguageTranslationDescription *>
    translations_from(const std::string &language_id,
                      std::int32_t version) const;

private:
    std::filesystem::path root_;
    std::vector<LanguageDescription> languages_;
    std::vector<LanguageTranslationDescription> translations_;
    std::vector<LegacyLanguageDescription> legacy_languages_;
    std::unordered_map<std::string, std::size_t> by_id_;
};

} // namespace llmghidra::program
