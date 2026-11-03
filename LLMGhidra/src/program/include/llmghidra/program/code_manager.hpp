#pragma once

#include "llmghidra/program/address_set.hpp"
#include "llmghidra/program/comment_manager.hpp"
#include "llmghidra/program/listing_manager.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace llmghidra::program {

class MemoryManager;
class ReferenceManager;
class RegisterContextManager;

enum class CodeUnitKind : std::uint8_t {
    instruction,
    defined_data,
    undefined_data,
};

struct CodeUnit {
    CodeUnitKind kind{CodeUnitKind::undefined_data};
    Address address;
    std::uint64_t length{1};
    std::optional<InstructionRecord> instruction;
    std::optional<DefinedDataRecord> data;
};

// Semantic coordinator corresponding to ProgramDB CodeManager. ListingManager
// owns its four exact storage tables; this layer coordinates memory, comments,
// references, processor-context locking and higher-level code-unit queries.
class CodeManager final {
public:
    CodeManager(ListingManager &listing,
                MemoryManager &memory,
                CommentManager &comments,
                ReferenceManager &references,
                RegisterContextManager &register_context);

    [[nodiscard]] InstructionRecord create_instruction(
        const Address &address,
        std::span<const std::uint8_t> prototype_bytes,
        const Address &prototype_source,
        bool in_delay_slot = false,
        std::uint8_t flags = 0,
        std::optional<std::string> base_context_value = std::nullopt);
    [[nodiscard]] DefinedDataRecord create_data(
        const Address &address,
        std::int64_t data_type_id);

    [[nodiscard]] std::optional<CodeUnit> at(const Address &address) const;
    [[nodiscard]] std::optional<CodeUnit> containing(
        const Address &address,
        bool use_prototype_length = false) const;
    [[nodiscard]] std::optional<CodeUnit> before(const Address &address) const;
    [[nodiscard]] std::optional<CodeUnit> after(const Address &address) const;
    [[nodiscard]] std::vector<CodeUnit> code_units(bool forward = true) const;
    [[nodiscard]] std::size_t instruction_count() const;
    [[nodiscard]] std::size_t defined_data_count() const;

    [[nodiscard]] std::optional<std::string> comment(
        const Address &address,
        CommentType type) const;
    void set_comment(const Address &address,
                     CommentType type,
                     std::optional<std::string> value);

    void set_fallthrough(const Address &instruction,
                         std::optional<Address> destination);
    [[nodiscard]] std::optional<Address> fallthrough(
        const Address &instruction) const;

    [[nodiscard]] AddressSet undefined_ranges(
        const AddressSet &within,
        bool initialized_memory_only = true) const;
    [[nodiscard]] std::optional<CodeUnit> undefined_at(
        const Address &address) const;

    void clear_code_units(const Address &start,
                          const Address &end,
                          bool clear_context);
    void clear_comments(const Address &start, const Address &end);
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);
    void activate_context_locking() noexcept;
    void memory_changed(const Address &start, const Address &end) noexcept;

private:
    [[nodiscard]] static CodeUnit from_instruction(
        InstructionRecord value);
    [[nodiscard]] static CodeUnit from_data(DefinedDataRecord value);
    [[nodiscard]] bool is_initialized_memory(const Address &address) const;
    [[nodiscard]] std::vector<CodeUnit> sorted_units() const;
    void check_context_write(const Address &start, const Address &end) const;

    ListingManager *listing_{};
    MemoryManager *memory_{};
    CommentManager *comments_{};
    ReferenceManager *references_{};
    RegisterContextManager *register_context_{};
    bool context_locking_enabled_{};
};

} // namespace llmghidra::program
