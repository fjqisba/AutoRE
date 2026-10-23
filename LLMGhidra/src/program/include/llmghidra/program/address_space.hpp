#pragma once

#include "llmghidra/program/address.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace llmghidra::program {

enum class AddressSpaceType : std::uint8_t {
    constant = 0,
    ram = 1,
    code = 2,
    unique = 3,
    reg = 4,
    stack = 5,
    join = 6,
    other = 7,
    symbol = 9,
    external = 10,
    variable = 11,
    deleted = 13,
    unknown = 14,
    none = 15,
};

enum class AddressSpaceKind : std::uint8_t {
    generic,
    segmented_real_mode,
    segmented_protected_mode,
};

class AddressSpace final : public std::enable_shared_from_this<AddressSpace> {
public:
    static constexpr std::uint32_t id_size_mask = 0x0070;
    static constexpr std::uint32_t id_size_shift = 4;
    static constexpr std::uint32_t id_type_mask = 0x000f;
    static constexpr std::uint32_t id_unique_shift = 7;

    struct Config {
        std::string name;
        std::uint32_t size_bits{};
        std::uint32_t addressable_unit_size{1};
        AddressSpaceType type{AddressSpaceType::ram};
        std::uint32_t unique{};
        std::optional<bool> show_space_name;
        bool has_mapped_registers{};
        AddressSpaceKind kind{AddressSpaceKind::generic};
    };

    [[nodiscard]] static std::shared_ptr<AddressSpace> create(Config config);
    [[nodiscard]] static std::shared_ptr<AddressSpace> create_overlay(
        std::string name,
        std::shared_ptr<const AddressSpace> base_space,
        std::uint32_t unique,
        std::vector<std::pair<std::uint64_t, std::uint64_t>> regions,
        std::string ordered_key = {});
    [[nodiscard]] static std::shared_ptr<AddressSpace> create_segmented(
        std::string name,
        std::uint32_t unique);
    [[nodiscard]] static std::shared_ptr<AddressSpace> create_protected_segmented(
        std::string name,
        std::uint32_t unique);

    [[nodiscard]] const std::string &name() const noexcept;
    [[nodiscard]] std::uint32_t size() const noexcept;
    [[nodiscard]] std::uint32_t addressable_unit_size() const noexcept;
    [[nodiscard]] std::uint32_t pointer_size() const noexcept;
    [[nodiscard]] AddressSpaceType type() const noexcept;
    [[nodiscard]] std::uint32_t unique() const noexcept;
    [[nodiscard]] std::int32_t space_id() const noexcept;
    [[nodiscard]] bool has_signed_offset() const noexcept;
    [[nodiscard]] bool show_space_name() const noexcept;
    [[nodiscard]] bool has_mapped_registers() const noexcept;

    [[nodiscard]] bool is_memory_space() const noexcept;
    [[nodiscard]] bool is_loaded_memory_space() const noexcept;
    [[nodiscard]] bool is_non_loaded_memory_space() const noexcept;
    [[nodiscard]] bool is_register_space() const noexcept;
    [[nodiscard]] bool is_stack_space() const noexcept;
    [[nodiscard]] bool is_unique_space() const noexcept;
    [[nodiscard]] bool is_constant_space() const noexcept;
    [[nodiscard]] bool is_variable_space() const noexcept;
    [[nodiscard]] bool is_external_space() const noexcept;
    [[nodiscard]] bool is_overlay_space() const noexcept;
    [[nodiscard]] bool is_segmented_space() const noexcept;

    [[nodiscard]] std::uint64_t min_offset() const noexcept;
    [[nodiscard]] std::uint64_t max_offset() const noexcept;
    [[nodiscard]] Address min_address() const;
    [[nodiscard]] Address max_address() const;
    [[nodiscard]] std::uint64_t addressable_word_offset(std::uint64_t byte_offset) const noexcept;
    [[nodiscard]] std::uint64_t truncate_offset(std::uint64_t byte_offset) const noexcept;
    [[nodiscard]] std::uint64_t truncate_addressable_word_offset(std::uint64_t word_offset) const noexcept;
    [[nodiscard]] std::uint64_t make_valid_offset(std::uint64_t byte_offset) const;
    [[nodiscard]] bool is_valid_range(std::uint64_t byte_offset, std::uint64_t length) const noexcept;

    [[nodiscard]] Address address(std::uint64_t byte_offset) const;
    [[nodiscard]] Address address_signed(std::int64_t byte_offset) const;
    [[nodiscard]] Address address(std::uint64_t offset, bool addressable_word_offset) const;
    [[nodiscard]] Address truncated_address(std::uint64_t offset, bool addressable_word_offset) const;
    [[nodiscard]] Address address_in_this_space(std::uint64_t byte_offset) const;
    [[nodiscard]] Address segmented_address(std::uint16_t segment,
                                            std::uint16_t segment_offset) const;
    [[nodiscard]] std::optional<Address> address_in_segment(
        std::uint64_t flat_offset,
        std::uint16_t preferred_segment) const;
    [[nodiscard]] std::uint16_t default_segment(std::uint64_t flat_offset) const;
    [[nodiscard]] std::uint16_t segment_offset(std::uint64_t flat_offset,
                                               std::uint16_t segment) const;
    [[nodiscard]] std::optional<Address> parse_address(const std::string &text,
                                                       bool case_sensitive = true) const;

    [[nodiscard]] Address add_wrap(const Address &address, std::int64_t displacement) const;
    [[nodiscard]] Address subtract_wrap(const Address &address, std::int64_t displacement) const;
    [[nodiscard]] Address add_no_wrap(const Address &address, std::int64_t displacement) const;
    [[nodiscard]] Address subtract_no_wrap(const Address &address, std::int64_t displacement) const;
    [[nodiscard]] std::int64_t subtract(const Address &lhs, const Address &rhs) const;
    [[nodiscard]] bool is_successor(const Address &first, const Address &second) const noexcept;

    [[nodiscard]] bool contains_overlay_offset(std::uint64_t offset) const noexcept;
    [[nodiscard]] const std::vector<std::pair<std::uint64_t, std::uint64_t>> &overlay_regions() const noexcept;
    void set_overlay_regions(
        std::vector<std::pair<std::uint64_t, std::uint64_t>> regions);
    [[nodiscard]] std::shared_ptr<const AddressSpace> physical_space() const;
    [[nodiscard]] std::shared_ptr<const AddressSpace> overlayed_space() const noexcept;
    [[nodiscard]] Address overlay_address(const Address &address) const;
    [[nodiscard]] Address translate_overlay_address(const Address &address,
                                                    bool force_translation = false) const;
    [[nodiscard]] const std::string &ordered_key() const noexcept;

    void set_show_space_name(bool show) noexcept;
    void set_has_mapped_registers(bool present) noexcept;
    void rename_overlay(std::string new_name);

    [[nodiscard]] bool equivalent(const AddressSpace &other) const noexcept;
    [[nodiscard]] std::strong_ordering compare(const AddressSpace &other) const noexcept;

private:
    explicit AddressSpace(Config config);
    AddressSpace(std::string name,
                 std::shared_ptr<const AddressSpace> base_space,
                 std::uint32_t unique,
                 std::vector<std::pair<std::uint64_t, std::uint64_t>> regions,
                 std::string ordered_key);

    void validate_and_initialize();
    void normalize_overlay_regions();
    void require_same_space(const Address &address) const;
    [[nodiscard]] Address unchecked_address(std::uint64_t offset) const;

    std::string name_;
    std::uint32_t size_bits_{};
    std::uint32_t unit_size_{1};
    AddressSpaceType type_{AddressSpaceType::ram};
    AddressSpaceKind kind_{AddressSpaceKind::generic};
    std::uint32_t unique_{};
    std::int32_t space_id_{};
    bool signed_offset_{};
    bool show_name_{};
    bool mapped_registers_{};
    std::uint64_t min_offset_{};
    std::uint64_t max_offset_{};
    // Zero denotes a complete 2^64-byte span, matching Ghidra's sentinel.
    std::uint64_t byte_span_{};
    std::uint64_t word_mask_{};
    std::shared_ptr<const AddressSpace> base_space_;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> overlay_regions_;
    std::string ordered_key_;
};

[[nodiscard]] const std::shared_ptr<AddressSpace> &other_space();
[[nodiscard]] const std::shared_ptr<AddressSpace> &external_space();
[[nodiscard]] const std::shared_ptr<AddressSpace> &variable_space();
[[nodiscard]] const std::shared_ptr<AddressSpace> &hash_space();
[[nodiscard]] const std::shared_ptr<AddressSpace> &default_register_space();

} // namespace llmghidra::program
