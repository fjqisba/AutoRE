#pragma once

#include <compare>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace llmghidra::program {

class AddressSpace;

class AddressError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class AddressFormatError final : public AddressError {
public:
    using AddressError::AddressError;
};

class AddressOutOfBoundsError final : public AddressError {
public:
    using AddressError::AddressError;
};

class AddressOverflowError final : public AddressError {
public:
    using AddressError::AddressError;
};

// A portable unsigned 128-bit count. Address sets may contain several complete
// 64-bit spaces, so a uint64_t is not sufficient even though each address is.
struct AddressCount {
    std::uint64_t high{};
    std::uint64_t low{};

    [[nodiscard]] bool is_zero() const noexcept;
    [[nodiscard]] bool fits_uint64() const noexcept;
    [[nodiscard]] std::uint64_t to_uint64() const;
    [[nodiscard]] std::string to_string() const;

    AddressCount &operator+=(AddressCount other) noexcept;
    AddressCount &operator-=(AddressCount other);

    friend AddressCount operator+(AddressCount lhs, AddressCount rhs) noexcept {
        return lhs += rhs;
    }
    friend AddressCount operator-(AddressCount lhs, AddressCount rhs) {
        return lhs -= rhs;
    }
    friend auto operator<=>(const AddressCount &, const AddressCount &) = default;
};

class Address {
public:
    Address() = default;

    [[nodiscard]] static Address no_address() noexcept;
    [[nodiscard]] static Address external_entry_address();
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] bool is_external_entry_address() const noexcept;

    [[nodiscard]] const std::shared_ptr<const AddressSpace> &space() const noexcept;
    [[nodiscard]] std::uint64_t offset() const noexcept;
    [[nodiscard]] std::int64_t signed_offset() const noexcept;
    [[nodiscard]] std::uint64_t addressable_word_offset() const;
    [[nodiscard]] std::uint32_t pointer_size() const;
    [[nodiscard]] std::optional<std::uint16_t> segment() const noexcept;
    [[nodiscard]] std::optional<std::uint16_t> segment_offset() const noexcept;
    [[nodiscard]] Address normalize_segment(std::uint16_t segment) const;

    [[nodiscard]] Address add_wrap(std::int64_t displacement) const;
    [[nodiscard]] Address subtract_wrap(std::int64_t displacement) const;
    [[nodiscard]] Address add_no_wrap(std::int64_t displacement) const;
    [[nodiscard]] Address subtract_no_wrap(std::int64_t displacement) const;
    [[nodiscard]] std::int64_t subtract(const Address &other) const;
    [[nodiscard]] std::optional<Address> next() const;
    [[nodiscard]] std::optional<Address> previous() const;
    [[nodiscard]] Address physical_address() const;

    [[nodiscard]] bool is_memory_address() const;
    [[nodiscard]] bool is_loaded_memory_address() const;
    [[nodiscard]] bool is_non_loaded_memory_address() const;
    [[nodiscard]] bool is_register_address() const;
    [[nodiscard]] bool is_stack_address() const;
    [[nodiscard]] bool is_unique_address() const;
    [[nodiscard]] bool is_constant_address() const;
    [[nodiscard]] bool is_variable_address() const;
    [[nodiscard]] bool is_external_address() const;

    [[nodiscard]] std::string to_string(bool show_space, std::uint32_t min_digits = 8) const;
    [[nodiscard]] std::string to_string() const;

    [[nodiscard]] bool same_space(const Address &other) const noexcept;
    [[nodiscard]] std::strong_ordering compare(const Address &other) const noexcept;

    friend bool operator==(const Address &lhs, const Address &rhs) noexcept;
    friend std::strong_ordering operator<=>(const Address &lhs, const Address &rhs) noexcept {
        return lhs.compare(rhs);
    }

private:
    friend class AddressSpace;

    Address(std::shared_ptr<const AddressSpace> space,
            std::uint64_t offset,
            std::optional<std::uint16_t> segment = std::nullopt) noexcept;

    std::shared_ptr<const AddressSpace> space_;
    std::uint64_t offset_{};
    std::optional<std::uint16_t> segment_;
};

} // namespace llmghidra::program
