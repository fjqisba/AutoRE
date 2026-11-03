#pragma once

#include "llmghidra/program/address.hpp"

#include <optional>
#include <string>

namespace llmghidra::program {

class AddressRange {
public:
    AddressRange(Address first, Address second);
    AddressRange(Address start, AddressCount length);

    [[nodiscard]] const Address &min_address() const noexcept;
    [[nodiscard]] const Address &max_address() const noexcept;
    [[nodiscard]] const std::shared_ptr<const AddressSpace> &space() const noexcept;
    [[nodiscard]] AddressCount length() const noexcept;
    [[nodiscard]] bool contains(const Address &address) const noexcept;
    [[nodiscard]] bool intersects(const AddressRange &other) const noexcept;
    [[nodiscard]] std::optional<AddressRange> intersection(const AddressRange &other) const;
    [[nodiscard]] int compare(const Address &address) const noexcept;
    [[nodiscard]] std::string to_string() const;

    friend bool operator==(const AddressRange &, const AddressRange &) = default;
    friend std::strong_ordering operator<=>(const AddressRange &lhs,
                                            const AddressRange &rhs) noexcept;

private:
    Address min_;
    Address max_;
};

} // namespace llmghidra::program
