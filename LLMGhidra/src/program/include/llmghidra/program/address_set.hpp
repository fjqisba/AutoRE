#pragma once

#include "llmghidra/program/address_range.hpp"

#include <cstddef>
#include <optional>
#include <vector>

namespace llmghidra::program {

class AddressSet {
public:
    class AddressIterator {
    public:
        [[nodiscard]] bool has_next() const noexcept;
        [[nodiscard]] std::optional<Address> next();

    private:
        friend class AddressSet;
        AddressIterator(const AddressSet &set, std::optional<Address> start, bool forward);

        const AddressSet *set_{};
        std::size_t range_index_{};
        std::optional<Address> current_;
        bool forward_{true};
    };

    AddressSet() = default;
    explicit AddressSet(Address address);
    explicit AddressSet(AddressRange range);
    AddressSet(Address first, Address second);

    void clear() noexcept;
    void add(Address address);
    void add(AddressRange range);
    void add(Address first, Address second);
    void add(const AddressSet &set);
    void erase(AddressRange range);
    void erase(Address first, Address second);
    void erase(const AddressSet &set);
    void delete_from_min(const Address &through);
    void delete_to_max(const Address &from);

    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] std::size_t range_count() const noexcept;
    [[nodiscard]] AddressCount address_count() const noexcept;
    [[nodiscard]] const std::vector<AddressRange> &ranges() const noexcept;
    [[nodiscard]] std::optional<Address> min_address() const noexcept;
    [[nodiscard]] std::optional<Address> max_address() const noexcept;
    [[nodiscard]] std::optional<AddressRange> range_containing(const Address &address) const;
    [[nodiscard]] bool contains(const Address &address) const noexcept;
    [[nodiscard]] bool contains(const Address &first, const Address &second) const;
    [[nodiscard]] bool contains(const AddressSet &set) const noexcept;
    [[nodiscard]] bool intersects(const Address &first, const Address &second) const;
    [[nodiscard]] bool intersects(const AddressSet &set) const noexcept;
    [[nodiscard]] std::optional<Address> first_address_in_common(const AddressSet &set) const noexcept;

    [[nodiscard]] AddressSet intersection(const AddressSet &set) const;
    [[nodiscard]] AddressSet intersect_range(const Address &first, const Address &second) const;
    [[nodiscard]] AddressSet set_union(const AddressSet &set) const;
    [[nodiscard]] AddressSet subtract(const AddressSet &set) const;
    [[nodiscard]] AddressSet symmetric_difference(const AddressSet &set) const;

    [[nodiscard]] AddressIterator addresses(bool forward = true) const;
    [[nodiscard]] AddressIterator addresses(Address start, bool forward = true) const;
    [[nodiscard]] std::string to_string() const;

    friend bool operator==(const AddressSet &, const AddressSet &) = default;

private:
    [[nodiscard]] static bool adjacent(const Address &first, const Address &second) noexcept;

    std::vector<AddressRange> ranges_;
};

} // namespace llmghidra::program
