#pragma once

#include "llmghidra/program/address_factory.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace llmghidra::program {

struct AddressKeyRange {
    std::uint64_t min_key{};
    std::uint64_t max_key{};

    friend bool operator==(const AddressKeyRange &, const AddressKeyRange &) = default;
};

class AddressMap {
public:
    explicit AddressMap(std::uint8_t map_id = 0,
                        std::shared_ptr<AddressFactory> factory = {});

    [[nodiscard]] std::uint64_t key(const Address &address);
    [[nodiscard]] std::optional<Address> decode(std::uint64_t value) const;
    [[nodiscard]] std::vector<AddressKeyRange> key_ranges(const Address &start,
                                                          const Address &end);
    [[nodiscard]] std::vector<AddressKeyRange> key_ranges(const AddressSet &set);
    void reconcile();

private:
    static constexpr std::uint32_t address_offset_bits = 32;
    static constexpr std::uint32_t map_id_bits = 8;
    static constexpr std::uint64_t address_offset_mask = 0xffffffffULL;
    static constexpr std::uint32_t base_id_bits = 24;
    static constexpr std::uint32_t base_id_mask = 0x00ffffffU;
    static constexpr std::uint32_t stack_space_id = base_id_mask;

    [[nodiscard]] std::uint32_t base_index(const Address &address);
    void append_key_ranges(std::vector<AddressKeyRange> &result,
                           const Address &start,
                           const Address &end);

    std::uint64_t map_id_mask_{};
    std::shared_ptr<AddressFactory> factory_;
    mutable std::recursive_mutex mutex_;
    std::vector<Address> bases_;
    std::shared_ptr<const AddressSpace> stack_space_;
};

} // namespace llmghidra::program
