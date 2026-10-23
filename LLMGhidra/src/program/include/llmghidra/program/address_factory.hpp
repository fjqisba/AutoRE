#pragma once

#include "llmghidra/program/address_set.hpp"
#include "llmghidra/program/address_space.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ghidra {
class Translate;
}

namespace llmghidra::program {

struct CompilerSpec;
struct ProcessorSpec;

class AddressFactory {
public:
    explicit AddressFactory(
        std::vector<std::shared_ptr<AddressSpace>> spaces,
        std::shared_ptr<AddressSpace> default_space = {});
    [[nodiscard]] static std::shared_ptr<AddressFactory> from_sleigh(
        const ghidra::Translate &translate,
        const ProcessorSpec &processor_spec,
        const CompilerSpec &compiler_spec);

    [[nodiscard]] std::optional<Address> parse_address(const std::string &text) const;
    [[nodiscard]] std::vector<Address> parse_all_addresses(const std::string &text,
                                                           bool case_sensitive = true) const;
    [[nodiscard]] const std::shared_ptr<AddressSpace> &default_space() const noexcept;
    [[nodiscard]] const std::vector<std::shared_ptr<AddressSpace>> &all_spaces() const noexcept;
    [[nodiscard]] std::vector<std::shared_ptr<AddressSpace>> physical_spaces() const;
    [[nodiscard]] std::shared_ptr<AddressSpace> space(const std::string &name) const noexcept;
    [[nodiscard]] std::shared_ptr<AddressSpace> space(std::int32_t id) const noexcept;
    [[nodiscard]] std::shared_ptr<AddressSpace> constant_space() const noexcept;
    [[nodiscard]] std::shared_ptr<AddressSpace> unique_space() const noexcept;
    [[nodiscard]] std::shared_ptr<AddressSpace> stack_space() const noexcept;
    [[nodiscard]] std::shared_ptr<AddressSpace> register_space() const noexcept;
    [[nodiscard]] bool is_valid(const Address &address) const noexcept;
    [[nodiscard]] bool has_multiple_memory_spaces() const noexcept;
    [[nodiscard]] bool has_stale_overlay_condition() const noexcept;
    void refresh_stale_overlay_status() noexcept;

    [[nodiscard]] Address address(std::int32_t space_id, std::uint64_t offset) const;
    [[nodiscard]] Address constant_address(std::uint64_t offset) const;
    [[nodiscard]] std::uint64_t old_index(const Address &address);
    [[nodiscard]] Address decode_old_index(std::uint64_t value) const;
    [[nodiscard]] AddressSet memory_address_set() const;
    [[nodiscard]] AddressSet address_set(const Address &min, const Address &max) const;

    void add_space(std::shared_ptr<AddressSpace> space);
    void remove_space(const std::string &name);
    void rename_overlay(const std::string &old_name, std::string new_name);

private:
    void index_space(const std::shared_ptr<AddressSpace> &space);
    void rebuild_memory_set();

    std::vector<std::shared_ptr<AddressSpace>> spaces_;
    std::shared_ptr<AddressSpace> default_space_;
    std::shared_ptr<AddressSpace> constant_space_;
    std::shared_ptr<AddressSpace> unique_space_;
    std::shared_ptr<AddressSpace> stack_space_;
    std::shared_ptr<AddressSpace> register_space_;
    std::unordered_map<std::string, std::shared_ptr<AddressSpace>> by_name_;
    std::unordered_map<std::int32_t, std::shared_ptr<AddressSpace>> by_id_;
    AddressSet memory_set_;
    bool stale_overlay_{};
};

} // namespace llmghidra::program
