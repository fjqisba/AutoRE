#pragma once

#include "llmghidra/program/address.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace llmghidra::program {

class AddressFactory;
class LanguageTranslator;

struct StorageVarnode {
    Address address;
    std::int32_t size{};

    friend bool operator==(const StorageVarnode &, const StorageVarnode &) = default;
};

enum class VariableStorageKind : std::uint8_t {
    mapped,
    bad,
    unassigned,
    void_storage,
};

// Native representation of ghidra.program.model.listing.VariableStorage.
// Its serialization and CRC64 locator are persisted by Ghidra and are
// therefore part of the database compatibility contract.
class VariableStorage final {
public:
    [[nodiscard]] static VariableStorage mapped(
        const AddressFactory &factory,
        std::vector<StorageVarnode> varnodes);
    [[nodiscard]] static VariableStorage deserialize(
        const AddressFactory &factory,
        const std::string &serialization);
    [[nodiscard]] static std::string translate_serialization(
        const AddressFactory &new_factory,
        const LanguageTranslator &translator,
        const std::string &serialization);
    [[nodiscard]] static VariableStorage bad();
    [[nodiscard]] static VariableStorage unassigned();
    [[nodiscard]] static VariableStorage void_storage();

    [[nodiscard]] VariableStorageKind kind() const noexcept;
    [[nodiscard]] bool is_mapped() const noexcept;
    [[nodiscard]] bool is_bad() const noexcept;
    [[nodiscard]] bool is_unassigned() const noexcept;
    [[nodiscard]] bool is_void() const noexcept;
    [[nodiscard]] bool is_compound() const noexcept;
    [[nodiscard]] bool is_stack_storage() const noexcept;
    [[nodiscard]] bool has_stack_storage() const noexcept;
    [[nodiscard]] bool is_constant_storage() const noexcept;
    [[nodiscard]] bool is_hash_storage() const noexcept;
    [[nodiscard]] bool is_unique_storage() const noexcept;
    [[nodiscard]] std::int32_t size() const noexcept;
    [[nodiscard]] const std::vector<StorageVarnode> &varnodes() const noexcept;
    [[nodiscard]] const std::string &serialization() const noexcept;
    [[nodiscard]] std::int64_t long_hash() const noexcept;
    [[nodiscard]] bool intersects(const VariableStorage &other) const noexcept;

    friend bool operator==(const VariableStorage &, const VariableStorage &) = default;

private:
    VariableStorage(VariableStorageKind kind,
                    std::vector<StorageVarnode> varnodes,
                    std::int32_t size,
                    std::string serialization,
                    std::int64_t hash) noexcept;

    [[nodiscard]] static std::string serialize(
        const std::vector<StorageVarnode> &varnodes);
    [[nodiscard]] static std::int64_t hash_serialization(
        const std::string &serialization) noexcept;

    VariableStorageKind kind_{VariableStorageKind::unassigned};
    std::vector<StorageVarnode> varnodes_;
    std::int32_t size_{};
    std::string serialization_;
    std::int64_t hash_{};
};

} // namespace llmghidra::program
