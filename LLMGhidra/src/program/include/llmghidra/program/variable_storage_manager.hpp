#pragma once

#include "llmghidra/program/persistent_address_map.hpp"
#include "llmghidra/program/variable_storage.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Schema;
class Table;
}

namespace llmghidra::program {

class AddressFactory;
class LanguageTranslator;

struct VariableStorageRecord {
    std::int64_t id{};
    std::int64_t hash{};
    std::string serialization;
};

// Current-schema native counterpart of VariableStorageManagerDB and
// VariableStorageDBAdapterV2.
class VariableStorageManager final {
public:
    static constexpr int schema_version = 2;

    VariableStorageManager(std::shared_ptr<db::DatabaseHandle> database,
                           std::shared_ptr<AddressFactory> address_factory,
                           ProgramOpenMode mode,
                           bool create);

    [[nodiscard]] bool has_table() const noexcept;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::optional<VariableStorageRecord> record(
        const Address &variable_address) const;
    [[nodiscard]] std::optional<VariableStorage> storage(
        const Address &variable_address) const;
    [[nodiscard]] std::optional<Address> address_for(
        const VariableStorage &storage,
        bool create);
    [[nodiscard]] std::vector<VariableStorageRecord> all() const;
    void set_language(std::shared_ptr<AddressFactory> new_address_factory,
                      const LanguageTranslator &translator);
    void rebind_address_factory(
        std::shared_ptr<AddressFactory> address_factory);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> current_schema();
    [[nodiscard]] std::optional<std::int64_t> find_matching_key(
        const VariableStorage &storage) const;
    void require_mutation() const;
    void bind_existing_table(bool allow_missing);

    std::shared_ptr<db::DatabaseHandle> database_;
    std::shared_ptr<AddressFactory> address_factory_;
    std::shared_ptr<db::Table> table_;
    ProgramOpenMode mode_{};
};

} // namespace llmghidra::program
