#pragma once

#include "llmghidra/program/address.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Record;
class Schema;
class Table;
}

namespace llmghidra::program {

class NamespaceManager;
class LanguageTranslator;

// Persistent values match ghidra.program.model.symbol.SourceType storage IDs.
enum class SourceType : std::uint8_t {
    analysis = 0,
    user_defined = 1,
    default_source = 2,
    imported = 3,
    ai = 4,
};

// Persistent values match ghidra.program.model.symbol.SymbolType IDs.
enum class SymbolType : std::uint8_t {
    label = 0,
    library = 1,
    name_space = 3,
    class_type = 4,
    function = 5,
    parameter = 6,
    local_variable = 7,
    global_variable = 8,
};

struct Symbol {
    std::int64_t id{};
    std::string name;
    Address address;
    std::int64_t parent_id{};
    SymbolType type{SymbolType::label};
    SourceType source{SourceType::default_source};
    bool primary{};
    bool pinned{};
    std::optional<std::int64_t> data_type_id;
    std::optional<std::int32_t> variable_offset;
    std::optional<std::string> original_imported_name;
    std::optional<std::string> external_program_address;
    std::optional<std::string> comment;
    std::optional<std::string> library_path;
};

struct SymbolSpec {
    std::string name;
    Address address;
    std::int64_t parent_id{};
    SymbolType type{SymbolType::label};
    SourceType source{SourceType::analysis};
    bool primary{};
    bool pinned{};
    std::optional<std::int64_t> data_type_id;
    std::optional<std::int32_t> variable_offset;
    std::optional<std::string> original_imported_name;
    std::optional<std::string> external_program_address;
    std::optional<std::string> comment;
    std::optional<std::string> library_path;
};

class SymbolManager final {
public:
    static constexpr std::int64_t global_namespace_id = 0;
    static constexpr int schema_version = 4;

    SymbolManager(std::shared_ptr<db::DatabaseHandle> database,
                  PersistentAddressMap &address_map,
                  ProgramOpenMode mode,
                  bool create);

    [[nodiscard]] Symbol create(SymbolSpec spec);
    [[nodiscard]] std::optional<Symbol> get(std::int64_t id) const;
    [[nodiscard]] std::vector<Symbol> all() const;
    [[nodiscard]] std::vector<Symbol> at(const Address &address) const;
    [[nodiscard]] std::vector<Symbol> named(const std::string &name) const;
    [[nodiscard]] std::vector<Symbol> in_namespace(std::int64_t parent_id) const;
    [[nodiscard]] std::vector<Symbol> named_in_namespace(
        const std::string &name,
        std::int64_t parent_id) const;
    [[nodiscard]] std::optional<Symbol> primary_at(const Address &address) const;
    [[nodiscard]] std::size_t size() const;

    void update(const Symbol &symbol);
    void rename(std::int64_t id, std::string name, SourceType source);
    void set_namespace(std::int64_t id, std::int64_t parent_id);
    void set_primary(std::int64_t id);
    void move(std::int64_t id, Address address);
    [[nodiscard]] bool remove(std::int64_t id);
    [[nodiscard]] std::size_t remove_range(const Address &start,
                                           const Address &end,
                                           bool preserve_pinned = true);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);
    [[nodiscard]] std::size_t replace_data_type(std::int64_t replaced_id,
                                                std::int64_t replacement_id);
    void set_external_removal_handler(
        std::function<void(std::int64_t)> handler);
    void set_language(const LanguageTranslator &translator);

    [[nodiscard]] bool has_deferred_legacy_local_symbols() const noexcept;
    void finalize_legacy_local_symbols(NamespaceManager &namespaces);

    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> current_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_schema(int version);
    [[nodiscard]] std::unique_ptr<db::Record> translate_legacy_record(
        const db::Record &record) const;
    [[nodiscard]] std::unique_ptr<db::Record> translate_v0_global_record(
        const db::Record &record,
        std::int64_t destination_id) const;
    [[nodiscard]] Symbol decode(const db::Record &record) const;
    [[nodiscard]] std::unique_ptr<db::Record> encode(const Symbol &symbol) const;
    [[nodiscard]] std::int64_t allocate_id() const;
    [[nodiscard]] std::uint64_t encoded_address(const Address &address,
                                                bool create) const;
    [[nodiscard]] static std::optional<std::int64_t> locator_hash(
        const std::string &name,
        std::int64_t namespace_id,
        std::uint64_t address_key);
    static void validate(const Symbol &symbol);
    void require_mutation() const;
    void clear_primary(const Address &address, std::int64_t except_id);

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    std::shared_ptr<db::Table> table_;
    std::shared_ptr<const db::Schema> schema_;
    struct DeferredLegacyLocalSymbol {
        std::int64_t id{};
        std::uint64_t old_address_key{};
        std::string name;
        bool primary{};
    };
    std::vector<DeferredLegacyLocalSymbol> deferred_legacy_local_symbols_;
    int stored_schema_version_{schema_version};
    ProgramOpenMode mode_{};
    std::function<void(std::int64_t)> external_removal_handler_;
};

} // namespace llmghidra::program
