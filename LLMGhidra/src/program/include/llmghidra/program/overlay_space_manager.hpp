#pragma once

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_range.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace llmghidra::db {
class DatabaseHandle;
class Schema;
class Table;
}

namespace llmghidra::program {

class LanguageTranslator;

struct OverlaySpaceInfo {
    std::int64_t id{};
    std::string name;
    std::string base_space_name;
};

// Native OverlaySpaceDBAdapter V1 manager. It must run before
// PersistentAddressMap so persisted overlay names resolve to live spaces.
class OverlaySpaceManager final {
public:
    static constexpr int schema_version = 1;
    static constexpr const char *table_name = "Overlay Spaces";

    OverlaySpaceManager(std::shared_ptr<db::DatabaseHandle> database,
                        std::shared_ptr<AddressFactory> address_factory,
                        ProgramOpenMode mode,
                        bool create);
    ~OverlaySpaceManager();

    [[nodiscard]] std::vector<OverlaySpaceInfo> all() const;
    [[nodiscard]] std::shared_ptr<AddressSpace> create(
        std::string name,
        const std::shared_ptr<AddressSpace> &base_space);
    [[nodiscard]] bool rename(const std::string &old_name,
                              std::string new_name);
    [[nodiscard]] bool remove(const std::string &name);
    void set_language(std::shared_ptr<AddressFactory> new_address_factory,
                      const LanguageTranslator &translator);
    void rebind_address_factory(
        std::shared_ptr<AddressFactory> address_factory);
    void reconcile_regions(const std::vector<AddressRange> &memory_ranges);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> current_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_schema();
    void open_table();
    void initialize_factory();
    void require_mutation() const;
    void require_valid_name(const std::string &name) const;
    [[nodiscard]] std::uint32_t allocate_unique() const;
    [[nodiscard]] std::shared_ptr<db::Table> writable_table();

    std::shared_ptr<db::DatabaseHandle> database_;
    std::shared_ptr<AddressFactory> address_factory_;
    ProgramOpenMode mode_{};
    std::shared_ptr<db::Table> table_;
    std::vector<std::string> managed_names_;
};

} // namespace llmghidra::program
