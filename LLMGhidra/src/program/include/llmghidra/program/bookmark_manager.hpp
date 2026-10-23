#pragma once

#include "llmghidra/program/address.hpp"

#include <cstddef>
#include <cstdint>
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

class PersistentAddressMap;
class PropertyMapManager;
enum class ProgramOpenMode;

struct BookmarkType {
    std::int32_t id{};
    std::string name;
};

struct Bookmark {
    std::int64_t id{};
    BookmarkType type;
    Address address;
    std::string category;
    std::string comment;
};

// Native BookmarkDBManager for the current per-type V3 tables, including
// upgrades from the unified V1/V2 table and pre-table OldBookmark object
// properties. Type names and table/key encodings remain Ghidra-compatible.
class BookmarkManager final {
public:
    static constexpr const char *type_table_name = "Bookmark Types";
    static constexpr const char *bookmark_table_prefix = "Bookmarks";
    static constexpr int bookmark_schema_version = 3;
    static constexpr int type_schema_version = 0;

    BookmarkManager(std::shared_ptr<db::DatabaseHandle> database,
                    PersistentAddressMap &address_map,
                    PropertyMapManager &properties,
                    ProgramOpenMode mode,
                    bool create);

    [[nodiscard]] std::vector<BookmarkType> types() const;
    [[nodiscard]] std::optional<BookmarkType> type(
        const std::string &name) const;
    [[nodiscard]] BookmarkType create_type(std::string name);
    [[nodiscard]] bool remove_type(const std::string &name);

    [[nodiscard]] Bookmark set(const Address &address,
                               std::string type,
                               std::string category,
                               std::string comment);
    [[nodiscard]] std::optional<Bookmark> get(std::int64_t id) const;
    [[nodiscard]] std::optional<Bookmark> get(
        const Address &address,
        const std::string &type,
        const std::string &category) const;
    [[nodiscard]] std::vector<Bookmark> all() const;
    [[nodiscard]] std::vector<Bookmark> at(const Address &address) const;
    [[nodiscard]] std::vector<Bookmark> of_type(
        const std::string &type) const;
    [[nodiscard]] std::vector<std::string> categories(
        const std::string &type) const;
    [[nodiscard]] std::size_t size() const;

    void update(const Bookmark &bookmark);
    [[nodiscard]] bool remove(std::int64_t id);
    [[nodiscard]] std::size_t remove(
        const std::string &type,
        const std::optional<std::string> &category = std::nullopt);
    void delete_address_range(const Address &start, const Address &end);
    void move_address_range(const Address &from,
                            const Address &to,
                            std::uint64_t length);
    void invalidate_cache();

private:
    [[nodiscard]] static std::shared_ptr<db::Schema> type_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> bookmark_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> legacy_bookmark_schema(
        int version);
    [[nodiscard]] static std::string bookmark_table_name(std::int32_t type_id);
    [[nodiscard]] std::shared_ptr<db::Table> bookmark_table(
        std::int32_t type_id) const;
    [[nodiscard]] Bookmark decode(const BookmarkType &type,
                                  const db::Record &record) const;
    [[nodiscard]] std::int64_t allocate_id(
        std::int32_t type_id,
        const db::Table &table) const;
    [[nodiscard]] std::uint64_t address_key(const Address &address,
                                            bool create) const;
    void load_and_validate_current();
    void load_legacy_property_view(PropertyMapManager &properties);
    void upgrade_legacy_properties(PropertyMapManager &properties);
    void upgrade_legacy_table(const std::shared_ptr<db::Table> &legacy);
    void rekey_current_tables();
    void create_current_tables();
    void require_mutation() const;

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    ProgramOpenMode mode_{};
    std::shared_ptr<db::Table> type_table_;
    std::vector<BookmarkType> legacy_types_;
    std::vector<Bookmark> legacy_bookmarks_;
};

} // namespace llmghidra::program
