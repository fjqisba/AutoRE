#pragma once

#include "llmghidra/db/database_handle.hpp"

#include <memory>
#include <optional>
#include <set>
#include <string>

namespace llmghidra::program {

// Schema-stable Ghidra DBStringMapAdapter equivalent.
class StringMap {
public:
    StringMap(std::shared_ptr<db::DatabaseHandle> database,
              std::string table_name,
              bool create);

    void put(const std::string &key, std::optional<std::string> value);
    [[nodiscard]] std::optional<std::string> get(const std::string &key) const;
    [[nodiscard]] std::int32_t get_int(const std::string &key,
                                       std::int32_t default_value) const noexcept;
    [[nodiscard]] bool get_bool(const std::string &key,
                                bool default_value) const noexcept;
    [[nodiscard]] std::set<std::string> keys() const;
    void erase(const std::string &key);

private:
    std::shared_ptr<db::DatabaseHandle> database_;
    std::shared_ptr<db::Table> table_;
    std::shared_ptr<const db::Schema> schema_;
};

} // namespace llmghidra::program
