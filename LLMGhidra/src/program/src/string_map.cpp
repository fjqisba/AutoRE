#include "llmghidra/program/string_map.hpp"

#include "llmghidra/db/field.hpp"
#include "llmghidra/db/record.hpp"
#include "llmghidra/db/schema.hpp"
#include "llmghidra/db/table.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <stdexcept>
#include <utility>
#include <vector>

namespace llmghidra::program {
namespace {

[[nodiscard]] std::shared_ptr<db::Schema> string_map_schema() {
    std::vector<std::unique_ptr<db::Field>> fields;
    fields.push_back(std::make_unique<db::StringField>());
    return std::make_shared<db::Schema>(
        0, std::make_unique<db::StringField>(), "Key", std::move(fields),
        std::vector<std::string>{"Value"});
}

[[nodiscard]] db::StringField string_field(const std::string &value) {
    return db::StringField(std::optional<std::string>(value));
}

} // namespace

StringMap::StringMap(std::shared_ptr<db::DatabaseHandle> database,
                     std::string table_name,
                     bool create)
    : database_(std::move(database)) {
    if (!database_) {
        throw std::invalid_argument("string map requires a database");
    }
    if (create) {
        auto schema = string_map_schema();
        table_ = database_->create_table(std::move(table_name), schema);
        schema_ = std::move(schema);
    }
    else {
        table_ = database_->get_table(table_name);
        if (!table_) {
            throw std::runtime_error("string-map table not found: " + table_name);
        }
        schema_ = table_->schema_handle();
        if (!schema_->equals(*string_map_schema())) {
            throw std::runtime_error("string-map table has an incompatible schema: " + table_name);
        }
    }
}

void StringMap::put(const std::string &key, std::optional<std::string> value) {
    if (!value) {
        erase(key);
        return;
    }
    if (get(key) == value) {
        return;
    }
    auto record = schema_->create_record(
        std::make_unique<db::StringField>(std::optional<std::string>(key)));
    record->set_string(0, std::move(value));
    table_->put_record(*record);
}

std::optional<std::string> StringMap::get(const std::string &key) const {
    const auto field = string_field(key);
    auto record = table_->record(field);
    return record ? record->field(0).as_string() : std::nullopt;
}

std::int32_t StringMap::get_int(const std::string &key,
                                std::int32_t default_value) const noexcept {
    try {
        const auto value = get(key);
        if (!value) {
            return default_value;
        }
        std::int32_t result{};
        const auto [end, error] =
            std::from_chars(value->data(), value->data() + value->size(), result);
        return error == std::errc{} && end == value->data() + value->size()
                   ? result
                   : default_value;
    }
    catch (...) {
        return default_value;
    }
}

bool StringMap::get_bool(const std::string &key, bool default_value) const noexcept {
    try {
        const auto value = get(key);
        if (!value) {
            return default_value;
        }
        std::string folded = *value;
        std::ranges::transform(folded, folded.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return folded == "true";
    }
    catch (...) {
        return default_value;
    }
}

std::set<std::string> StringMap::keys() const {
    std::set<std::string> result;
    auto iterator = table_->field_key_iterator();
    while (iterator->has_next()) {
        auto field = iterator->next();
        if (const auto key = field->as_string()) {
            result.insert(*key);
        }
    }
    return result;
}

void StringMap::erase(const std::string &key) {
    const auto field = string_field(key);
    (void)table_->delete_record(field);
}

} // namespace llmghidra::program
