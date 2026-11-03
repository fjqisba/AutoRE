#pragma once

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_map.hpp"

#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace llmghidra::program {

class LanguageTranslator;

enum class ProgramOpenMode {
    create,
    update,
    upgrade,
    read_only,
};

// Database-backed Ghidra AddressMapDB encoding. Mutating operations participate
// in the caller-owned DatabaseHandle transaction, like the Java manager.
class PersistentAddressMap {
public:
    static constexpr std::uint64_t invalid_key = std::numeric_limits<std::uint64_t>::max();

    PersistentAddressMap(std::shared_ptr<db::DatabaseHandle> database,
                         ProgramOpenMode mode,
                         std::shared_ptr<AddressFactory> factory,
                         std::uint64_t image_base_offset = 0);

    [[nodiscard]] std::uint64_t key(const Address &address, bool create);
    [[nodiscard]] std::uint64_t absolute_key(const Address &address, bool create);
    [[nodiscard]] Address decode(std::uint64_t value) const noexcept;
    [[nodiscard]] std::vector<AddressKeyRange> key_ranges(const Address &start,
                                                          const Address &end,
                                                          bool absolute,
                                                          bool create);
    [[nodiscard]] std::vector<AddressKeyRange> key_ranges(const AddressSet &set,
                                                          bool absolute,
                                                          bool create);

    [[nodiscard]] const std::shared_ptr<AddressFactory> &factory() const noexcept;
    [[nodiscard]] Address image_base() const;
    [[nodiscard]] bool upgraded() const noexcept;
    [[nodiscard]] bool uses_old_address_encoding() const noexcept;
    void set_image_base(Address base);
    void invalidate_cache();
    void set_address_factory(std::shared_ptr<AddressFactory> factory);
    void set_language(std::shared_ptr<AddressFactory> factory,
                      const LanguageTranslator &translator);
    void rename_overlay_space(const std::string &old_name, const std::string &new_name);
    void delete_overlay_space(const std::string &name);
    void clear();

private:
    struct Entry {
        std::int32_t index{};
        std::string name;
        std::int32_t segment{};
        bool deleted{};
    };

    class Adapter;

    enum class LookupMode { create, match };

    [[nodiscard]] Address canonical_address(const Address &address) const;
    [[nodiscard]] std::uint64_t encode(const Address &address,
                                       bool absolute,
                                       LookupMode mode);
    [[nodiscard]] std::optional<std::uint32_t> base_index(
        const Address &address,
        bool normalize,
        LookupMode mode);
    [[nodiscard]] std::uint64_t normalized_offset(const Address &address) const noexcept;
    void reload_bases(bool force);
    void append_memory_key_ranges(std::vector<AddressKeyRange> &result,
                                  Address start,
                                  Address end,
                                  bool absolute,
                                  bool create);

    std::shared_ptr<db::DatabaseHandle> database_;
    std::shared_ptr<AddressFactory> factory_;
    std::unique_ptr<Adapter> adapter_;
    mutable std::recursive_mutex mutex_;
    std::vector<Address> bases_;
    std::uint64_t image_base_offset_{};
    bool upgraded_{};
    bool use_old_address_encoding_{};
};

} // namespace llmghidra::program
