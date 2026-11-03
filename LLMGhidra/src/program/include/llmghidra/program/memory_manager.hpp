#pragma once

#include "llmghidra/db/chained_buffer.hpp"
#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/program/address.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace llmghidra::program {

enum class MemoryBlockType : std::uint8_t {
    default_block = 0,
    bit_mapped = 1,
    byte_mapped = 2,
};

enum class MemorySubBlockType : std::uint8_t {
    bit_mapped = 0,
    byte_mapped = 1,
    buffer = 2,
    uninitialized = 3,
    file_bytes = 4,
};

struct ByteMappingScheme {
    std::uint8_t mapped_bytes{1};
    std::uint8_t source_bytes{1};

    [[nodiscard]] static ByteMappingScheme decode(std::int32_t encoded);
    [[nodiscard]] std::int32_t encode() const;
    [[nodiscard]] std::uint64_t source_offset(std::uint64_t mapped_offset) const;
};

struct FileBytesInfo {
    std::int64_t id{};
    std::string filename;
    std::int64_t file_offset{};
    std::uint64_t size{};
};

struct MemorySubBlock {
    std::int64_t id{};
    std::int64_t parent_id{};
    MemorySubBlockType type{MemorySubBlockType::uninitialized};
    std::uint64_t length{};
    std::uint64_t starting_offset{};
    std::int32_t source_id{};
    std::int64_t source_address_or_offset{};
};

struct MemoryBlock {
    static constexpr std::uint8_t execute = 0x01;
    static constexpr std::uint8_t write = 0x02;
    static constexpr std::uint8_t read = 0x04;
    static constexpr std::uint8_t volatile_block = 0x08;
    static constexpr std::uint8_t artificial = 0x10;
    static constexpr std::uint8_t valid_flags = 0x1f;

    std::int64_t id{};
    std::string name;
    std::optional<std::string> comment;
    std::optional<std::string> source_name;
    std::uint8_t flags{};
    Address start;
    std::uint64_t length{};
    std::int32_t segment{};
    std::vector<MemorySubBlock> sub_blocks;

    [[nodiscard]] Address end() const;
    [[nodiscard]] bool contains(const Address &address) const noexcept;
    [[nodiscard]] bool initialized() const noexcept;
    [[nodiscard]] bool mapped() const noexcept;
    [[nodiscard]] MemoryBlockType type() const noexcept;
};

struct MemorySourceInfo {
    std::int64_t sub_block_id{};
    Address minimum;
    Address maximum;
    std::uint64_t length{};
    MemorySubBlockType type{MemorySubBlockType::uninitialized};
    std::optional<FileBytesInfo> file_bytes;
    std::optional<std::uint64_t> file_bytes_offset;
    std::optional<Address> mapped_minimum;
    std::optional<Address> mapped_maximum;
    std::optional<ByteMappingScheme> byte_mapping_scheme;
};

struct AddressSourceInfo {
    Address address;
    MemorySourceInfo source;
    std::optional<std::string> filename;
    std::optional<std::int64_t> file_offset;
    std::optional<std::uint8_t> original_value;
};

class MemoryAccessError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Native MemoryMapDB V3/FileBytes V0 manager. It retains the exact Ghidra
// block/sub-block tables and ChainedBuffer backing rather than flattening
// imported memory into a replacement container.
class MemoryManager final {
public:
    static constexpr std::int32_t maximum_chained_buffer_size = 1'000'000'000;

    MemoryManager(std::shared_ptr<db::DatabaseHandle> database,
                  PersistentAddressMap &address_map,
                  ProgramOpenMode mode,
                  bool create);

    [[nodiscard]] std::vector<MemoryBlock> blocks() const;
    [[nodiscard]] std::optional<MemoryBlock> block(std::int64_t id) const;
    [[nodiscard]] std::optional<MemoryBlock> block_containing(
        const Address &address) const;

    [[nodiscard]] FileBytesInfo create_file_bytes(
        std::string filename,
        std::int64_t file_offset,
        std::span<const std::uint8_t> bytes);
    [[nodiscard]] std::vector<FileBytesInfo> file_bytes() const;
    [[nodiscard]] std::vector<std::uint8_t> read_file_bytes(
        std::int64_t id, std::uint64_t offset, std::size_t length,
        bool original) const;
    void write_file_bytes(std::int64_t id, std::uint64_t offset,
                          std::span<const std::uint8_t> bytes);
    [[nodiscard]] bool remove_file_bytes(std::int64_t id);

    [[nodiscard]] MemoryBlock create_initialized_block(
        std::string name, const Address &start,
        std::span<const std::uint8_t> bytes, std::uint8_t flags,
        bool overlay = false);
    [[nodiscard]] MemoryBlock create_uninitialized_block(
        std::string name, const Address &start,
        std::uint64_t length, std::uint8_t flags,
        bool overlay = false);
    [[nodiscard]] MemoryBlock create_mapped_block(
        MemoryBlockType type, std::string name, const Address &start,
        std::uint64_t length, const Address &mapped_start,
        std::uint8_t flags, ByteMappingScheme scheme = {},
        bool overlay = false);
    [[nodiscard]] MemoryBlock create_file_bytes_block(
        std::string name, const Address &start, std::uint64_t length,
        std::int64_t file_bytes_id, std::uint64_t file_bytes_offset,
        std::uint8_t flags, bool overlay = false);

    void update_block_metadata(std::int64_t id, std::string name,
                               std::optional<std::string> comment,
                               std::optional<std::string> source_name,
                               std::uint8_t flags);
    [[nodiscard]] MemoryBlock split_block(std::int64_t id,
                                          const Address &split_address);
    [[nodiscard]] MemoryBlock join_blocks(std::int64_t first_id,
                                          std::int64_t second_id);
    [[nodiscard]] MemoryBlock convert_to_initialized(std::int64_t id,
                                                     std::uint8_t initial_value);
    [[nodiscard]] MemoryBlock convert_to_uninitialized(std::int64_t id);
    void move_block(std::int64_t id, const Address &new_start);
    [[nodiscard]] bool remove_block(std::int64_t id);

    [[nodiscard]] std::vector<MemorySourceInfo> source_infos(
        std::int64_t block_id) const;
    [[nodiscard]] std::optional<AddressSourceInfo> address_source_info(
        const Address &address) const;

    [[nodiscard]] std::uint8_t read_byte(const Address &address) const;
    [[nodiscard]] std::vector<std::uint8_t> read(
        const Address &address, std::size_t length) const;
    void write_byte(const Address &address, std::uint8_t value);
    void write(const Address &address, std::span<const std::uint8_t> bytes);

    void set_external_move_handler(
        std::function<void(const Address &, const Address &, std::uint64_t)> handler);
    void set_external_delete_handler(
        std::function<void(const Address &, const Address &)> handler);
    void set_external_overlay_creation_handler(
        std::function<Address(const std::string &, const Address &,
                              std::uint64_t)> handler);
    void set_external_region_change_handler(std::function<void()> handler);
    void set_external_overlay_cleanup_handler(
        std::function<void(const std::string &)> handler);
    void invalidate_caches() noexcept;

private:
    struct FileBytesState;

    [[nodiscard]] static std::shared_ptr<db::Schema> block_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> sub_block_schema();
    [[nodiscard]] static std::shared_ptr<db::Schema> file_bytes_schema();
    void create_tables();
    void open_tables();
    void validate_tables() const;
    void require_mutation() const;
    void require_block_range(const Address &start, std::uint64_t length,
                             std::optional<std::int64_t> except = std::nullopt) const;
    void require_unique_block_name(const std::string &name,
                                   std::optional<std::int64_t> except = std::nullopt) const;
    [[nodiscard]] std::string unique_split_name(const std::string &base) const;
    [[nodiscard]] Address resolve_block_start(
        const std::string &name, const Address &start,
        std::uint64_t length, bool overlay) const;
    void notify_region_change() const;
    [[nodiscard]] MemoryBlock decode_block(const db::Record &record) const;
    [[nodiscard]] std::shared_ptr<FileBytesState> file_bytes_state(
        std::int64_t id) const;
    [[nodiscard]] MemoryBlock create_single_sub_block(
        std::string name, const Address &start, std::uint64_t length,
        std::uint8_t flags, MemorySubBlockType type,
        std::int32_t source_id, std::int64_t source_address_or_offset);
    [[nodiscard]] std::uint8_t read_sub_block(
        const MemoryBlock &block, const MemorySubBlock &sub,
        std::uint64_t block_offset,
        std::vector<Address> &active) const;
    void write_sub_block(const MemoryBlock &block, const MemorySubBlock &sub,
                         std::uint64_t block_offset, std::uint8_t value,
                         std::vector<Address> &active);
    void remove_sub_block_storage(const MemorySubBlock &sub);
    [[nodiscard]] MemorySubBlock split_sub_block(const MemorySubBlock &sub,
                                                 std::uint64_t split_offset,
                                                 std::int64_t new_parent_id,
                                                 std::uint64_t new_starting_offset);

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    ProgramOpenMode mode_{};
    std::shared_ptr<db::Table> block_table_;
    std::shared_ptr<db::Table> sub_block_table_;
    std::shared_ptr<db::Table> file_bytes_table_;
    mutable std::vector<std::shared_ptr<FileBytesState>> file_bytes_cache_;
    std::function<void(const Address &, const Address &, std::uint64_t)>
        external_move_handler_;
    std::function<void(const Address &, const Address &)> external_delete_handler_;
    std::function<Address(const std::string &, const Address &, std::uint64_t)>
        external_overlay_creation_handler_;
    std::function<void()> external_region_change_handler_;
    std::function<void(const std::string &)> external_overlay_cleanup_handler_;
};

} // namespace llmghidra::program
