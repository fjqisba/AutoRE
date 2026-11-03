#include "llmghidra/program/variable_storage.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/address_space.hpp"
#include "llmghidra/program/language_translator.hpp"

#include <array>
#include <bit>
#include <charconv>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace llmghidra::program {
namespace {

constexpr std::string_view bad_serialization = "<BAD>";
constexpr std::string_view unassigned_serialization = "<UNASSIGNED>";
constexpr std::string_view void_serialization = "<VOID>";
constexpr std::uint64_t crc64_polynomial = 0xc96c5795d7870f42ULL;

[[nodiscard]] const std::array<std::uint64_t, 256> &crc64_table() noexcept {
    static const auto table = [] {
        std::array<std::uint64_t, 256> result{};
        for (std::uint64_t byte = 0; byte < result.size(); ++byte) {
            std::uint64_t remainder = byte;
            for (unsigned bit = 0; bit < 8; ++bit) {
                remainder = (remainder & 1U) != 0
                                ? (remainder >> 1U) ^ crc64_polynomial
                                : remainder >> 1U;
            }
            result[byte] = remainder;
        }
        return result;
    }();
    return table;
}

[[nodiscard]] bool is_hash_address(const Address &address) noexcept {
    return address.is_valid() && address.space()->equivalent(*hash_space());
}

[[nodiscard]] std::optional<Address> parse_storage_address(
    const AddressFactory &factory,
    const std::string &text) {
    if (const auto parsed = factory.parse_address(text)) return parsed;

    // DefaultAddressFactory keeps analysis-only spaces outside its physical
    // space list.  VariableStorage serialization may still name them.
    const std::array<std::shared_ptr<AddressSpace>, 4> special_spaces{
        hash_space(), variable_space(), external_space(), default_register_space()};
    for (const auto &space : special_spaces) {
        try {
            if (const auto parsed = space->parse_address(text)) return parsed;
        }
        catch (const AddressError &) {
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool varnodes_intersect(const StorageVarnode &left,
                                      const StorageVarnode &right) noexcept {
    if (!left.address.same_space(right.address)) return false;
    if (left.address.is_constant_address() || is_hash_address(left.address)) {
        return left.address.offset() == right.address.offset();
    }
    const auto left_end = left.address.offset() +
                          static_cast<std::uint64_t>(left.size - 1);
    const auto right_end = right.address.offset() +
                           static_cast<std::uint64_t>(right.size - 1);
    if (left_end < left.address.offset()) {
        return right.address.offset() >= left.address.offset() ||
               right_end <= left_end || right_end < right.address.offset();
    }
    if (right_end < right.address.offset()) {
        return left.address.offset() >= right.address.offset() ||
               left_end <= right_end;
    }
    return left.address.offset() <= right_end && right.address.offset() <= left_end;
}

void validate_varnodes(const AddressFactory &factory,
                       const std::vector<StorageVarnode> &varnodes) {
    if (varnodes.empty()) {
        throw std::invalid_argument("variable storage requires at least one varnode");
    }
    std::int64_t total_size = 0;
    for (const auto &varnode : varnodes) {
        if (!varnode.address.is_valid() || varnode.size <= 0) {
            throw std::invalid_argument("variable storage contains an invalid varnode");
        }
        const bool analysis_space = is_hash_address(varnode.address) ||
                                    varnode.address.is_constant_address() ||
                                    varnode.address.is_unique_address();
        if (!analysis_space && !factory.is_valid(varnode.address) &&
            !varnode.address.is_register_address()) {
            throw std::invalid_argument(
                "variable storage address does not belong to the program architecture");
        }
        if (!varnode.address.space()->is_valid_range(
                varnode.address.offset(), static_cast<std::uint64_t>(varnode.size))) {
            throw std::invalid_argument("variable storage varnode exceeds its address space");
        }
        if (analysis_space && varnodes.size() != 1) {
            throw std::invalid_argument(
                "hash, unique, and constant storage require a single varnode");
        }
        if (varnode.address.is_stack_address() &&
            varnode.address.signed_offset() < 0) {
            const auto magnitude = 0U - varnode.address.offset();
            if (magnitude < static_cast<std::uint64_t>(varnode.size)) {
                throw std::invalid_argument(
                    "stack variable storage may not cross stack offset zero");
            }
        }
        total_size += varnode.size;
        if (total_size > std::numeric_limits<std::int32_t>::max()) {
            throw std::overflow_error("variable storage size exceeds Ghidra int range");
        }
    }
    for (std::size_t left = 0; left < varnodes.size(); ++left) {
        for (std::size_t right = left + 1; right < varnodes.size(); ++right) {
            if (varnodes_intersect(varnodes[left], varnodes[right])) {
                throw std::invalid_argument("variable storage varnodes overlap");
            }
        }
    }
}

} // namespace

VariableStorage::VariableStorage(VariableStorageKind kind,
                                 std::vector<StorageVarnode> varnodes,
                                 std::int32_t size,
                                 std::string serialization,
                                 std::int64_t hash) noexcept
    : kind_(kind), varnodes_(std::move(varnodes)), size_(size),
      serialization_(std::move(serialization)), hash_(hash) {}

VariableStorage VariableStorage::mapped(
    const AddressFactory &factory,
    std::vector<StorageVarnode> varnodes) {
    validate_varnodes(factory, varnodes);
    std::int64_t total = 0;
    for (const auto &varnode : varnodes) total += varnode.size;
    auto text = serialize(varnodes);
    return VariableStorage(VariableStorageKind::mapped, std::move(varnodes),
                           static_cast<std::int32_t>(total), text,
                           hash_serialization(text));
}

VariableStorage VariableStorage::deserialize(
    const AddressFactory &factory,
    const std::string &serialization) {
    if (serialization == bad_serialization) return bad();
    if (serialization.empty() || serialization == unassigned_serialization) {
        return unassigned();
    }
    if (serialization == void_serialization) return void_storage();

    std::vector<StorageVarnode> varnodes;
    std::size_t start = 0;
    while (start <= serialization.size()) {
        const auto comma = serialization.find(',', start);
        const auto piece = serialization.substr(
            start, comma == std::string::npos ? std::string::npos : comma - start);
        const auto colon = piece.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 == piece.size()) {
            throw std::invalid_argument("invalid Ghidra variable-storage serialization");
        }
        const auto address = parse_storage_address(factory, piece.substr(0, colon));
        std::int32_t size{};
        const auto size_text = piece.substr(colon + 1);
        const auto [end, error] = std::from_chars(
            size_text.data(), size_text.data() + size_text.size(), size);
        if (!address || error != std::errc{} ||
            end != size_text.data() + size_text.size() || size <= 0) {
            throw std::invalid_argument("invalid Ghidra variable-storage serialization");
        }
        varnodes.push_back({*address, size});
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return mapped(factory, std::move(varnodes));
}

std::string VariableStorage::translate_serialization(
    const AddressFactory &new_factory,
    const LanguageTranslator &translator,
    const std::string &serialization) {
    if (serialization.empty() || serialization == unassigned_serialization ||
        serialization == void_serialization ||
        serialization == bad_serialization) {
        return serialization;
    }
    const auto old_storage = deserialize(
        translator.old_address_factory(), serialization);
    std::vector<StorageVarnode> translated_varnodes;
    translated_varnodes.reserve(old_storage.varnodes().size());
    for (const auto &varnode : old_storage.varnodes()) {
        std::optional<Address> translated_address;
        if (varnode.address.is_register_address()) {
            translated_address = translator.new_register_address(
                varnode.address, varnode.size);
            if (!translated_address) {
                const auto target_register_space = new_factory.register_space();
                if (target_register_space &&
                    varnode.address.offset() <=
                        target_register_space->max_offset()) {
                    translated_address =
                        target_register_space->address_in_this_space(
                            varnode.address.offset());
                }
            }
        }
        else if (varnode.address.is_memory_address()) {
            translated_address = translator.new_address(varnode.address);
            if (!translated_address) {
                const auto overlay = new_factory.space(
                    varnode.address.space()->name());
                if (overlay && overlay->is_overlay_space() &&
                    varnode.address.offset() <= overlay->max_offset()) {
                    translated_address = overlay->address_in_this_space(
                        varnode.address.offset());
                }
            }
        }
        else {
            const auto target_space = new_factory.space(
                varnode.address.space()->name());
            if (target_space && varnode.address.offset() <=
                                    target_space->max_offset()) {
                translated_address = target_space->address_in_this_space(
                    varnode.address.offset());
            }
            else {
                translated_address = varnode.address;
            }
        }
        if (!translated_address) {
            throw std::runtime_error(
                "language translation cannot preserve Variable Storage varnode");
        }
        translated_varnodes.push_back({*translated_address, varnode.size});
    }
    return mapped(new_factory, std::move(translated_varnodes)).serialization();
}

VariableStorage VariableStorage::bad() {
    const std::string text(bad_serialization);
    return VariableStorage(VariableStorageKind::bad, {}, 0, text,
                           hash_serialization(text));
}

VariableStorage VariableStorage::unassigned() {
    const std::string text(unassigned_serialization);
    return VariableStorage(VariableStorageKind::unassigned, {}, 0, text,
                           hash_serialization(text));
}

VariableStorage VariableStorage::void_storage() {
    const std::string text(void_serialization);
    return VariableStorage(VariableStorageKind::void_storage, {}, 0, text,
                           hash_serialization(text));
}

VariableStorageKind VariableStorage::kind() const noexcept { return kind_; }
bool VariableStorage::is_mapped() const noexcept {
    return kind_ == VariableStorageKind::mapped;
}
bool VariableStorage::is_bad() const noexcept {
    return kind_ == VariableStorageKind::bad;
}
bool VariableStorage::is_unassigned() const noexcept {
    return kind_ == VariableStorageKind::unassigned;
}
bool VariableStorage::is_void() const noexcept {
    return kind_ == VariableStorageKind::void_storage;
}
bool VariableStorage::is_compound() const noexcept { return varnodes_.size() > 1; }
bool VariableStorage::is_stack_storage() const noexcept {
    return varnodes_.size() == 1 && varnodes_.front().address.is_stack_address();
}
bool VariableStorage::has_stack_storage() const noexcept {
    return !varnodes_.empty() &&
           (varnodes_.front().address.is_stack_address() ||
            varnodes_.back().address.is_stack_address());
}
bool VariableStorage::is_constant_storage() const noexcept {
    return varnodes_.size() == 1 && varnodes_.front().address.is_constant_address();
}
bool VariableStorage::is_hash_storage() const noexcept {
    return varnodes_.size() == 1 && is_hash_address(varnodes_.front().address);
}
bool VariableStorage::is_unique_storage() const noexcept {
    return varnodes_.size() == 1 && varnodes_.front().address.is_unique_address();
}
std::int32_t VariableStorage::size() const noexcept { return size_; }
const std::vector<StorageVarnode> &VariableStorage::varnodes() const noexcept {
    return varnodes_;
}
const std::string &VariableStorage::serialization() const noexcept {
    return serialization_;
}
std::int64_t VariableStorage::long_hash() const noexcept { return hash_; }

bool VariableStorage::intersects(const VariableStorage &other) const noexcept {
    for (const auto &left : varnodes_) {
        for (const auto &right : other.varnodes_) {
            if (varnodes_intersect(left, right)) return true;
        }
    }
    return false;
}

std::string VariableStorage::serialize(
    const std::vector<StorageVarnode> &varnodes) {
    std::string result;
    for (const auto &varnode : varnodes) {
        if (!result.empty()) result.push_back(',');
        result += varnode.address.to_string(true);
        result.push_back(':');
        result += std::to_string(varnode.size);
    }
    return result;
}

std::int64_t VariableStorage::hash_serialization(
    const std::string &serialization) noexcept {
    std::uint64_t crc = std::numeric_limits<std::uint64_t>::max();
    const auto &table = crc64_table();
    for (const auto byte : serialization) {
        crc = table[(static_cast<std::uint8_t>(byte) ^
                     static_cast<std::uint8_t>(crc))] ^
              (crc >> 8U);
    }
    return std::bit_cast<std::int64_t>(~crc);
}

} // namespace llmghidra::program
