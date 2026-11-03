#include "llmghidra/headless/program_constant_pool.hpp"

#include "llmghidra/headless/program_sleigh_architecture.hpp"
#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/data_type_manager.hpp"
#include "llmghidra/program/memory_manager.hpp"
#include "llmghidra/program/program.hpp"

#include "cpool.hh"
#include "fspec.hh"
#include "type.hh"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace llmghidra::headless {
namespace {

constexpr std::string_view java_provider_class =
    "ghidra.app.util.pcodeInject.PcodeInjectLibraryJava";
constexpr std::string_view dex_provider_class =
    "ghidra.dalvik.dex.inject.PcodeInjectLibraryDex";

[[nodiscard]] std::string reference_text(
    const std::vector<ghidra::uintb> &refs) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < refs.size(); ++index) {
        if (index != 0) stream << ',';
        stream << "0x" << std::hex << refs[index];
    }
    return stream.str();
}

[[nodiscard]] std::vector<std::string> split_path(std::string_view value) {
    std::vector<std::string> result;
    std::size_t begin = 0;
    while (begin <= value.size()) {
        const auto end = value.find('/', begin);
        const auto component = value.substr(
            begin, end == std::string_view::npos ? value.size() - begin
                                                 : end - begin);
        if (!component.empty()) result.emplace_back(component);
        if (end == std::string_view::npos) break;
        begin = end + 1;
    }
    return result;
}

[[nodiscard]] std::vector<std::string> category_path(
    const program::DataTypeManager &manager,
    std::int64_t category_id) {
    std::vector<std::string> reversed;
    std::vector<std::int64_t> active;
    while (category_id != program::DataTypeManager::root_category_id) {
        if (std::ranges::find(active, category_id) != active.end()) {
            throw ghidra::LowlevelError(
                "ProgramDB data-type category graph contains a cycle");
        }
        active.push_back(category_id);
        const auto category = manager.category(category_id);
        if (!category) {
            throw ghidra::LowlevelError(
                "ProgramDB data-type category graph contains a missing parent");
        }
        reversed.push_back(category->name);
        category_id = category->parent_id;
    }
    std::ranges::reverse(reversed);
    return reversed;
}

struct NamedProgramType {
    std::int64_t id{};
    std::int64_t category_id{};
    std::string name;
};

[[nodiscard]] std::optional<NamedProgramType> named_type(
    const program::DataType &encoded) {
    return std::visit(
        [](const auto &value) -> std::optional<NamedProgramType> {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, program::BuiltinDataType> ||
                          std::is_same_v<T, program::TypedefDataType> ||
                          std::is_same_v<T, program::EnumDataType> ||
                          std::is_same_v<T, program::CompositeDataType> ||
                          std::is_same_v<
                              T, program::FunctionDefinitionDataType>) {
                return NamedProgramType{
                    value.id, value.category_id, value.name};
            }
            return std::nullopt;
        },
        encoded);
}

[[nodiscard]] ghidra::Datatype *find_program_type(
    ProgramSleighArchitecture &architecture,
    const std::vector<std::string> &wanted_category,
    std::string_view wanted_name) {
    std::optional<std::int64_t> best;
    for (const auto &encoded :
         architecture.program().data_types().all_data_types()) {
        const auto candidate = named_type(encoded);
        if (!candidate || candidate->name != wanted_name) continue;
        if (category_path(
                architecture.program().data_types(), candidate->category_id) !=
            wanted_category) {
            continue;
        }
        if (!best || candidate->id < *best) best = candidate->id;
    }
    if (!best) return nullptr;
    return architecture.resolve_program_data_type(*best);
}

class ProgramMemoryReader {
public:
    ProgramMemoryReader(
        const program::MemoryManager &memory,
        program::Address base,
        bool little_endian)
        : memory_(&memory), cursor_(std::move(base)),
          little_endian_(little_endian) {
        if (!cursor_.is_valid()) {
            throw ghidra::LowlevelError(
                "constant-pool provider has no valid source address");
        }
    }

    [[nodiscard]] std::uint8_t u1() {
        return bytes(1).front();
    }

    [[nodiscard]] std::uint16_t u2() {
        const auto data = bytes(2);
        if (little_endian_) {
            return static_cast<std::uint16_t>(data[0]) |
                   static_cast<std::uint16_t>(data[1]) << 8;
        }
        return static_cast<std::uint16_t>(data[0]) << 8 |
               static_cast<std::uint16_t>(data[1]);
    }

    [[nodiscard]] std::uint32_t u4() {
        const auto data = bytes(4);
        std::uint32_t result = 0;
        if (little_endian_) {
            for (std::size_t index = 0; index < data.size(); ++index) {
                result |= static_cast<std::uint32_t>(data[index]) <<
                          (index * 8);
            }
        }
        else {
            for (const auto value : data) result = result << 8 | value;
        }
        return result;
    }

    [[nodiscard]] std::uint64_t u8() {
        const auto data = bytes(8);
        std::uint64_t result = 0;
        if (little_endian_) {
            for (std::size_t index = 0; index < data.size(); ++index) {
                result |= static_cast<std::uint64_t>(data[index]) <<
                          (index * 8);
            }
        }
        else {
            for (const auto value : data) result = result << 8 | value;
        }
        return result;
    }

    [[nodiscard]] std::vector<std::uint8_t> bytes(std::size_t length) {
        try {
            auto result = memory_->read(cursor_, length);
            advance(length);
            return result;
        }
        catch (const program::MemoryAccessError &error) {
            throw ghidra::LowlevelError(
                "cannot read processor constant-pool source: " +
                std::string(error.what()));
        }
        catch (const std::overflow_error &) {
            throw ghidra::LowlevelError(
                "processor constant-pool source address overflow");
        }
    }

private:
    void advance(std::size_t amount) {
        if (amount == 0) return;
        if (amount > static_cast<std::size_t>(
                         std::numeric_limits<std::int64_t>::max())) {
            throw ghidra::LowlevelError(
                "processor constant-pool read exceeds the address range");
        }
        cursor_ = cursor_.add_no_wrap(static_cast<std::int64_t>(amount));
    }

    const program::MemoryManager *memory_{};
    program::Address cursor_;
    bool little_endian_{};
};

struct JavaPoolEntry {
    std::uint8_t tag{};
    std::uint16_t first{};
    std::uint16_t second{};
    std::uint64_t value{};
    std::vector<std::uint8_t> bytes;
};

class ProgramJavaConstantPool final : public ghidra::ConstantPool {
public:
    explicit ProgramJavaConstantPool(ProgramSleighArchitecture &architecture)
        : architecture_(&architecture) {
        const auto space = architecture.program().address_factory()->space(
            "constantPool");
        if (!space) {
            throw ghidra::LowlevelError(
                "JVM constant-pool provider requires the constantPool address space");
        }
        ProgramMemoryReader reader(
            architecture.program().memory(), space->min_address(), false);
        if (reader.u4() != 0xcafebabeU) {
            throw ghidra::LowlevelError(
                "constantPool memory does not contain a Java class file");
        }
        (void)reader.u2();
        (void)reader.u2();
        const auto count = reader.u2();
        if (count == 0) {
            throw ghidra::LowlevelError(
                "Java class file has an invalid constant_pool_count");
        }
        entries_.resize(count);
        for (std::uint32_t index = 1; index < count; ++index) {
            auto &entry = entries_[index];
            entry.tag = reader.u1();
            switch (entry.tag) {
            case 1:
                entry.bytes = reader.bytes(reader.u2());
                break;
            case 3:
            case 4:
                entry.value = reader.u4();
                break;
            case 5:
            case 6:
                entry.value = reader.u8();
                if (++index >= count) {
                    throw ghidra::LowlevelError(
                        "Java long/double constant has no reserved follower entry");
                }
                break;
            case 7:
            case 8:
            case 16:
            case 19:
            case 20:
                entry.first = reader.u2();
                break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 17:
            case 18:
                entry.first = reader.u2();
                entry.second = reader.u2();
                break;
            case 15:
                entry.first = reader.u1();
                entry.second = reader.u2();
                break;
            default:
                throw ghidra::LowlevelError(
                    "unsupported Java constant-pool tag " +
                    std::to_string(entry.tag));
            }
        }
    }

    const ghidra::CPoolRecord *getRecord(
        const std::vector<ghidra::uintb> &refs) const override {
        if (const auto *cached = cache_.getRecord(refs)) return cached;
        if (refs.size() < 2) {
            throw ghidra::LowlevelError(
                "JVM constant-pool reference requires index and operation");
        }
        materialize(refs);
        const auto *result = cache_.getRecord(refs);
        if (result == nullptr) {
            throw ghidra::LowlevelError(
                "could not materialize JVM constant-pool reference " +
                reference_text(refs));
        }
        return result;
    }

    bool empty() const override { return false; }
    void clear() override { cache_.clear(); }
    void encode(ghidra::Encoder &) const override {
        throw ghidra::LowlevelError(
            "ProgramDB JVM constant pool cannot be serialized independently");
    }
    void decode(ghidra::Decoder &, ghidra::TypeFactory &) override {
        throw ghidra::LowlevelError(
            "ProgramDB JVM constant pool cannot be replaced from a stream");
    }

private:
    ghidra::CPoolRecord *createRecord(
        const std::vector<ghidra::uintb> &) override {
        throw ghidra::LowlevelError(
            "ProgramDB JVM constant pool is populated through its native parser");
    }

    [[nodiscard]] const JavaPoolEntry &entry(
        std::uint64_t index, std::optional<std::uint8_t> tag = std::nullopt) const {
        if (index == 0 || index >= entries_.size()) {
            throw ghidra::LowlevelError(
                "Java constant-pool index is out of range: " +
                std::to_string(index));
        }
        const auto &result = entries_[static_cast<std::size_t>(index)];
        if (result.tag == 0) {
            throw ghidra::LowlevelError(
                "Java constant-pool index names a reserved entry: " +
                std::to_string(index));
        }
        if (tag && result.tag != *tag) {
            throw ghidra::LowlevelError(
                "Java constant-pool entry has unexpected tag at index " +
                std::to_string(index));
        }
        return result;
    }

    [[nodiscard]] std::string utf8(std::uint64_t index) const {
        const auto &value = entry(index, 1);
        return std::string(value.bytes.begin(), value.bytes.end());
    }

    [[nodiscard]] ghidra::Datatype *primitive(char descriptor) const {
        auto *types = architecture_->types;
        switch (descriptor) {
        case 'B': return types->getBase(1, ghidra::TYPE_INT);
        case 'C': return types->getBase(1, ghidra::TYPE_UINT);
        case 'I': return types->getBase(4, ghidra::TYPE_INT);
        case 'S': return types->getBase(2, ghidra::TYPE_INT);
        case 'Z': return types->getBase(1, ghidra::TYPE_BOOL);
        case 'F': return types->getBase(4, ghidra::TYPE_FLOAT);
        case 'D': return types->getBase(8, ghidra::TYPE_FLOAT);
        case 'J': return types->getBase(8, ghidra::TYPE_INT);
        case 'V': return types->getTypeVoid();
        default:
            throw ghidra::LowlevelError(
                "invalid JVM data-type descriptor");
        }
    }

    [[nodiscard]] ghidra::Datatype *pointer_to(
        ghidra::Datatype *target,
        std::optional<ghidra::int4> size = std::nullopt) const {
        if (target == nullptr) target = architecture_->types->getBase(
            1, ghidra::TYPE_UNKNOWN);
        const auto pointer_size = size.value_or(static_cast<ghidra::int4>(
            architecture_->compiler_spec().data_organization.pointer_size));
        const auto word_size = std::max<ghidra::uint4>(
            1, architecture_->getDefaultDataSpace()->getWordSize());
        return architecture_->types->getTypePointer(
            std::max<ghidra::int4>(1, pointer_size), target, word_size);
    }

    [[nodiscard]] ghidra::Datatype *reference_type(
        std::string_view descriptor,
        bool includes_markers) const {
        if (includes_markers) {
            if (descriptor.size() < 2 || descriptor.front() != 'L' ||
                descriptor.back() != ';') {
                throw ghidra::LowlevelError(
                    "invalid JVM reference descriptor");
            }
            descriptor.remove_prefix(1);
            descriptor.remove_suffix(1);
        }
        auto path = split_path(descriptor);
        if (path.empty()) {
            throw ghidra::LowlevelError("empty JVM reference descriptor");
        }
        auto *target = find_program_type(
            *architecture_, path, path.back());
        return pointer_to(target);
    }

    [[nodiscard]] ghidra::Datatype *descriptor_type(
        std::string_view descriptor) const {
        if (descriptor.empty()) {
            throw ghidra::LowlevelError("empty JVM data-type descriptor");
        }
        if (descriptor.front() == '[') {
            const auto base = descriptor.find_last_of('[');
            if (base == std::string_view::npos || base + 1 >= descriptor.size()) {
                throw ghidra::LowlevelError("invalid JVM array descriptor");
            }
            return pointer_to(descriptor_type(descriptor.substr(base + 1)));
        }
        if (descriptor.front() == 'L') {
            const auto end = descriptor.find(';');
            if (end == std::string_view::npos) {
                throw ghidra::LowlevelError("unterminated JVM reference descriptor");
            }
            return reference_type(descriptor.substr(0, end + 1), true);
        }
        return primitive(descriptor.front());
    }

    [[nodiscard]] std::vector<ghidra::Datatype *> method_parameters(
        std::string_view descriptor) const {
        if (descriptor.empty() || descriptor.front() != '(') {
            throw ghidra::LowlevelError("invalid JVM method descriptor");
        }
        const auto close = descriptor.find(')');
        if (close == std::string_view::npos) {
            throw ghidra::LowlevelError("unterminated JVM method descriptor");
        }
        std::vector<ghidra::Datatype *> result;
        std::size_t cursor = 1;
        while (cursor < close) {
            const auto start = cursor;
            while (cursor < close && descriptor[cursor] == '[') ++cursor;
            if (cursor >= close) {
                throw ghidra::LowlevelError("invalid JVM array parameter");
            }
            if (descriptor[cursor] == 'L') {
                const auto end = descriptor.find(';', cursor);
                if (end == std::string_view::npos || end >= close) {
                    throw ghidra::LowlevelError(
                        "unterminated JVM reference parameter");
                }
                cursor = end + 1;
            }
            else {
                ++cursor;
            }
            result.push_back(descriptor_type(
                descriptor.substr(start, cursor - start)));
        }
        return result;
    }

    [[nodiscard]] ghidra::Datatype *method_return(
        std::string_view descriptor) const {
        const auto close = descriptor.find(')');
        if (close == std::string_view::npos || close + 1 >= descriptor.size()) {
            throw ghidra::LowlevelError("invalid JVM method return descriptor");
        }
        return descriptor_type(descriptor.substr(close + 1));
    }

    [[nodiscard]] std::string class_name(std::string_view qualified) const {
        const auto slash = qualified.find_last_of('/');
        return std::string(slash == std::string_view::npos
                               ? qualified
                               : qualified.substr(slash + 1));
    }

    void put(
        const std::vector<ghidra::uintb> &refs,
        ghidra::uint4 tag,
        std::string token,
        ghidra::Datatype *type,
        ghidra::uintb value = 0,
        ghidra::uint4 flags = 0) const {
        cache_.putRecord(refs, tag, token, type, value, flags);
    }

    void put_bytes(
        const std::vector<ghidra::uintb> &refs,
        ghidra::uint4 tag,
        std::string token,
        ghidra::Datatype *type,
        const std::vector<std::uint8_t> &bytes,
        ghidra::uint4 flags = 0) const {
        std::vector<ghidra::uint1> native(bytes.begin(), bytes.end());
        cache_.putRecord(refs, tag, token, type, native, flags);
    }

    void fill_method(
        const std::vector<ghidra::uintb> &refs,
        std::uint64_t pool_index,
        std::uint16_t name_and_type_index,
        bool static_call,
        bool dynamic_call) const {
        const auto &name_and_type = entry(name_and_type_index, 12);
        auto token = utf8(name_and_type.first);
        if (static_call && !dynamic_call) {
            const auto &method_reference = entry(pool_index);
            if (method_reference.tag != 10 && method_reference.tag != 11) {
                throw ghidra::LowlevelError(
                    "JVM static invocation does not reference a method");
            }
            const auto &owner = entry(method_reference.first, 7);
            token = class_name(utf8(owner.first)) + "." + token;
        }
        const auto descriptor = utf8(name_and_type.second);
        ghidra::PrototypePieces pieces;
        pieces.model = architecture_->getModel(
            static_call || dynamic_call ? "__stdcall" : "__thiscall");
        if (pieces.model == nullptr) pieces.model = architecture_->defaultfp;
        pieces.name = [&] {
            std::ostringstream name;
            name << std::hex << pool_index << '_' << token;
            return name.str();
        }();
        pieces.outtype = method_return(descriptor);
        pieces.intypes = method_parameters(descriptor);
        pieces.innames.assign(pieces.intypes.size(), std::string{});
        if (!static_call && !dynamic_call) {
            pieces.intypes.insert(
                pieces.intypes.begin(), pointer_to(
                    architecture_->types->getTypeVoid(), 4));
            pieces.innames.insert(pieces.innames.begin(), "objectRef");
        }
        pieces.firstVarArgSlot = -1;
        auto *code = architecture_->types->getTypeCode(pieces);
        put(refs, ghidra::CPoolRecord::pointer_method,
            std::move(token), pointer_to(code));
    }

    void fill_field(
        const std::vector<ghidra::uintb> &refs,
        const JavaPoolEntry &field_reference,
        bool static_field) const {
        if (field_reference.tag != 9) {
            throw ghidra::LowlevelError(
                "JVM field operation does not reference a field");
        }
        const auto &name_and_type = entry(field_reference.second, 12);
        auto token = utf8(name_and_type.first);
        if (static_field) {
            const auto &owner = entry(field_reference.first, 7);
            token = class_name(utf8(owner.first)) + "." + token;
        }
        put(refs, ghidra::CPoolRecord::pointer_field,
            std::move(token), pointer_to(
                descriptor_type(utf8(name_and_type.second))));
    }

    void fill_type_name(
        const std::vector<ghidra::uintb> &refs,
        const JavaPoolEntry &class_reference,
        ghidra::uint4 tag,
        std::string token) const {
        if (class_reference.tag != 7) {
            throw ghidra::LowlevelError(
                "JVM type operation does not reference a class");
        }
        const auto qualified = utf8(class_reference.first);
        auto path = split_path(qualified);
        auto *target = path.empty()
                           ? nullptr
                           : find_program_type(*architecture_, path, path.back());
        if (token.empty()) token = class_name(qualified);
        put(refs, tag, std::move(token), pointer_to(target));
    }

    void materialize(const std::vector<ghidra::uintb> &refs) const {
        const auto index = refs[0];
        const auto operation = refs[1];
        if (operation == 14) {
            const char *token{};
            char descriptor{};
            switch (index) {
            case 4: token = "boolean"; descriptor = 'Z'; break;
            case 5: token = "char"; descriptor = 'C'; break;
            case 6: token = "float"; descriptor = 'F'; break;
            case 7: token = "double"; descriptor = 'D'; break;
            case 8: token = "byte"; descriptor = 'B'; break;
            case 9: token = "short"; descriptor = 'S'; break;
            case 10: token = "int"; descriptor = 'I'; break;
            case 11: token = "long"; descriptor = 'J'; break;
            default:
                throw ghidra::LowlevelError(
                    "invalid JVM primitive array type code");
            }
            put(refs, ghidra::CPoolRecord::pointer_method,
                token, pointer_to(primitive(descriptor)));
            return;
        }
        if (operation == 17) {
            put(refs, ghidra::CPoolRecord::array_length,
                "length", primitive('I'));
            return;
        }

        const auto &pool_entry = entry(index);
        switch (operation) {
        case 0:
        case 13:
            fill_type_name(
                refs, pool_entry, ghidra::CPoolRecord::class_reference, {});
            return;
        case 1: {
            if (pool_entry.tag != 7) {
                throw ghidra::LowlevelError(
                    "JVM checkcast does not reference a class");
            }
            const auto name = class_name(utf8(pool_entry.first));
            fill_type_name(
                refs, pool_entry, ghidra::CPoolRecord::check_cast,
                "checkcast(" + name + ")");
            return;
        }
        case 6:
            fill_type_name(
                refs, pool_entry, ghidra::CPoolRecord::instance_of,
                "instanceof");
            return;
        case 2:
        case 16:
            fill_field(refs, pool_entry, false);
            return;
        case 3:
        case 15:
            fill_field(refs, pool_entry, true);
            return;
        case 7:
            if (pool_entry.tag != 18) {
                throw ghidra::LowlevelError(
                    "JVM invokedynamic has an invalid constant-pool tag");
            }
            fill_method(refs, index, pool_entry.second, true, true);
            return;
        case 8:
        case 9:
        case 10:
        case 11:
            if (pool_entry.tag != 10 && pool_entry.tag != 11) {
                throw ghidra::LowlevelError(
                    "JVM invocation has an invalid constant-pool tag");
            }
            fill_method(
                refs, index, pool_entry.second, operation == 10, false);
            return;
        case 4:
            if (pool_entry.tag == 3) {
                put(refs, ghidra::CPoolRecord::primitive,
                    "int", primitive('I'), pool_entry.value);
            }
            else if (pool_entry.tag == 4) {
                put(refs, ghidra::CPoolRecord::primitive,
                    "float", primitive('F'), pool_entry.value);
            }
            else if (pool_entry.tag == 8) {
                const auto &literal = entry(pool_entry.first, 1);
                put_bytes(
                    refs, ghidra::CPoolRecord::string_literal, {},
                    reference_type("java/lang/String", false), literal.bytes);
            }
            else if (pool_entry.tag == 7) {
                const auto qualified = utf8(pool_entry.first);
                put(refs, ghidra::CPoolRecord::class_reference,
                    class_name(qualified) + ".class",
                    reference_type(qualified, false));
            }
            else if (pool_entry.tag == 16) {
                put(refs, ghidra::CPoolRecord::pointer_method,
                    utf8(pool_entry.first),
                    pointer_to(primitive('I')));
            }
            else if (pool_entry.tag == 15) {
                put(refs, ghidra::CPoolRecord::pointer_method,
                    {}, pointer_to(primitive('I')));
            }
            else {
                throw ghidra::LowlevelError(
                    "unsupported JVM ldc constant-pool tag " +
                    std::to_string(pool_entry.tag));
            }
            return;
        case 5:
            if (pool_entry.tag == 5) {
                put(refs, ghidra::CPoolRecord::primitive,
                    "long", primitive('J'), pool_entry.value);
            }
            else if (pool_entry.tag == 6) {
                put(refs, ghidra::CPoolRecord::primitive,
                    "double", primitive('D'), pool_entry.value);
            }
            else {
                throw ghidra::LowlevelError(
                    "JVM ldc2_w does not reference a long or double");
            }
            return;
        case 12:
            if (pool_entry.tag != 7) {
                throw ghidra::LowlevelError(
                    "JVM multianewarray does not reference a class");
            }
            put(refs, ghidra::CPoolRecord::class_reference,
                class_name(utf8(pool_entry.first)),
                pointer_to(architecture_->types->getTypeVoid()));
            return;
        default:
            throw ghidra::LowlevelError(
                "unsupported JVM constant-pool operation " +
                std::to_string(operation));
        }
    }

    ProgramSleighArchitecture *architecture_{};
    std::vector<JavaPoolEntry> entries_;
    mutable ghidra::ConstantPoolInternal cache_;
};

} // namespace

std::unique_ptr<ghidra::ConstantPool> build_program_constant_pool(
    ProgramSleighArchitecture &architecture) {
    const auto provider = architecture.processor_spec().properties.find(
        "pcodeInjectLibraryClass");
    if (provider == architecture.processor_spec().properties.end()) {
        return std::make_unique<ghidra::ConstantPoolInternal>();
    }
    if (provider->second == java_provider_class) {
        return std::make_unique<ProgramJavaConstantPool>(architecture);
    }
    if (provider->second == dex_provider_class) {
        throw ghidra::LowlevelError(
            "native Dalvik constant-pool provider is not installed");
    }
    // A processor may use a custom injection library without defining a
    // deferred constant system. Preserve the standard empty pool in that case.
    return std::make_unique<ghidra::ConstantPoolInternal>();
}

} // namespace llmghidra::headless
