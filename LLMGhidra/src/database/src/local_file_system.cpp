/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/local_file_system.hpp"

#include "java_character_tables.hpp"
#include "llmghidra/db/packed_item.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <charconv>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <system_error>
#include <utility>

namespace llmghidra::db {
namespace {

constexpr std::string_view index_file_name = "~index.dat";
constexpr std::string_view backup_index_file_name = "~index.bak";
constexpr std::string_view temporary_index_file_name = "~index.tmp";
constexpr std::string_view journal_file_name = "~journal.dat";
constexpr std::string_view backup_journal_file_name = "~journal.bak";
constexpr std::string_view rebuild_error_file_name = "~rebuild.err";
constexpr std::string_view hidden_item_prefix = ".ghidra.";
// The fixed Ghidra 12.1.3 implementation calls MessageDigest.digest(byte[])
// for every line instead of update(byte[]).  Each call resets the digest, so
// its final index checksum is always MD5(empty).  Readers also accept the
// intended concatenated checksum emitted by early native migration builds.
constexpr std::string_view upstream_index_md5 =
    "d41d8cd98f00b204e9800998ecf8427e";

bool is_hex_storage_name(std::string_view name) {
  if (name.size() < 8 || name.size() > 16)
    return false;
  return std::all_of(name.begin(), name.end(), [](unsigned char character) {
    return std::isxdigit(character) != 0;
  });
}

bool has_indexed_storage(const std::filesystem::path &root) {
  std::error_code error;
  for (std::filesystem::directory_iterator directories(root, error), end;
       !error && directories != end; directories.increment(error)) {
    if (directories->is_symlink(error) && !error) {
      throw LocalFileSystemError("indexed storage shard is a symbolic link: " +
                                 directories->path().string());
    }
    if (!directories->is_directory(error) || error)
      continue;
    const auto directory_name = directories->path().filename().string();
    if (directory_name.size() != 2 ||
        !std::all_of(
            directory_name.begin(), directory_name.end(),
            [](unsigned char value) { return std::isxdigit(value) != 0; })) {
      continue;
    }
    for (std::filesystem::directory_iterator files(directories->path(), error),
         files_end;
         !error && files != files_end; files.increment(error)) {
      if (files->is_regular_file(error) && !error &&
          files->path().extension() == ".prp" &&
          is_hex_storage_name(files->path().stem().string())) {
        return true;
      }
    }
  }
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to inspect local filesystem structure", root, error);
  }
  return false;
}

void reject_symbolic_link_path(const std::filesystem::path &root,
                               const std::filesystem::path &candidate) {
  const auto relative = candidate.lexically_relative(root);
  if (relative.empty() && candidate != root)
    throw LocalFileSystemError("filesystem path is outside project root");
  if (relative.is_absolute() ||
      (!relative.empty() && *relative.begin() == "..")) {
    throw LocalFileSystemError("filesystem path is outside project root");
  }
  auto current = root;
  for (const auto &component : relative) {
    current /= component;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(current, error);
    if (error == std::errc::no_such_file_or_directory)
      return;
    if (error) {
      throw std::filesystem::filesystem_error(
          "unable to inspect local filesystem path", current, error);
    }
    if (std::filesystem::is_symlink(status)) {
      throw LocalFileSystemError(
          "local filesystem path traverses a symbolic link: " +
          current.string());
    }
  }
}

void reject_symbolic_link_file(const std::filesystem::path &path) {
  std::error_code error;
  const auto status = std::filesystem::symlink_status(path, error);
  if (!error && std::filesystem::is_symlink(status)) {
    throw LocalFileSystemError("filesystem control file is a symbolic link: " +
                               path.string());
  }
  if (error && error != std::errc::no_such_file_or_directory) {
    throw std::filesystem::filesystem_error(
        "unable to inspect filesystem control file", path, error);
  }
}

std::uint64_t parse_hex(std::string_view value, std::string_view label) {
  std::uint64_t result = 0;
  const auto parsed =
      std::from_chars(value.data(), value.data() + value.size(), result, 16);
  if (value.empty() || parsed.ec != std::errc{} ||
      parsed.ptr != value.data() + value.size()) {
    throw LocalFileSystemIndexError("invalid " + std::string(label));
  }
  return result;
}

std::vector<std::string> split(std::string_view value, char separator) {
  std::vector<std::string> result;
  std::size_t begin = 0;
  while (begin <= value.size()) {
    const auto end = value.find(separator, begin);
    result.emplace_back(value.substr(begin, end == std::string_view::npos
                                                ? value.size() - begin
                                                : end - begin));
    if (end == std::string_view::npos)
      break;
    begin = end + 1;
  }
  return result;
}

std::string lower_ascii(std::string_view value) {
  std::string result(value);
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char character) {
                   return static_cast<char>(std::tolower(character));
                 });
  return result;
}

std::optional<std::vector<std::uint32_t>> decode_utf8(std::string_view value) {
  std::vector<std::uint32_t> result;
  for (std::size_t index = 0; index < value.size();) {
    const auto first = static_cast<unsigned char>(value[index]);
    std::size_t count = 1;
    std::uint32_t code_point = first;
    if (first >= 0x80) {
      if ((first & 0xe0U) == 0xc0U) {
        count = 2;
        code_point = first & 0x1fU;
        if (code_point < 2)
          return std::nullopt;
      } else if ((first & 0xf0U) == 0xe0U) {
        count = 3;
        code_point = first & 0x0fU;
      } else if ((first & 0xf8U) == 0xf0U) {
        count = 4;
        code_point = first & 0x07U;
      } else {
        return std::nullopt;
      }
      if (index + count > value.size())
        return std::nullopt;
      for (std::size_t offset = 1; offset < count; ++offset) {
        const auto next = static_cast<unsigned char>(value[index + offset]);
        if ((next & 0xc0U) != 0x80U)
          return std::nullopt;
        code_point = (code_point << 6) | (next & 0x3fU);
      }
      if ((count == 3 && code_point < 0x800) ||
          (count == 4 && code_point < 0x10000) || code_point > 0x10ffff ||
          (code_point >= 0xd800 && code_point <= 0xdfff)) {
        return std::nullopt;
      }
    }
    result.push_back(code_point);
    index += count;
  }
  return result;
}

void append_utf8(std::string &output, std::uint32_t code_point) {
  if (code_point <= 0x7f) {
    output.push_back(static_cast<char>(code_point));
  } else if (code_point <= 0x7ff) {
    output.push_back(static_cast<char>(0xc0U | (code_point >> 6)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  } else if (code_point <= 0xffff) {
    output.push_back(static_cast<char>(0xe0U | (code_point >> 12)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 6) & 0x3fU)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  } else {
    output.push_back(static_cast<char>(0xf0U | (code_point >> 18)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 12) & 0x3fU)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 6) & 0x3fU)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
  }
}

template <std::size_t Size>
bool in_unicode_ranges(
    std::uint32_t code_point,
    const std::array<unicode_tables::UnicodeRange, Size> &ranges) {
  const auto found =
      std::lower_bound(ranges.begin(), ranges.end(), code_point,
                       [](const auto &range, std::uint32_t value) {
                         return range.last < value;
                       });
  return found != ranges.end() && found->first <= code_point;
}

template <std::size_t Size>
std::uint32_t
map_unicode(std::uint32_t code_point,
            const std::array<unicode_tables::UnicodeMapping, Size> &mappings) {
  const auto found =
      std::lower_bound(mappings.begin(), mappings.end(), code_point,
                       [](const auto &mapping, std::uint32_t value) {
                         return mapping.from < value;
                       });
  return found != mappings.end() && found->from == code_point ? found->to
                                                              : code_point;
}

bool unicode_uppercase(std::uint32_t code_point) {
  return code_point <= 0xffff &&
         in_unicode_ranges(code_point, unicode_tables::bmp_uppercase_ranges);
}

std::string mangle_name(std::string_view value) {
  std::string escaped;
  std::size_t prefixes = 0;
  while (prefixes < value.size() && value[prefixes] == '~')
    ++prefixes;
  escaped.append(prefixes, '~');
  escaped.append(value);

  const auto code_points = decode_utf8(escaped);
  if (!code_points)
    throw LocalFileSystemInvalidNameError("invalid UTF-8 mangled name");
  std::string result;
  result.reserve(escaped.size() * 2);
  for (const auto character : *code_points) {
    if (character == '_') {
      result += "__";
    } else if (unicode_uppercase(character)) {
      result.push_back('_');
      append_utf8(result, map_unicode(character,
                                      unicode_tables::bmp_lowercase_mappings));
    } else {
      append_utf8(result, character);
    }
  }
  return result;
}

std::optional<std::string> demangle_name(std::string_view value) {
  const auto code_points = decode_utf8(value);
  if (!code_points)
    return std::nullopt;
  std::string result;
  result.reserve(value.size());
  bool escaped = false;
  for (const auto character : *code_points) {
    if (unicode_uppercase(character))
      return std::nullopt;
    if (escaped) {
      escaped = false;
      append_utf8(
          result,
          character == '_'
              ? character
              : map_unicode(character, unicode_tables::bmp_uppercase_mappings));
    } else if (character == '_') {
      escaped = true;
    } else {
      append_utf8(result, character);
    }
  }
  std::size_t prefixes = 0;
  while (prefixes < result.size() && result[prefixes] == '~')
    ++prefixes;
  if ((prefixes & 1U) != 0)
    return std::nullopt;
  result.erase(0, prefixes / 2);
  return result;
}

class Md5 final {
public:
  void update(std::string_view input) {
    for (const unsigned char value : input) {
      buffer_[buffer_size_++] = value;
      bit_count_ += 8;
      if (buffer_size_ == buffer_.size()) {
        transform(buffer_.data());
        buffer_size_ = 0;
      }
    }
  }

  [[nodiscard]] std::string finish() {
    const auto original_bits = bit_count_;
    buffer_[buffer_size_++] = 0x80;
    if (buffer_size_ > 56) {
      std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_),
                buffer_.end(), std::uint8_t{0});
      transform(buffer_.data());
      buffer_size_ = 0;
    }
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_),
              buffer_.begin() + 56, std::uint8_t{0});
    for (std::size_t index = 0; index < 8; ++index)
      buffer_[56 + index] =
          static_cast<std::uint8_t>(original_bits >> (index * 8));
    transform(buffer_.data());

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto word : state_) {
      for (std::size_t index = 0; index < 4; ++index) {
        output << std::setw(2)
               << static_cast<unsigned>((word >> (index * 8)) & 0xffU);
      }
    }
    return output.str();
  }

private:
  void transform(const std::uint8_t *block) {
    static constexpr std::array<std::uint32_t, 64> constants{
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
    static constexpr std::array<std::uint32_t, 64> shifts{
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    std::array<std::uint32_t, 16> words{};
    for (std::size_t index = 0; index < words.size(); ++index) {
      const auto offset = index * 4;
      words[index] = static_cast<std::uint32_t>(block[offset]) |
                     (static_cast<std::uint32_t>(block[offset + 1]) << 8) |
                     (static_cast<std::uint32_t>(block[offset + 2]) << 16) |
                     (static_cast<std::uint32_t>(block[offset + 3]) << 24);
    }
    auto a = state_[0];
    auto b = state_[1];
    auto c = state_[2];
    auto d = state_[3];
    for (std::uint32_t index = 0; index < 64; ++index) {
      std::uint32_t function = 0;
      std::uint32_t word = 0;
      if (index < 16) {
        function = (b & c) | (~b & d);
        word = index;
      } else if (index < 32) {
        function = (d & b) | (~d & c);
        word = (5 * index + 1) % 16;
      } else if (index < 48) {
        function = b ^ c ^ d;
        word = (3 * index + 5) % 16;
      } else {
        function = c ^ (b | ~d);
        word = (7 * index) % 16;
      }
      const auto next = d;
      d = c;
      c = b;
      b += std::rotl(a + function + constants[index] + words[word],
                     static_cast<int>(shifts[index]));
      a = next;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
  }

  std::array<std::uint32_t, 4> state_{0x67452301, 0xefcdab89, 0x98badcfe,
                                      0x10325476};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffer_size_ = 0;
  std::uint64_t bit_count_ = 0;
};

std::string md5_lines(const std::vector<std::string> &lines) {
  Md5 digest;
  for (const auto &line : lines)
    digest.update(line);
  return digest.finish();
}

std::filesystem::path checked_root(std::filesystem::path root) {
  if (root.empty())
    throw std::invalid_argument("local filesystem root is empty");
  root = std::filesystem::absolute(std::move(root)).lexically_normal();
  std::error_code error;
  if (!std::filesystem::is_directory(root, error) || error) {
    throw LocalFileSystemNotFoundError("local filesystem root not found: " +
                                       root.string());
  }
  auto canonical = std::filesystem::weakly_canonical(root, error);
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to canonicalize local filesystem root", root, error);
  }
  return canonical;
}

void validate_existing_name(std::string_view name, std::size_t maximum_bytes) {
  if (name.empty() || name.size() > maximum_bytes ||
      !LocalFileSystem::valid_utf8(name)) {
    throw LocalFileSystemInvalidNameError(
        "stored project name is empty, too long, or invalid UTF-8");
  }
  constexpr std::string_view structurally_invalid = "/\\:\0";
  for (const unsigned char character : name) {
    if (character < 0x20 || character == 0x7f ||
        structurally_invalid.find(static_cast<char>(character)) !=
            std::string_view::npos) {
      throw LocalFileSystemInvalidNameError(
          "stored project name contains a structural delimiter");
    }
  }
}

void validate_existing_path(std::string_view value,
                            std::size_t maximum_name_bytes) {
  if (value.empty() || value.front() != '/') {
    throw LocalFileSystemInvalidNameError(
        "stored project path is not absolute");
  }
  if (value == "/")
    return;
  if (value.back() == '/' || value.find("//") != std::string_view::npos) {
    throw LocalFileSystemInvalidNameError(
        "stored project path is not canonical");
  }
  for (const auto &component : split(value.substr(1), '/')) {
    if (component == "." || component == "..") {
      throw LocalFileSystemInvalidNameError(
          "stored project path contains traversal");
    }
    validate_existing_name(component, maximum_name_bytes);
  }
}

} // namespace

struct LocalFileSystem::Impl final
    : public std::enable_shared_from_this<LocalFileSystem::Impl> {
  struct Entry final {
    std::string parent;
    std::string name;
    std::string storage_name;
    std::optional<std::string> file_id;
  };

  Impl(std::filesystem::path root_value, bool versioned_value,
       bool read_only_value, LocalFileSystemSchema schema_value)
      : root(std::move(root_value)), versioned(versioned_value),
        read_only(read_only_value), schema(schema_value),
        context(std::make_shared<LocalFileSystemContext>(root)) {
    context->versioned = versioned;
    context->read_only = read_only;
    folders.insert("/");
  }

  void install_hooks() {
    const std::weak_ptr<Impl> weak = shared_from_this();
    context->item_created = [weak](std::string_view parent,
                                   std::string_view name) {
      if (const auto self = weak.lock())
        self->item_created(parent, name);
    };
    context->item_changed = [weak](std::string_view parent,
                                   std::string_view name) {
      if (const auto self = weak.lock(); self && !self->suppress_item_changed) {
        self->emit({LocalFileSystemEventKind::item_changed,
                    std::string(parent),
                    std::string(name),
                    {},
                    {}});
      }
    };
    context->item_deleted = [weak](std::string_view parent,
                                   std::string_view name) {
      if (const auto self = weak.lock())
        self->item_deleted(parent, name);
    };
    context->item_file_id_changed =
        [weak](std::string_view parent, std::string_view name,
               const std::optional<std::string> &old_id,
               const std::optional<std::string> &new_id) {
          if (const auto self = weak.lock())
            self->file_id_changed(parent, name, old_id, new_id);
        };
  }

  void require_online() const {
    if (!online || !context->online)
      throw LocalFileSystemError("local filesystem is disposed");
  }

  void require_writable() const {
    require_online();
    if (read_only)
      throw LocalItemReadOnlyError("local filesystem is read-only");
  }

  void emit(LocalFileSystemEvent event) const {
    if (online && event_sink)
      event_sink(event);
  }

  [[nodiscard]] bool indexed() const noexcept {
    return schema != LocalFileSystemSchema::mangled;
  }

  [[nodiscard]] std::filesystem::path
  storage_directory(std::string_view storage_name) const {
    if (!is_hex_storage_name(storage_name))
      throw LocalFileSystemIndexError("bad indexed storage name");
    auto result =
        root / std::string(storage_name.substr(storage_name.size() - 3, 2));
    reject_symbolic_link_path(root, result);
    return result;
  }

  [[nodiscard]] LocalItemIdentity identity(const Entry &entry) const {
    return {storage_directory(entry.storage_name), entry.storage_name,
            entry.parent, entry.name, true};
  }

  [[nodiscard]] std::filesystem::path
  mangled_folder(std::string_view path) const {
    validate_existing_path(path, 60);
    auto result = root;
    if (path == "/")
      return result;
    for (const auto &component : split(path.substr(1), '/'))
      result /= mangle_name(component);
    result = result.lexically_normal();
    reject_symbolic_link_path(root, result);
    return result;
  }

  [[nodiscard]] LocalItemIdentity
  mangled_identity(std::string_view parent, std::string_view name) const {
    return {mangled_folder(parent), mangle_name(name), std::string(parent),
            std::string(name), false};
  }

  [[nodiscard]] Entry &entry(std::string_view parent, std::string_view name) {
    const auto logical = LocalFileSystem::path(parent, name);
    const auto found = entries.find(logical);
    if (found == entries.end())
      throw LocalFileSystemNotFoundError("item not found: " + logical);
    return found->second;
  }

  [[nodiscard]] const Entry &entry(std::string_view parent,
                                   std::string_view name) const {
    const auto logical = LocalFileSystem::path(parent, name);
    const auto found = entries.find(logical);
    if (found == entries.end())
      throw LocalFileSystemNotFoundError("item not found: " + logical);
    return found->second;
  }

  void rebuild_file_ids() {
    file_ids.clear();
    if (schema != LocalFileSystemSchema::indexed_v1)
      return;
    for (const auto &[logical, value] : entries) {
      if (value.file_id)
        file_ids.insert_or_assign(*value.file_id, logical);
    }
  }

  void add_parent_folders(std::string path) {
    while (path != "/") {
      folders.insert(path);
      path = LocalFileSystem::parent_path(path);
    }
    folders.insert("/");
  }

  std::vector<std::string> create_missing_folders(std::string_view path) {
    std::vector<std::string> missing;
    std::string current = "/";
    if (path != "/") {
      for (const auto &component : split(path.substr(1), '/')) {
        current = LocalFileSystem::path(current, component);
        if (!folders.contains(current))
          missing.push_back(current);
      }
    }
    return missing;
  }

  void append_journal(std::string_view line) {
    reject_symbolic_link_file(root / std::string(journal_file_name));
    std::ofstream output(root / std::string(journal_file_name),
                         std::ios::binary | std::ios::app);
    if (!output)
      throw LocalFileSystemIndexError("unable to open filesystem journal");
    output << line << '\n';
    output.flush();
    if (!output)
      throw LocalFileSystemIndexError("unable to update filesystem journal");
  }

  void append_journal(const std::vector<std::string> &lines) {
    if (lines.empty())
      return;
    reject_symbolic_link_file(root / std::string(journal_file_name));
    std::ofstream output(root / std::string(journal_file_name),
                         std::ios::binary | std::ios::app);
    if (!output)
      throw LocalFileSystemIndexError("unable to open filesystem journal");
    for (const auto &line : lines)
      output << line << '\n';
    output.flush();
    if (!output)
      throw LocalFileSystemIndexError("unable to update filesystem journal");
  }

  [[nodiscard]] std::vector<std::string>
  index_payload_lines(std::uint64_t next_id) const {
    std::vector<std::string> payload;
    if (schema == LocalFileSystemSchema::indexed_v1)
      payload.emplace_back("VERSION=1");

    std::function<void(const std::string &)> visit =
        [&](const std::string &folder) {
          payload.push_back(folder);
          for (const auto &[logical, value] : entries) {
            (void)logical;
            if (value.parent != folder)
              continue;
            auto line = value.storage_name + ":" + value.name;
            if (schema == LocalFileSystemSchema::indexed_v1 && value.file_id)
              line += ":" + *value.file_id;
            payload.push_back(line);
          }
          std::vector<std::string> children;
          for (const auto &candidate : folders) {
            if (candidate != "/" &&
                LocalFileSystem::parent_path(candidate) == folder)
              children.push_back(candidate);
          }
          for (const auto &child : children)
            visit(child);
        };
    visit("/");
    std::ostringstream id;
    id << "NEXT-ID:" << std::hex << next_id;
    payload.push_back(id.str());
    return payload;
  }

  void write_index() {
    if (!indexed())
      return;
    require_writable();
    const auto payload = index_payload_lines(next_storage_id);
    const auto temporary = root / std::string(temporary_index_file_name);
    const auto index = root / std::string(index_file_name);
    const auto backup = root / std::string(backup_index_file_name);
    const auto journal = root / std::string(journal_file_name);
    const auto journal_backup = root / std::string(backup_journal_file_name);

    reject_symbolic_link_file(temporary);
    reject_symbolic_link_file(index);
    reject_symbolic_link_file(backup);
    reject_symbolic_link_file(journal);
    reject_symbolic_link_file(journal_backup);

    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    {
      std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
      if (!output)
        throw LocalFileSystemIndexError("unable to create temporary index");
      for (std::size_t index_value = 0; index_value < payload.size();
           ++index_value) {
        const auto &line = payload[index_value];
        const bool item_line = !line.empty() && line.front() != '/' &&
                               !line.starts_with("VERSION=") &&
                               !line.starts_with("NEXT-ID:");
        output << (item_line ? "  " : "") << line << '\n';
      }
      output << "MD5:" << upstream_index_md5 << '\n';
      output.flush();
      if (!output)
        throw LocalFileSystemIndexError("unable to write temporary index");
    }

    std::filesystem::remove(backup, ignored);
    ignored.clear();
    std::filesystem::remove(journal_backup, ignored);
    bool index_backed_up = false;
    bool journal_backed_up = false;
    try {
      if (std::filesystem::exists(index)) {
        std::filesystem::rename(index, backup);
        index_backed_up = true;
      }
      if (std::filesystem::exists(journal)) {
        std::filesystem::rename(journal, journal_backup);
        journal_backed_up = true;
      }
      std::filesystem::rename(temporary, index);
    } catch (...) {
      std::filesystem::remove(index, ignored);
      if (index_backed_up) {
        ignored.clear();
        std::filesystem::rename(backup, index, ignored);
      }
      if (journal_backed_up) {
        ignored.clear();
        std::filesystem::rename(journal_backup, journal, ignored);
      }
      std::filesystem::remove(temporary, ignored);
      throw;
    }
    std::filesystem::remove(backup, ignored);
    ignored.clear();
    std::filesystem::remove(journal_backup, ignored);
  }

  void parse_index() {
    const auto file = root / std::string(index_file_name);
    reject_symbolic_link_file(file);
    std::ifstream input(file, std::ios::binary);
    if (!input)
      throw LocalFileSystemIndexError("filesystem index not found");
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      lines.push_back(line);
    }
    if (lines.empty())
      throw LocalFileSystemIndexError("empty filesystem index");

    auto parsed_schema = LocalFileSystemSchema::indexed_v0;
    std::map<std::string, Entry, std::less<>> parsed_entries;
    std::set<std::string, std::less<>> parsed_folders{"/"};
    std::size_t cursor = 0;
    if (lines.front().starts_with("VERSION=")) {
      const auto version = lines.front().substr(8);
      if (version != "1")
        throw LocalFileSystemIndexError("unsupported filesystem index version");
      parsed_schema = LocalFileSystemSchema::indexed_v1;
      ++cursor;
    }
    std::vector<std::string> digest_lines;
    if (parsed_schema == LocalFileSystemSchema::indexed_v1)
      digest_lines.push_back("VERSION=1");
    std::string current_folder;
    std::optional<std::uint64_t> parsed_next;
    std::optional<std::string> expected_md5;
    for (; cursor < lines.size(); ++cursor) {
      const auto &raw = lines[cursor];
      if (raw.starts_with("MD5:")) {
        expected_md5 = raw.substr(4);
        if (cursor + 1 != lines.size())
          throw LocalFileSystemIndexError("content follows index digest");
        continue;
      }
      if (raw.starts_with("NEXT-ID:")) {
        parsed_next = parse_hex(std::string_view(raw).substr(8), "NEXT-ID");
        digest_lines.push_back(raw);
        continue;
      }
      if (!raw.empty() && raw.front() == '/') {
        current_folder = raw;
        validate_existing_path(current_folder, 254);
        parsed_folders.insert(current_folder);
        digest_lines.push_back(raw);
        continue;
      }
      if (!raw.starts_with("  ") || current_folder.empty())
        throw LocalFileSystemIndexError("invalid filesystem index entry");
      const auto encoded = raw.substr(2);
      const auto fields = split(encoded, ':');
      const auto valid_field_count =
          parsed_schema == LocalFileSystemSchema::indexed_v1
              ? fields.size() >= 2 && fields.size() <= 3
              : fields.size() == 2;
      if (!valid_field_count || !is_hex_storage_name(fields[0]) ||
          fields[1].empty()) {
        throw LocalFileSystemIndexError("invalid filesystem item entry");
      }
      Entry value{current_folder, fields[1], fields[0], std::nullopt};
      validate_existing_name(value.name, 254);
      if (fields.size() == 3 && !fields[2].empty() && fields[2] != "null")
        value.file_id = fields[2];
      const auto logical = LocalFileSystem::path(value.parent, value.name);
      if (!parsed_entries.emplace(logical, std::move(value)).second)
        throw LocalFileSystemIndexError("duplicate logical item in index");
      digest_lines.push_back(encoded);
    }
    const auto normalized_md5 =
        expected_md5 ? lower_ascii(*expected_md5) : std::string{};
    if (!parsed_next || !expected_md5 ||
        (normalized_md5 != upstream_index_md5 &&
         normalized_md5 != md5_lines(digest_lines))) {
      throw LocalFileSystemIndexError("invalid filesystem index digest");
    }
    schema = parsed_schema;
    entries = std::move(parsed_entries);
    folders = std::move(parsed_folders);
    next_storage_id = *parsed_next;
    rebuild_file_ids();
  }

  void apply_journal_line(std::string_view line) {
    const auto fields = split(line, ':');
    if (fields.empty())
      throw LocalFileSystemIndexError("empty filesystem journal entry");
    if (fields[0] == "FADD" && fields.size() == 2) {
      validate_existing_path(fields[1], 254);
      add_parent_folders(fields[1]);
      return;
    }
    if (fields[0] == "FDEL" && fields.size() == 2) {
      validate_existing_path(fields[1], 254);
      folders.erase(fields[1]);
      return;
    }
    if (fields[0] == "FMV" && fields.size() == 3) {
      validate_existing_path(fields[1], 254);
      validate_existing_path(fields[2], 254);
      rename_folder_prefix(fields[1], fields[2]);
      return;
    }
    if (fields[0] == "IADD" && fields.size() == 3) {
      if (!is_hex_storage_name(fields[1]))
        throw LocalFileSystemIndexError("invalid journal storage name");
      validate_existing_path(fields[2], 254);
      const auto parent = LocalFileSystem::parent_path(fields[2]);
      const auto name = LocalFileSystem::basename(fields[2]);
      Entry value{parent, name, fields[1], std::nullopt};
      entries.insert_or_assign(fields[2], std::move(value));
      const auto id = parse_hex(fields[1], "journal storage name");
      next_storage_id = (std::max)(next_storage_id, id + 1);
      add_parent_folders(parent);
      return;
    }
    if (fields[0] == "IDEL" && fields.size() == 2) {
      validate_existing_path(fields[1], 254);
      entries.erase(fields[1]);
      return;
    }
    if (fields[0] == "IMV" && fields.size() == 3) {
      validate_existing_path(fields[1], 254);
      validate_existing_path(fields[2], 254);
      const auto found = entries.find(fields[1]);
      if (found == entries.end())
        throw LocalFileSystemIndexError("journal item move source missing");
      auto value = found->second;
      entries.erase(found);
      value.parent = LocalFileSystem::parent_path(fields[2]);
      value.name = LocalFileSystem::basename(fields[2]);
      entries.insert_or_assign(fields[2], std::move(value));
      add_parent_folders(LocalFileSystem::parent_path(fields[2]));
      return;
    }
    if (fields[0] == "IDSET" && fields.size() == 3) {
      validate_existing_path(fields[1], 254);
      const auto found = entries.find(fields[1]);
      if (found == entries.end())
        throw LocalFileSystemIndexError("journal file-id item missing");
      found->second.file_id = fields[2].empty() || fields[2] == "null"
                                  ? std::nullopt
                                  : std::optional<std::string>(fields[2]);
      return;
    }
    throw LocalFileSystemIndexError("invalid filesystem journal entry");
  }

  void replay_journal() {
    const auto journal = root / std::string(journal_file_name);
    reject_symbolic_link_file(journal);
    if (!std::filesystem::exists(journal))
      return;
    std::ifstream input(journal, std::ios::binary);
    if (!input)
      throw LocalFileSystemIndexError("unable to read filesystem journal");
    const auto saved_entries = entries;
    const auto saved_folders = folders;
    const auto saved_file_ids = file_ids;
    const auto saved_next_storage_id = next_storage_id;
    try {
      std::string line;
      while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r')
          line.pop_back();
        apply_journal_line(line);
      }
      if (!input.eof())
        throw LocalFileSystemIndexError("unable to read filesystem journal");
      input.close();
      rebuild_file_ids();
    } catch (...) {
      entries = saved_entries;
      folders = saved_folders;
      file_ids = saved_file_ids;
      next_storage_id = saved_next_storage_id;
      throw;
    }
    if (!read_only)
      write_index();
  }

  void reconcile_indexed_properties() {
    if (!indexed())
      return;
    for (const auto &[logical, value] : entries) {
      (void)logical;
      ItemPropertyFile property(storage_directory(value.storage_name),
                                value.storage_name, value.parent, value.name,
                                true);
      if (!property.exists()) {
        throw LocalFileSystemIndexError("indexed item property is missing: " +
                                        logical);
      }
      const bool stale_identity = property.parent_path() != value.parent ||
                                  property.name() != value.name;
      const bool stale_file_id = schema == LocalFileSystemSchema::indexed_v1 &&
                                 property.file_id() != value.file_id;
      if (!stale_identity && !stale_file_id) {
        continue;
      }
      if (read_only) {
        throw LocalFileSystemIndexError(
            "indexed item property identity is stale: " + logical);
      }
      if (stale_identity) {
        property.move_to(storage_directory(value.storage_name),
                         value.storage_name, value.parent, value.name);
      }
      if (stale_file_id) {
        property.set_file_id(value.file_id);
        property.write_state();
      }
    }
  }

  void rebuild_index(std::string reason = {}, const TaskContext &task = {}) {
    require_writable();
    task.checkpoint();
    const auto saved_entries = entries;
    const auto saved_folders = folders;
    const auto saved_file_ids = file_ids;
    const auto saved_next_storage_id = next_storage_id;
    const auto saved_schema = schema;
    try {
      entries.clear();
      folders.clear();
      folders.insert("/");
      next_storage_id = 0;
      std::vector<std::string> diagnostics;
      if (!reason.empty())
        diagnostics.push_back(std::move(reason));
      struct PropertyCandidate final {
        std::filesystem::path directory;
        std::filesystem::path path;
        std::string storage;
      };
      std::vector<std::filesystem::path> shards;
      std::vector<PropertyCandidate> properties;
      std::error_code error;
      for (std::filesystem::directory_iterator directories(root, error), end;
           !error && directories != end; directories.increment(error)) {
        task.checkpoint();
        if (directories->is_symlink(error) && !error) {
          throw LocalFileSystemError(
              "indexed storage shard is a symbolic link: " +
              directories->path().string());
        }
        if (!directories->is_directory())
          continue;
        const auto directory_name = directories->path().filename().string();
        if (directory_name.size() != 2 ||
            !std::all_of(
                directory_name.begin(), directory_name.end(),
                [](unsigned char value) { return std::isxdigit(value) != 0; }))
          continue;
        shards.push_back(directories->path());
      }
      if (error)
        throw std::filesystem::filesystem_error(
            "unable to scan indexed filesystem", root, error);

      const auto shard_total = static_cast<std::uint64_t>(shards.size());
      task.report("filesystem-index-scan", 0, shard_total);
      for (std::size_t shard_index = 0; shard_index < shards.size();
           ++shard_index) {
        const auto &shard = shards[shard_index];
        std::error_code shard_error;
        for (std::filesystem::directory_iterator files(shard, shard_error),
             files_end;
             !shard_error && files != files_end; files.increment(shard_error)) {
          task.checkpoint();
          if (!files->is_regular_file() || files->path().extension() != ".prp")
            continue;
          const auto storage = files->path().stem().string();
          if (!is_hex_storage_name(storage))
            continue;
          properties.push_back({shard, files->path(), storage});
        }
        if (shard_error)
          throw std::filesystem::filesystem_error(
              "unable to scan indexed filesystem shard", shard, shard_error);
        task.report("filesystem-index-scan",
                    static_cast<std::uint64_t>(shard_index) + 1, shard_total);
      }

      const auto total = static_cast<std::uint64_t>(properties.size());
      task.report("filesystem-index-rebuild", 0, total);
      for (std::size_t property_index = 0; property_index < properties.size();
           ++property_index) {
        const auto &candidate = properties[property_index];
        task.checkpoint();
        const auto &storage = candidate.storage;
        try {
          ItemPropertyFile property(candidate.directory, storage, {}, {}, true);
          if (property.name().empty() || property.parent_path().empty())
            throw LocalFileSystemIndexError(
                "indexed property has no logical identity");
          validate_existing_name(property.name(), 254);
          validate_existing_path(property.parent_path(), 254);
          Entry value{property.parent_path(), property.name(), storage,
                      property.file_id()};
          const auto logical = LocalFileSystem::path(value.parent, value.name);
          const auto conflict = entries.find(logical);
          if (conflict == entries.end()) {
            entries.insert_or_assign(logical, std::move(value));
          } else if (storage > conflict->second.storage_name) {
            diagnostics.push_back(
                "orphaned duplicate indexed property: " +
                (storage_directory(conflict->second.storage_name) /
                 (conflict->second.storage_name + ".prp"))
                    .string());
            entries.insert_or_assign(logical, std::move(value));
          } else {
            diagnostics.push_back("orphaned duplicate indexed property: " +
                                  candidate.path.string());
          }
          add_parent_folders(property.parent_path());
          next_storage_id =
              (std::max)(next_storage_id,
                         parse_hex(storage, "indexed property storage") + 1);
        } catch (const std::exception &exception) {
          diagnostics.push_back("invalid indexed property " +
                                candidate.path.string() + ": " +
                                exception.what());
        }
        task.report("filesystem-index-rebuild",
                    static_cast<std::uint64_t>(property_index) + 1, total);
      }
      schema = LocalFileSystemSchema::indexed_v1;
      rebuild_file_ids();
      // The index and diagnostics are a single non-cancellable publication
      // phase. Cancellation before this point restores the prior in-memory
      // state and leaves the existing on-disk repair inputs untouched.
      task.checkpoint();
      const auto diagnostic_file = root / std::string(rebuild_error_file_name);
      reject_symbolic_link_file(diagnostic_file);
      if (diagnostics.empty()) {
        std::error_code ignored;
        std::filesystem::remove(diagnostic_file, ignored);
      } else {
        std::ofstream output(diagnostic_file,
                             std::ios::binary | std::ios::trunc);
        if (!output)
          throw LocalFileSystemIndexError(
              "unable to create filesystem rebuild diagnostics");
        for (const auto &diagnostic : diagnostics)
          output << diagnostic << '\n';
        output.flush();
        if (!output)
          throw LocalFileSystemIndexError(
              "unable to write filesystem rebuild diagnostics");
      }
      write_index();
    } catch (...) {
      entries = saved_entries;
      folders = saved_folders;
      file_ids = saved_file_ids;
      next_storage_id = saved_next_storage_id;
      schema = saved_schema;
      throw;
    }
  }

  void rename_folder_prefix(std::string_view old_path,
                            std::string_view new_path) {
    std::set<std::string, std::less<>> next_folders;
    for (const auto &folder : folders) {
      if (folder == old_path ||
          (folder.size() > old_path.size() && folder.starts_with(old_path) &&
           folder[old_path.size()] == '/')) {
        next_folders.insert(std::string(new_path) +
                            folder.substr(old_path.size()));
      } else {
        next_folders.insert(folder);
      }
    }
    std::map<std::string, Entry, std::less<>> next_entries;
    for (auto [logical, value] : entries) {
      (void)logical;
      if (value.parent == old_path || (value.parent.size() > old_path.size() &&
                                       value.parent.starts_with(old_path) &&
                                       value.parent[old_path.size()] == '/')) {
        value.parent =
            std::string(new_path) + value.parent.substr(old_path.size());
      }
      next_entries.emplace(LocalFileSystem::path(value.parent, value.name),
                           std::move(value));
    }
    folders = std::move(next_folders);
    entries = std::move(next_entries);
    rebuild_file_ids();
  }

  struct ItemRelocation final {
    std::unique_ptr<LocalDatabaseItem> item;
    LocalItemIdentity old_identity;
    LocalItemIdentity new_identity;
  };

  void rollback_item_relocations(std::vector<ItemRelocation> &relocations,
                                 std::size_t moved_count) noexcept {
    suppress_item_changed = true;
    while (moved_count != 0) {
      --moved_count;
      try {
        relocations[moved_count].item->move_to(
            relocations[moved_count].old_identity);
      } catch (...) {
      }
    }
    suppress_item_changed = false;
  }

  [[nodiscard]] std::vector<ItemRelocation>
  relocate_folder_items(std::string_view old_path, std::string_view new_path) {
    std::vector<ItemRelocation> relocations;
    for (const auto &[logical, value] : entries) {
      (void)logical;
      if (value.parent != old_path &&
          !value.parent.starts_with(std::string(old_path) + "/")) {
        continue;
      }
      auto opened = LocalDatabaseItem::open_existing(context, identity(value));
      if (opened->parent_path() != value.parent ||
          opened->name() != value.name) {
        throw LocalFileSystemIndexError(
            "indexed item property identity disagrees with filesystem index");
      }
      const auto next_parent =
          std::string(new_path) + value.parent.substr(old_path.size());
      relocations.push_back(
          {std::move(opened),
           identity(value),
           {storage_directory(value.storage_name), value.storage_name,
            next_parent, value.name, true}});
    }

    std::size_t moved_count = 0;
    suppress_item_changed = true;
    try {
      for (auto &relocation : relocations) {
        relocation.item->move_to(relocation.new_identity);
        ++moved_count;
      }
      suppress_item_changed = false;
    } catch (...) {
      suppress_item_changed = false;
      rollback_item_relocations(relocations, moved_count);
      throw;
    }
    return relocations;
  }

  LocalItemIdentity allocate(std::string parent, std::string name) {
    require_writable();
    if (indexed() && folders.contains(parent))
      validate_existing_path(parent, 254);
    else
      LocalFileSystem::validate_path(parent, indexed() ? 254 : 60);
    LocalFileSystem::validate_name(name, indexed() ? 254 : 60);
    if (indexed()) {
      const auto logical = LocalFileSystem::path(parent, name);
      if (entries.contains(logical))
        throw LocalFileSystemDuplicateError("item already exists: " + logical);
      const auto missing = create_missing_folders(parent);
      std::ostringstream storage;
      storage << std::hex << std::setw(8) << std::setfill('0')
              << next_storage_id;
      const auto storage_name = storage.str();
      const auto storage_dir = storage_directory(storage_name);
      std::error_code error;
      std::filesystem::create_directories(storage_dir, error);
      if (error)
        throw std::filesystem::filesystem_error(
            "unable to create indexed storage directory", storage_dir, error);
      std::vector<std::string> journal_lines;
      for (const auto &folder : missing)
        journal_lines.push_back("FADD:" + folder);
      journal_lines.push_back("IADD:" + storage_name + ":" + logical);
      append_journal(journal_lines);
      for (const auto &folder : missing) {
        folders.insert(folder);
        emit({LocalFileSystemEventKind::folder_created,
              LocalFileSystem::parent_path(folder),
              LocalFileSystem::basename(folder),
              {},
              {}});
      }
      ++next_storage_id;
      Entry value{parent, name, storage_name, std::nullopt};
      entries.emplace(logical, value);
      return identity(value);
    }

    auto result = mangled_identity(parent, name);
    if (std::filesystem::exists(result.storage_directory /
                                (result.storage_name + ".prp"))) {
      throw LocalFileSystemDuplicateError("item already exists: " +
                                          LocalFileSystem::path(parent, name));
    }
    std::error_code error;
    std::filesystem::create_directories(result.storage_directory, error);
    if (error)
      throw std::filesystem::filesystem_error("unable to create mangled folder",
                                              result.storage_directory, error);
    return result;
  }

  void deallocate(std::string_view parent, std::string_view name, bool notify) {
    if (!indexed())
      return;
    const auto logical = LocalFileSystem::path(parent, name);
    const auto found = entries.find(logical);
    if (found == entries.end())
      return;
    append_journal("IDEL:" + logical);
    entries.erase(found);
    rebuild_file_ids();
    write_index();
    if (notify)
      emit({LocalFileSystemEventKind::item_deleted,
            std::string(parent),
            std::string(name),
            {},
            {}});
  }

  void item_created(std::string_view parent, std::string_view name) {
    std::scoped_lock lock(context->mutex);
    if (!online)
      return;
    if (indexed()) {
      auto &value = entry(parent, name);
      ItemPropertyFile property(storage_directory(value.storage_name),
                                value.storage_name, value.parent, value.name,
                                true);
      value.file_id = property.file_id();
      rebuild_file_ids();
      write_index();
    }
    emit({LocalFileSystemEventKind::item_created,
          std::string(parent),
          std::string(name),
          {},
          {}});
  }

  void item_deleted(std::string_view parent, std::string_view name) {
    std::scoped_lock lock(context->mutex);
    if (!online)
      return;
    deallocate(parent, name, false);
    emit({LocalFileSystemEventKind::item_deleted,
          std::string(parent),
          std::string(name),
          {},
          {}});
  }

  void file_id_changed(std::string_view parent, std::string_view name,
                       const std::optional<std::string> &,
                       const std::optional<std::string> &new_id) {
    std::scoped_lock lock(context->mutex);
    if (!online || schema != LocalFileSystemSchema::indexed_v1)
      return;
    const auto logical = LocalFileSystem::path(parent, name);
    auto &value = entry(parent, name);
    append_journal("IDSET:" + logical + ":" +
                   (new_id ? *new_id : std::string("null")));
    value.file_id = new_id;
    rebuild_file_ids();
    write_index();
    emit({LocalFileSystemEventKind::file_id_changed,
          std::string(parent),
          std::string(name),
          {},
          {}});
  }

  std::filesystem::path root;
  bool versioned = false;
  bool read_only = false;
  bool online = true;
  bool suppress_item_changed = false;
  LocalFileSystemSchema schema = LocalFileSystemSchema::indexed_v1;
  std::shared_ptr<LocalFileSystemContext> context;
  EventSink event_sink;
  std::set<std::string, std::less<>> folders;
  std::map<std::string, Entry, std::less<>> entries;
  std::map<std::string, std::string, std::less<>> file_ids;
  std::uint64_t next_storage_id = 0;
};

LocalFileSystem::LocalFileSystem(std::shared_ptr<Impl> implementation)
    : impl_(std::move(implementation)) {}

LocalFileSystem::~LocalFileSystem() { dispose(); }

std::unique_ptr<LocalFileSystem>
LocalFileSystem::create(std::filesystem::path root, bool versioned,
                        bool read_only) {
  root = checked_root(std::move(root));
  if (read_only)
    throw LocalItemReadOnlyError(
        "cannot create an indexed filesystem in read-only mode");
  std::error_code empty_error;
  if (!std::filesystem::is_empty(root, empty_error) || empty_error) {
    throw LocalFileSystemError("new filesystem root is not empty");
  }
  auto impl = std::make_shared<Impl>(std::move(root), versioned, false,
                                     LocalFileSystemSchema::indexed_v1);
  impl->install_hooks();
  impl->write_index();
  return std::unique_ptr<LocalFileSystem>(new LocalFileSystem(std::move(impl)));
}

std::unique_ptr<LocalFileSystem>
LocalFileSystem::open(std::filesystem::path root, bool versioned,
                      bool read_only, bool repair_index,
                      const TaskContext &task) {
  root = checked_root(std::move(root));
  const auto index = root / std::string(index_file_name);
  const bool index_exists = std::filesystem::exists(index);
  const bool indexed_storage = !index_exists && has_indexed_storage(root);
  auto schema = index_exists || indexed_storage
                    ? LocalFileSystemSchema::indexed_v1
                    : LocalFileSystemSchema::mangled;
  auto impl =
      std::make_shared<Impl>(std::move(root), versioned, read_only, schema);
  impl->install_hooks();
  if (index_exists) {
    try {
      impl->parse_index();
      impl->replay_journal();
      impl->reconcile_indexed_properties();
    } catch (const std::exception &exception) {
      if (!repair_index || read_only)
        throw;
      impl->rebuild_index(
          "index repair triggered: " + std::string(exception.what()), task);
    }
  } else if (indexed_storage) {
    if (!repair_index || read_only) {
      throw LocalFileSystemIndexError(
          "indexed filesystem storage exists but its index is missing");
    }
    impl->rebuild_index(
        "filesystem index missing; rebuilt from indexed properties", task);
  }
  return std::unique_ptr<LocalFileSystem>(new LocalFileSystem(std::move(impl)));
}

const std::filesystem::path &LocalFileSystem::root() const noexcept {
  return impl_->root;
}

LocalFileSystemSchema LocalFileSystem::schema() const noexcept {
  return impl_->schema;
}

bool LocalFileSystem::versioned() const noexcept { return impl_->versioned; }

bool LocalFileSystem::read_only() const noexcept { return impl_->read_only; }

bool LocalFileSystem::online() const noexcept { return impl_->online; }

void LocalFileSystem::set_event_sink(EventSink sink) {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  impl_->event_sink = std::move(sink);
}

void LocalFileSystem::dispose() noexcept {
  if (!impl_)
    return;
  std::scoped_lock lock(impl_->context->mutex);
  impl_->online = false;
  impl_->context->online = false;
  impl_->event_sink = {};
}

void LocalFileSystem::refresh() {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  if (impl_->indexed()) {
    impl_->parse_index();
    impl_->replay_journal();
    impl_->reconcile_indexed_properties();
  }
}

void LocalFileSystem::flush_index() {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->write_index();
}

bool LocalFileSystem::folder_exists(std::string_view value) const {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  validate_existing_path(value, impl_->indexed() ? 254 : 60);
  return impl_->indexed()
             ? impl_->folders.contains(value)
             : std::filesystem::is_directory(impl_->mangled_folder(value));
}

bool LocalFileSystem::item_exists(std::string_view parent,
                                  std::string_view name) const {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  validate_existing_path(parent, impl_->indexed() ? 254 : 60);
  validate_existing_name(name, impl_->indexed() ? 254 : 60);
  if (impl_->indexed())
    return impl_->entries.contains(path(parent, name));
  const auto identity = impl_->mangled_identity(parent, name);
  return std::filesystem::is_regular_file(identity.storage_directory /
                                          (identity.storage_name + ".prp"));
}

std::vector<std::string>
LocalFileSystem::folder_names(std::string_view value) const {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  validate_existing_path(value, impl_->indexed() ? 254 : 60);
  std::vector<std::string> result;
  if (impl_->indexed()) {
    if (!impl_->folders.contains(value))
      throw LocalFileSystemNotFoundError("folder not found: " +
                                         std::string(value));
    for (const auto &candidate : impl_->folders) {
      if (candidate != "/" && parent_path(candidate) == value)
        result.push_back(basename(candidate));
    }
  } else {
    const auto folder = impl_->mangled_folder(value);
    if (!std::filesystem::is_directory(folder))
      throw LocalFileSystemNotFoundError("folder not found: " +
                                         std::string(value));
    for (const auto &candidate : std::filesystem::directory_iterator(folder)) {
      if (!candidate.is_directory())
        continue;
      if (const auto decoded =
              demangle_name(candidate.path().filename().string()))
        result.push_back(*decoded);
    }
    std::sort(result.begin(), result.end());
  }
  return result;
}

std::vector<std::string>
LocalFileSystem::item_names(std::string_view value, bool include_hidden) const {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  validate_existing_path(value, impl_->indexed() ? 254 : 60);
  std::vector<std::string> result;
  if (impl_->indexed()) {
    if (!impl_->folders.contains(value))
      throw LocalFileSystemNotFoundError("folder not found: " +
                                         std::string(value));
    for (const auto &[logical, entry] : impl_->entries) {
      (void)logical;
      if (entry.parent == value &&
          (include_hidden || !entry.name.starts_with(hidden_item_prefix)))
        result.push_back(entry.name);
    }
  } else {
    const auto folder = impl_->mangled_folder(value);
    if (!std::filesystem::is_directory(folder))
      throw LocalFileSystemNotFoundError("folder not found: " +
                                         std::string(value));
    for (const auto &candidate : std::filesystem::directory_iterator(folder)) {
      if (!candidate.is_regular_file() ||
          candidate.path().extension() != ".prp")
        continue;
      if (const auto decoded = demangle_name(candidate.path().stem().string());
          decoded &&
          (include_hidden || !decoded->starts_with(hidden_item_prefix)))
        result.push_back(*decoded);
    }
    std::sort(result.begin(), result.end());
  }
  return result;
}

std::size_t LocalFileSystem::item_count() const {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  if (impl_->indexed())
    return impl_->entries.size();
  std::size_t count = 0;
  std::function<void(const std::string &)> visit =
      [&](const std::string &folder) {
        count += item_names(folder, true).size();
        for (const auto &child : folder_names(folder))
          visit(path(folder, child));
      };
  visit("/");
  return count;
}

void LocalFileSystem::create_folder(std::string parent, std::string name) {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_writable();
  if (impl_->indexed() && impl_->folders.contains(parent))
    validate_existing_path(parent, 254);
  else
    validate_path(parent, impl_->indexed() ? 254 : 60);
  validate_name(name, impl_->indexed() ? 254 : 60);
  const auto logical = path(parent, name);
  if (impl_->indexed()) {
    const auto missing = impl_->create_missing_folders(parent);
    if (impl_->folders.contains(logical))
      return;
    std::vector<std::string> lines;
    for (const auto &folder : missing)
      lines.push_back("FADD:" + folder);
    lines.push_back("FADD:" + logical);
    impl_->append_journal(lines);
    for (const auto &folder : missing)
      impl_->folders.insert(folder);
    impl_->folders.insert(logical);
    impl_->write_index();
  } else {
    const auto physical = impl_->mangled_folder(logical);
    std::error_code error;
    std::filesystem::create_directories(physical, error);
    if (error)
      throw std::filesystem::filesystem_error("folder creation failed",
                                              physical, error);
  }
  impl_->emit({LocalFileSystemEventKind::folder_created, parent, name, {}, {}});
}

void LocalFileSystem::delete_folder(std::string value) {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_writable();
  validate_existing_path(value, impl_->indexed() ? 254 : 60);
  if (value == "/")
    throw LocalFileSystemError("root folder may not be deleted");
  if (!folder_exists(value))
    return;
  if (!folder_names(value).empty() || !item_names(value, true).empty())
    throw LocalFileSystemError("folder is not empty: " + value);
  if (impl_->indexed()) {
    impl_->append_journal("FDEL:" + value);
    impl_->folders.erase(value);
    impl_->write_index();
  } else {
    std::error_code error;
    if (!std::filesystem::remove(impl_->mangled_folder(value), error) || error)
      throw std::filesystem::filesystem_error(
          "folder deletion failed", impl_->mangled_folder(value), error);
  }
  impl_->emit({LocalFileSystemEventKind::folder_deleted,
               parent_path(value),
               basename(value),
               {},
               {}});
}

void LocalFileSystem::move_folder(std::string parent, std::string name,
                                  std::string new_parent) {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_writable();
  const auto old_path = path(parent, name);
  const auto new_path = path(new_parent, name);
  validate_existing_path(old_path, impl_->indexed() ? 254 : 60);
  if (impl_->indexed() && impl_->folders.contains(new_parent))
    validate_existing_path(new_parent, 254);
  else
    validate_path(new_parent, impl_->indexed() ? 254 : 60);
  if (old_path == new_path)
    return;
  if (new_parent == old_path || new_parent.starts_with(old_path + "/"))
    throw LocalFileSystemInvalidNameError("folder cannot move into itself");
  if (!folder_exists(old_path))
    throw LocalFileSystemNotFoundError("folder not found: " + old_path);
  if (folder_exists(new_path))
    throw LocalFileSystemDuplicateError("folder already exists: " + new_path);
  if (impl_->indexed()) {
    const auto missing = impl_->create_missing_folders(new_parent);
    auto relocations = impl_->relocate_folder_items(old_path, new_path);
    std::vector<std::string> lines;
    for (const auto &folder : missing)
      lines.push_back("FADD:" + folder);
    lines.push_back("FMV:" + old_path + ":" + new_path);
    try {
      impl_->append_journal(lines);
    } catch (...) {
      impl_->rollback_item_relocations(relocations, relocations.size());
      throw;
    }
    for (const auto &folder : missing)
      impl_->folders.insert(folder);
    impl_->rename_folder_prefix(old_path, new_path);
    impl_->write_index();
    for (const auto &folder : missing) {
      impl_->emit({LocalFileSystemEventKind::folder_created,
                   parent_path(folder),
                   basename(folder),
                   {},
                   {}});
    }
  } else {
    const auto source = impl_->mangled_folder(old_path);
    const auto destination = impl_->mangled_folder(new_path);
    std::filesystem::create_directories(destination.parent_path());
    std::error_code error;
    std::filesystem::rename(source, destination, error);
    if (error)
      throw std::filesystem::filesystem_error("folder move failed", source,
                                              destination, error);
  }
  impl_->emit(
      {LocalFileSystemEventKind::folder_moved, parent, name, new_parent, name});
}

void LocalFileSystem::rename_folder(std::string parent, std::string name,
                                    std::string new_name) {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_writable();
  validate_name(new_name, impl_->indexed() ? 254 : 60);
  const auto old_path = path(parent, name);
  const auto new_path = path(parent, new_name);
  validate_existing_path(old_path, impl_->indexed() ? 254 : 60);
  if (old_path == new_path)
    return;
  if (!folder_exists(old_path))
    throw LocalFileSystemNotFoundError("folder not found: " + old_path);
  if (folder_exists(new_path))
    throw LocalFileSystemDuplicateError("folder already exists: " + new_path);
  if (impl_->indexed()) {
    auto relocations = impl_->relocate_folder_items(old_path, new_path);
    try {
      impl_->append_journal("FMV:" + old_path + ":" + new_path);
    } catch (...) {
      impl_->rollback_item_relocations(relocations, relocations.size());
      throw;
    }
    impl_->rename_folder_prefix(old_path, new_path);
    impl_->write_index();
  } else {
    const auto source = impl_->mangled_folder(old_path);
    const auto destination = impl_->mangled_folder(new_path);
    std::filesystem::rename(source, destination);
  }
  impl_->emit({LocalFileSystemEventKind::folder_renamed, parent, name, parent,
               new_name});
}

std::unique_ptr<LocalDatabaseItem>
LocalFileSystem::item(std::string parent, std::string name) const {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  validate_existing_path(parent, impl_->indexed() ? 254 : 60);
  validate_existing_name(name, impl_->indexed() ? 254 : 60);
  const auto identity = impl_->indexed()
                            ? impl_->identity(impl_->entry(parent, name))
                            : impl_->mangled_identity(parent, name);
  try {
    return LocalDatabaseItem::open_existing(impl_->context, identity);
  } catch (const LocalItemError &) {
    throw;
  } catch (const std::exception &error) {
    throw LocalFileSystemNotFoundError(
        "unable to open item " + path(parent, name) + ": " + error.what());
  }
}

std::unique_ptr<LocalDatabaseItem>
LocalFileSystem::item_by_file_id(std::string_view file_id) const {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_online();
  if (impl_->schema == LocalFileSystemSchema::indexed_v0) {
    throw LocalFileSystemError(
        "file-ID lookup is unsupported for Indexed V0 filesystems");
  }
  if (impl_->schema == LocalFileSystemSchema::indexed_v1) {
    const auto found = impl_->file_ids.find(file_id);
    if (found == impl_->file_ids.end())
      return nullptr;
    return item(parent_path(found->second), basename(found->second));
  }
  std::function<std::unique_ptr<LocalDatabaseItem>(const std::string &)> find =
      [&](const std::string &folder) -> std::unique_ptr<LocalDatabaseItem> {
    for (const auto &name : item_names(folder, true)) {
      auto candidate = item(folder, name);
      if (candidate->file_id() == file_id)
        return candidate;
    }
    for (const auto &child : folder_names(folder)) {
      if (auto result = find(path(folder, child)))
        return result;
    }
    return nullptr;
  };
  return find("/");
}

std::unique_ptr<LocalDatabaseItem> LocalFileSystem::create_database(
    std::string parent, std::string name, std::string content_type,
    std::optional<std::string> file_id, std::int32_t buffer_size,
    std::string user, std::optional<std::string> project_path,
    std::string comment) {
  std::scoped_lock lock(impl_->context->mutex);
  const auto identity = impl_->allocate(parent, name);
  try {
    return LocalDatabaseItem::create_empty(
        impl_->context, identity, std::move(content_type), std::move(file_id),
        buffer_size, std::move(user), std::move(project_path),
        std::move(comment));
  } catch (...) {
    impl_->deallocate(parent, name, false);
    throw;
  }
}

std::unique_ptr<LocalDatabaseItem> LocalFileSystem::create_database_from(
    std::string parent, std::string name, DatabaseHandle &source,
    std::string content_type, std::optional<std::string> file_id,
    bool reset_database_identity, std::string user,
    std::optional<std::string> project_path, std::string comment) {
  std::scoped_lock lock(impl_->context->mutex);
  const auto identity = impl_->allocate(parent, name);
  try {
    return LocalDatabaseItem::create_from(
        impl_->context, identity, source, std::move(content_type),
        std::move(file_id), reset_database_identity, std::move(user),
        std::move(project_path), std::move(comment));
  } catch (...) {
    impl_->deallocate(parent, name, false);
    throw;
  }
}

std::unique_ptr<LocalDatabaseItem> LocalFileSystem::create_database_from_packed(
    std::string parent, std::string name,
    const std::filesystem::path &packed_file,
    std::optional<std::string> file_id, std::string user,
    std::optional<std::string> project_path, std::string comment) {
  PackedItemReader reader(packed_file);
  if (reader.metadata().file_type != LocalFolderItem::database_file_type)
    throw LocalFileSystemError("packed item is not a database");
  if (name.empty())
    name = reader.metadata().item_name;
  if (!reader.metadata().content_type) {
    throw LocalFileSystemError("packed database has no content type");
  }
  auto content_type = *reader.metadata().content_type;
  std::scoped_lock lock(impl_->context->mutex);
  const auto identity = impl_->allocate(parent, name);
  try {
    return LocalDatabaseItem::create_from_packed(
        impl_->context, identity, packed_file, std::move(content_type),
        std::move(file_id), std::move(user), std::move(project_path),
        std::move(comment));
  } catch (...) {
    impl_->deallocate(parent, name, false);
    throw;
  }
}

void LocalFileSystem::move_item(std::string parent, std::string name,
                                std::string new_parent, std::string new_name) {
  std::scoped_lock lock(impl_->context->mutex);
  impl_->require_writable();
  if (impl_->indexed() && impl_->folders.contains(new_parent))
    validate_existing_path(new_parent, 254);
  else
    validate_path(new_parent, impl_->indexed() ? 254 : 60);
  validate_name(new_name, impl_->indexed() ? 254 : 60);
  const auto old_path = path(parent, name);
  const auto new_path = path(new_parent, new_name);
  if (old_path == new_path)
    return;
  if (item_exists(new_parent, new_name))
    throw LocalFileSystemDuplicateError("item already exists: " + new_path);
  auto opened = item(parent, name);
  if (impl_->indexed()) {
    auto value = impl_->entry(parent, name);
    const auto missing = impl_->create_missing_folders(new_parent);
    const auto old_identity = impl_->identity(value);
    const LocalItemIdentity new_identity{
        impl_->storage_directory(value.storage_name), value.storage_name,
        new_parent, new_name, true};
    impl_->suppress_item_changed = true;
    try {
      opened->move_to(new_identity);
      impl_->suppress_item_changed = false;
    } catch (...) {
      impl_->suppress_item_changed = false;
      throw;
    }
    std::vector<std::string> lines;
    for (const auto &folder : missing)
      lines.push_back("FADD:" + folder);
    lines.push_back("IMV:" + old_path + ":" + new_path);
    try {
      impl_->append_journal(lines);
    } catch (...) {
      impl_->suppress_item_changed = true;
      try {
        opened->move_to(old_identity);
      } catch (...) {
      }
      impl_->suppress_item_changed = false;
      throw;
    }
    for (const auto &folder : missing)
      impl_->folders.insert(folder);
    impl_->entries.erase(old_path);
    value.parent = new_parent;
    value.name = new_name;
    impl_->entries.emplace(new_path, std::move(value));
    impl_->rebuild_file_ids();
    impl_->write_index();
    for (const auto &folder : missing) {
      impl_->emit({LocalFileSystemEventKind::folder_created,
                   parent_path(folder),
                   basename(folder),
                   {},
                   {}});
    }
  } else {
    const auto destination = impl_->mangled_identity(new_parent, new_name);
    std::filesystem::create_directories(destination.storage_directory);
    impl_->suppress_item_changed = true;
    try {
      opened->move_to(destination);
      impl_->suppress_item_changed = false;
    } catch (...) {
      impl_->suppress_item_changed = false;
      throw;
    }
  }
  impl_->emit({parent == new_parent ? LocalFileSystemEventKind::item_renamed
                                    : LocalFileSystemEventKind::item_moved,
               parent, name, new_parent, new_name});
}

bool LocalFileSystem::valid_utf8(std::string_view text) noexcept {
  for (std::size_t index = 0; index < text.size();) {
    const auto first = static_cast<unsigned char>(text[index]);
    if (first < 0x80) {
      ++index;
      continue;
    }
    std::size_t count = 0;
    std::uint32_t value = 0;
    if ((first & 0xe0U) == 0xc0U) {
      count = 2;
      value = first & 0x1fU;
      if (value < 2)
        return false;
    } else if ((first & 0xf0U) == 0xe0U) {
      count = 3;
      value = first & 0x0fU;
    } else if ((first & 0xf8U) == 0xf0U) {
      count = 4;
      value = first & 0x07U;
    } else {
      return false;
    }
    if (index + count > text.size())
      return false;
    for (std::size_t offset = 1; offset < count; ++offset) {
      const auto next = static_cast<unsigned char>(text[index + offset]);
      if ((next & 0xc0U) != 0x80U)
        return false;
      value = (value << 6) | (next & 0x3fU);
    }
    if ((count == 3 && value < 0x800) || (count == 4 && value < 0x10000) ||
        value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
      return false;
    index += count;
  }
  return true;
}

void LocalFileSystem::validate_name(std::string_view name,
                                    std::size_t maximum_bytes) {
  if (name.empty() ||
      std::all_of(name.begin(), name.end(),
                  [](unsigned char character) { return character == ' '; }))
    throw LocalFileSystemInvalidNameError("project name is empty or reserved");
  if (name.size() > maximum_bytes)
    throw LocalFileSystemInvalidNameError("project name is too long");
  if (!valid_utf8(name))
    throw LocalFileSystemInvalidNameError("project name is not valid UTF-8");
  if (name.front() == '.')
    throw LocalFileSystemInvalidNameError(
        "project name may not start with a dot");
  if (name.back() == ' ' || name.back() == '.')
    throw LocalFileSystemInvalidNameError(
        "project name has a trailing space or dot");
  constexpr std::string_view allowed_ascii_symbols = ".-=@ _()[]~";
  for (const unsigned char character : name) {
    if (character >= 0x80 || std::isalnum(character) != 0 ||
        allowed_ascii_symbols.find(static_cast<char>(character)) !=
            std::string_view::npos) {
      continue;
    }
    {
      throw LocalFileSystemInvalidNameError(
          "project name contains an invalid character");
    }
  }
  const auto code_points = decode_utf8(name);
  for (const auto code_point : *code_points) {
    if (code_point > 0x7f &&
        !in_unicode_ranges(code_point,
                           unicode_tables::letter_or_digit_ranges)) {
      throw LocalFileSystemInvalidNameError(
          "project name contains a non-letter Unicode character");
    }
  }
  auto stem = lower_ascii(name.substr(0, name.find('.')));
  const bool numbered_reserved =
      stem.size() == 4 && stem[3] >= '1' && stem[3] <= '9' &&
      (stem.starts_with("com") || stem.starts_with("lpt"));
  if (stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" ||
      numbered_reserved) {
    throw LocalFileSystemInvalidNameError(
        "project name is reserved by Windows filesystems");
  }
}

void LocalFileSystem::validate_path(std::string_view value,
                                    std::size_t maximum_name_bytes) {
  if (value.empty() || value.front() != '/')
    throw LocalFileSystemInvalidNameError(
        "project path must be absolute and slash-separated");
  if (value == "/")
    return;
  if (value.back() == '/' || value.find("//") != std::string_view::npos)
    throw LocalFileSystemInvalidNameError("project path is not canonical");
  for (const auto &component : split(value.substr(1), '/'))
    validate_name(component, maximum_name_bytes);
}

std::string LocalFileSystem::path(std::string_view parent,
                                  std::string_view name) {
  if (parent == "/")
    return "/" + std::string(name);
  return std::string(parent) + "/" + std::string(name);
}

std::string LocalFileSystem::parent_path(std::string_view value) {
  if (value == "/")
    return {};
  const auto position = value.rfind('/');
  if (position == std::string_view::npos)
    throw LocalFileSystemInvalidNameError("project path is not absolute");
  return position == 0 ? "/" : std::string(value.substr(0, position));
}

std::string LocalFileSystem::basename(std::string_view value) {
  if (value == "/")
    return "/";
  while (value.size() > 1 && value.back() == '/')
    value.remove_suffix(1);
  const auto position = value.rfind('/');
  return std::string(value.substr(position + 1));
}

} // namespace llmghidra::db
