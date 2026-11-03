/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/packed_item.hpp"

#include "zlib.h"

#include <algorithm>
#include <array>
#include <bit>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>
#include <streambuf>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace llmghidra::db {
namespace {

constexpr std::uint64_t packed_magic = 0x2e30212634e92c20ULL;
constexpr std::uint32_t packed_format_version = 1;
constexpr std::string_view zip_entry_name = "FOLDER_ITEM";
constexpr std::size_t io_buffer_size = 32 * 1024;

constexpr std::uint32_t local_header_signature = 0x04034b50;
constexpr std::uint32_t data_descriptor_signature = 0x08074b50;
constexpr std::uint32_t central_header_signature = 0x02014b50;
constexpr std::uint32_t eocd_signature = 0x06054b50;
constexpr std::uint32_t zip64_eocd_signature = 0x06064b50;
constexpr std::uint32_t zip64_locator_signature = 0x07064b50;
constexpr std::uint16_t zip_version_20 = 20;
constexpr std::uint16_t zip_version_45 = 45;
constexpr std::uint16_t zip64_extra_id = 0x0001;
constexpr std::uint16_t zip_flags = 0x0808;
constexpr std::uint16_t deflated_method = 8;
constexpr std::uint16_t stored_method = 0;

void require_read(std::istream &stream, std::span<std::uint8_t> bytes,
                  std::string_view what) {
  if (bytes.empty())
    return;
  stream.read(reinterpret_cast<char *>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
  if (stream.gcount() != static_cast<std::streamsize>(bytes.size())) {
    throw std::runtime_error("truncated " + std::string(what));
  }
}

void require_write(std::ostream &stream, std::span<const std::uint8_t> bytes,
                   std::string_view what) {
  if (bytes.empty())
    return;
  stream.write(reinterpret_cast<const char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!stream)
    throw std::runtime_error("unable to write " + std::string(what));
}

std::uint8_t read_u8(std::istream &stream, std::string_view what) {
  const auto value = stream.get();
  if (value == std::char_traits<char>::eof()) {
    throw std::runtime_error("truncated " + std::string(what));
  }
  return static_cast<std::uint8_t>(value);
}

std::uint16_t read_be_u16(std::istream &stream, std::string_view what) {
  const auto high = read_u8(stream, what);
  return static_cast<std::uint16_t>((high << 8) | read_u8(stream, what));
}

std::uint32_t read_be_u32(std::istream &stream, std::string_view what) {
  std::uint32_t result = 0;
  for (int index = 0; index < 4; ++index) {
    result = (result << 8) | read_u8(stream, what);
  }
  return result;
}

std::uint16_t span_le_u16(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
  if (offset > bytes.size() || bytes.size() - offset < 2) {
    throw std::runtime_error("truncated ZIP uint16");
  }
  return static_cast<std::uint16_t>(bytes[offset]) |
         static_cast<std::uint16_t>(bytes[offset + 1] << 8);
}

std::uint32_t span_le_u32(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
  if (offset > bytes.size() || bytes.size() - offset < 4) {
    throw std::runtime_error("truncated ZIP uint32");
  }
  std::uint32_t result = 0;
  for (int index = 3; index >= 0; --index) {
    result = (result << 8) | bytes[offset + static_cast<std::size_t>(index)];
  }
  return result;
}

std::uint64_t span_le_u64(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
  if (offset > bytes.size() || bytes.size() - offset < 8) {
    throw std::runtime_error("truncated ZIP uint64");
  }
  std::uint64_t result = 0;
  for (int index = 7; index >= 0; --index) {
    result = (result << 8) | bytes[offset + static_cast<std::size_t>(index)];
  }
  return result;
}

void write_be_u16(std::ostream &stream, std::uint16_t value) {
  stream.put(static_cast<char>(value >> 8));
  stream.put(static_cast<char>(value));
  if (!stream)
    throw std::runtime_error("unable to write packed uint16");
}

void write_be_u32(std::ostream &stream, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    stream.put(static_cast<char>(value >> shift));
  }
  if (!stream)
    throw std::runtime_error("unable to write packed uint32");
}

void write_le_u16(std::ostream &stream, std::uint16_t value) {
  stream.put(static_cast<char>(value));
  stream.put(static_cast<char>(value >> 8));
  if (!stream)
    throw std::runtime_error("unable to write ZIP uint16");
}

void write_le_u32(std::ostream &stream, std::uint32_t value) {
  for (int shift = 0; shift <= 24; shift += 8) {
    stream.put(static_cast<char>(value >> shift));
  }
  if (!stream)
    throw std::runtime_error("unable to write ZIP uint32");
}

void write_le_u64(std::ostream &stream, std::uint64_t value) {
  for (int shift = 0; shift <= 56; shift += 8) {
    stream.put(static_cast<char>(value >> shift));
  }
  if (!stream)
    throw std::runtime_error("unable to write ZIP uint64");
}

std::uint64_t checked_add(std::uint64_t left, std::uint64_t right,
                          std::string_view what) {
  if (right > (std::numeric_limits<std::uint64_t>::max)() - left) {
    throw std::overflow_error(std::string(what) + " overflows uint64");
  }
  return left + right;
}

std::uint64_t tell(std::ostream &stream) {
  const auto position = stream.tellp();
  if (position < 0)
    throw std::runtime_error("unable to query output position");
  return static_cast<std::uint64_t>(position);
}

void seek(std::istream &stream, std::uint64_t offset) {
  if (offset > static_cast<std::uint64_t>(
                   (std::numeric_limits<std::streamoff>::max)())) {
    throw std::overflow_error("packed file offset exceeds stream range");
  }
  stream.clear();
  stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!stream)
    throw std::runtime_error("unable to seek packed file");
}

std::vector<std::uint16_t> utf8_to_utf16(std::string_view text) {
  std::vector<std::uint16_t> result;
  for (std::size_t index = 0; index < text.size();) {
    const auto first = static_cast<std::uint8_t>(text[index]);
    std::uint32_t codepoint = 0;
    std::size_t count = 0;
    if (first < 0x80) {
      codepoint = first;
      count = 1;
    } else if ((first & 0xe0) == 0xc0) {
      codepoint = first & 0x1f;
      count = 2;
    } else if ((first & 0xf0) == 0xe0) {
      codepoint = first & 0x0f;
      count = 3;
    } else if ((first & 0xf8) == 0xf0) {
      codepoint = first & 0x07;
      count = 4;
    } else {
      throw std::invalid_argument("invalid UTF-8 leading byte");
    }
    if (index + count > text.size()) {
      throw std::invalid_argument("truncated UTF-8 string");
    }
    for (std::size_t continuation = 1; continuation < count; ++continuation) {
      const auto value = static_cast<std::uint8_t>(text[index + continuation]);
      if ((value & 0xc0) != 0x80) {
        throw std::invalid_argument("invalid UTF-8 continuation byte");
      }
      codepoint = (codepoint << 6) | (value & 0x3f);
    }
    const std::uint32_t minimum[] = {0, 0, 0x80, 0x800, 0x10000};
    if (codepoint < minimum[count] || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
      throw std::invalid_argument("non-canonical UTF-8 string");
    }
    if (codepoint <= 0xffff) {
      result.push_back(static_cast<std::uint16_t>(codepoint));
    } else {
      codepoint -= 0x10000;
      result.push_back(static_cast<std::uint16_t>(0xd800 + (codepoint >> 10)));
      result.push_back(
          static_cast<std::uint16_t>(0xdc00 + (codepoint & 0x3ff)));
    }
    index += count;
  }
  return result;
}

std::vector<std::uint8_t> encode_modified_utf8(std::string_view text) {
  std::vector<std::uint8_t> result;
  for (const auto unit : utf8_to_utf16(text)) {
    if (unit != 0 && unit <= 0x7f) {
      result.push_back(static_cast<std::uint8_t>(unit));
    } else if (unit <= 0x7ff) {
      result.push_back(static_cast<std::uint8_t>(0xc0 | (unit >> 6)));
      result.push_back(static_cast<std::uint8_t>(0x80 | (unit & 0x3f)));
    } else {
      result.push_back(static_cast<std::uint8_t>(0xe0 | (unit >> 12)));
      result.push_back(static_cast<std::uint8_t>(0x80 | ((unit >> 6) & 0x3f)));
      result.push_back(static_cast<std::uint8_t>(0x80 | (unit & 0x3f)));
    }
  }
  if (result.size() > (std::numeric_limits<std::uint16_t>::max)()) {
    throw std::length_error(
        "packed item UTF field exceeds Java writeUTF limit");
  }
  return result;
}

void append_utf8(std::string &result, std::uint32_t codepoint) {
  if (codepoint <= 0x7f) {
    result.push_back(static_cast<char>(codepoint));
  } else if (codepoint <= 0x7ff) {
    result.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
    result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  } else if (codepoint <= 0xffff) {
    result.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
    result.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  } else {
    result.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
    result.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
    result.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  }
}

std::string decode_modified_utf8(std::span<const std::uint8_t> bytes) {
  std::vector<std::uint16_t> units;
  for (std::size_t index = 0; index < bytes.size();) {
    const auto first = bytes[index++];
    if (first != 0 && first <= 0x7f) {
      units.push_back(first);
    } else if ((first & 0xe0) == 0xc0) {
      if (index == bytes.size() || (bytes[index] & 0xc0) != 0x80) {
        throw std::runtime_error("invalid modified UTF-8 field");
      }
      const auto unit = static_cast<std::uint16_t>(((first & 0x1f) << 6) |
                                                   (bytes[index++] & 0x3f));
      if (unit != 0 && unit < 0x80) {
        throw std::runtime_error("non-canonical modified UTF-8 field");
      }
      units.push_back(unit);
    } else if ((first & 0xf0) == 0xe0) {
      if (bytes.size() - index < 2 || (bytes[index] & 0xc0) != 0x80 ||
          (bytes[index + 1] & 0xc0) != 0x80) {
        throw std::runtime_error("invalid modified UTF-8 field");
      }
      const auto unit = static_cast<std::uint16_t>(
          ((first & 0x0f) << 12) | ((bytes[index] & 0x3f) << 6) |
          (bytes[index + 1] & 0x3f));
      index += 2;
      if (unit < 0x800) {
        throw std::runtime_error("non-canonical modified UTF-8 field");
      }
      units.push_back(unit);
    } else {
      throw std::runtime_error("invalid modified UTF-8 field");
    }
  }

  std::string result;
  for (std::size_t index = 0; index < units.size(); ++index) {
    std::uint32_t codepoint = units[index];
    if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
      if (++index == units.size() || units[index] < 0xdc00 ||
          units[index] > 0xdfff) {
        throw std::runtime_error("unpaired modified UTF-8 high surrogate");
      }
      codepoint =
          0x10000 + ((codepoint - 0xd800) << 10) + (units[index] - 0xdc00);
    } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
      throw std::runtime_error("unpaired modified UTF-8 low surrogate");
    }
    append_utf8(result, codepoint);
  }
  return result;
}

void append_be_u16(std::vector<std::uint8_t> &bytes, std::uint16_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 8));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

void append_be_u32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    bytes.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

void append_be_u64(std::vector<std::uint8_t> &bytes, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    bytes.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

void append_java_utf(std::vector<std::uint8_t> &bytes, std::string_view text) {
  const auto encoded = encode_modified_utf8(text);
  append_be_u16(bytes, static_cast<std::uint16_t>(encoded.size()));
  bytes.insert(bytes.end(), encoded.begin(), encoded.end());
}

void write_object_header(std::ostream &stream,
                         const PackedItemMetadata &metadata) {
  write_be_u16(stream, 0xaced);
  write_be_u16(stream, 5);
  std::vector<std::uint8_t> block;
  append_be_u64(block, packed_magic);
  append_be_u32(block, packed_format_version);
  append_java_utf(block, metadata.item_name);
  append_java_utf(block, metadata.content_type.value_or(""));
  append_be_u32(block, std::bit_cast<std::uint32_t>(metadata.file_type));
  append_be_u64(block, metadata.length);
  if (block.size() <= (std::numeric_limits<std::uint8_t>::max)()) {
    stream.put(static_cast<char>(0x77));
    stream.put(static_cast<char>(block.size()));
  } else {
    stream.put(static_cast<char>(0x7a));
    write_be_u32(stream, static_cast<std::uint32_t>(block.size()));
  }
  require_write(stream, block, "packed ObjectStream block");
}

class ByteCursor final {
public:
  explicit ByteCursor(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
  std::uint16_t u16() {
    const auto high = byte();
    return static_cast<std::uint16_t>((high << 8) | byte());
  }
  std::uint32_t u32() {
    std::uint32_t result = 0;
    for (int index = 0; index < 4; ++index)
      result = (result << 8) | byte();
    return result;
  }
  std::uint64_t u64() {
    std::uint64_t result = 0;
    for (int index = 0; index < 8; ++index)
      result = (result << 8) | byte();
    return result;
  }
  std::string java_utf() {
    const auto length = u16();
    if (bytes_.size() - offset_ < length) {
      throw std::runtime_error("truncated packed UTF field");
    }
    const auto value = decode_modified_utf8(bytes_.subspan(offset_, length));
    offset_ += length;
    return value;
  }
  [[nodiscard]] bool empty() const noexcept { return offset_ == bytes_.size(); }

private:
  std::uint8_t byte() {
    if (offset_ == bytes_.size()) {
      throw std::runtime_error("truncated packed ObjectStream metadata");
    }
    return bytes_[offset_++];
  }
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_ = 0;
};

std::pair<PackedItemMetadata, std::uint64_t>
read_object_header(std::istream &stream) {
  if (read_be_u16(stream, "ObjectStream header") != 0xaced ||
      read_be_u16(stream, "ObjectStream header") != 5) {
    throw std::runtime_error("invalid packed ObjectStream header");
  }
  std::vector<std::uint8_t> block;
  while (true) {
    const auto token_position = stream.tellg();
    if (token_position < 0) {
      throw std::runtime_error("unable to query packed header position");
    }
    const auto token = read_u8(stream, "ObjectStream block token");
    if (token != 0x77 && token != 0x7a) {
      stream.clear();
      stream.seekg(token_position);
      break;
    }
    const auto length = token == 0x77
                            ? static_cast<std::uint32_t>(
                                  read_u8(stream, "ObjectStream block length"))
                            : read_be_u32(stream, "ObjectStream block length");
    constexpr auto maximum_metadata =
        2U * (std::numeric_limits<std::uint16_t>::max)() + 28U;
    if (length > maximum_metadata || block.size() + length > maximum_metadata) {
      throw std::runtime_error("packed ObjectStream metadata is too large");
    }
    const auto old_size = block.size();
    block.resize(old_size + length);
    require_read(stream, std::span(block).subspan(old_size),
                 "ObjectStream metadata");
  }

  ByteCursor cursor(block);
  if (cursor.u64() != packed_magic) {
    throw std::runtime_error("invalid packed item magic");
  }
  if (cursor.u32() != packed_format_version) {
    throw std::runtime_error("unsupported packed item format");
  }
  PackedItemMetadata metadata;
  metadata.item_name = cursor.java_utf();
  auto content_type = cursor.java_utf();
  if (!content_type.empty())
    metadata.content_type = std::move(content_type);
  metadata.file_type = std::bit_cast<std::int32_t>(cursor.u32());
  const auto signed_length = std::bit_cast<std::int64_t>(cursor.u64());
  if (signed_length < 0)
    throw std::runtime_error("negative packed item length");
  metadata.length = static_cast<std::uint64_t>(signed_length);
  if (!cursor.empty()) {
    throw std::runtime_error("unexpected packed ObjectStream metadata bytes");
  }
  const auto position = stream.tellg();
  if (position < 0)
    throw std::runtime_error("unable to locate embedded ZIP");
  return {std::move(metadata), static_cast<std::uint64_t>(position)};
}

class Crc32 final {
public:
  void update(std::span<const std::uint8_t> bytes) noexcept {
    for (const auto byte : bytes) {
      value_ ^= byte;
      for (int bit = 0; bit < 8; ++bit) {
        value_ = (value_ >> 1) ^ (0xedb88320U & (0U - (value_ & 1U)));
      }
    }
  }
  [[nodiscard]] std::uint32_t value() const noexcept { return ~value_; }

private:
  std::uint32_t value_ = 0xffffffffU;
};

class NullStreamBuffer final : public std::streambuf {
protected:
  std::streamsize xsputn(const char *, std::streamsize count) override {
    return count;
  }

  int_type overflow(int_type value) override {
    return traits_type::not_eof(value);
  }
};

std::filesystem::path temporary_sibling(const std::filesystem::path &output) {
  for (std::uint32_t suffix = 0; suffix < 10000; ++suffix) {
    auto candidate = output;
    candidate += ".tmp." + std::to_string(suffix);
    if (!std::filesystem::exists(candidate))
      return candidate;
  }
  throw std::runtime_error("unable to allocate packed item temporary path");
}

void install_temporary(const std::filesystem::path &temporary,
                       const std::filesystem::path &output) {
  std::error_code error;
  std::filesystem::rename(temporary, output, error);
  if (error)
    throw std::runtime_error("unable to install packed item output");
}

struct ZipEntryInfo final {
  std::uint16_t flags = 0;
  std::uint16_t method = 0;
  std::uint32_t crc = 0;
  std::uint64_t compressed_size = 0;
  std::uint64_t uncompressed_size = 0;
  std::uint64_t local_offset = 0;
  std::uint64_t central_offset = 0;
  bool has_central_directory = false;
  bool zip64 = false;
};

struct Zip64ExtraValues final {
  std::optional<std::uint64_t> uncompressed_size;
  std::optional<std::uint64_t> compressed_size;
  std::optional<std::uint64_t> local_offset;
};

Zip64ExtraValues parse_zip64_extra(std::span<const std::uint8_t> extra,
                                   bool need_uncompressed, bool need_compressed,
                                   bool need_local_offset,
                                   bool need_disk_start) {
  Zip64ExtraValues result;
  bool found = false;
  for (std::size_t offset = 0; offset < extra.size();) {
    if (extra.size() - offset < 4) {
      throw std::runtime_error("truncated ZIP extra-field header");
    }
    const auto id = span_le_u16(extra, offset);
    const auto size = span_le_u16(extra, offset + 2);
    offset += 4;
    if (size > extra.size() - offset) {
      throw std::runtime_error("truncated ZIP extra field");
    }
    const auto field = extra.subspan(offset, size);
    offset += size;
    if (id != zip64_extra_id)
      continue;
    if (found)
      throw std::runtime_error("duplicate ZIP64 extra field");
    found = true;
    std::size_t value_offset = 0;
    const auto take_u64 = [&]() {
      const auto value = span_le_u64(field, value_offset);
      value_offset += 8;
      return value;
    };
    if (need_uncompressed)
      result.uncompressed_size = take_u64();
    if (need_compressed)
      result.compressed_size = take_u64();
    if (need_local_offset)
      result.local_offset = take_u64();
    if (need_disk_start) {
      if (field.size() - value_offset < 4) {
        throw std::runtime_error("truncated ZIP64 disk start");
      }
      if (span_le_u32(field, value_offset) != 0) {
        throw std::runtime_error("multi-disk ZIP64 is not supported");
      }
      value_offset += 4;
    } else if (field.size() - value_offset == 4) {
      // Apache Commons Compress Zip64Mode.Always writes the optional disk
      // start value even when the 16-bit central-header field is zero.
      if (span_le_u32(field, value_offset) != 0) {
        throw std::runtime_error("multi-disk ZIP64 is not supported");
      }
      value_offset += 4;
    }
    if (value_offset != field.size()) {
      throw std::runtime_error("unexpected ZIP64 extra-field payload");
    }
  }
  const bool required = need_uncompressed || need_compressed ||
                        need_local_offset || need_disk_start;
  if (required && !found)
    throw std::runtime_error("missing ZIP64 extra field");
  if (!required && found) {
    throw std::runtime_error("unexpected ZIP64 extra field");
  }
  return result;
}

void validate_zip_flags(std::uint16_t flags) {
  if ((flags & 0x0001U) != 0) {
    throw std::runtime_error("encrypted packed ZIP entries are not supported");
  }
}

ZipEntryInfo read_zip_directory(std::ifstream &stream, std::uint64_t zip_offset,
                                std::uint64_t file_size) {
  if (zip_offset >= file_size)
    throw std::runtime_error("packed item has no ZIP data");
  const auto tail_size = static_cast<std::size_t>(
      (std::min<
          std::uint64_t>)(file_size - zip_offset,
                          22U + (std::numeric_limits<std::uint16_t>::max)()));
  std::vector<std::uint8_t> tail(tail_size);
  seek(stream, file_size - tail_size);
  require_read(stream, tail, "ZIP end record");

  std::optional<std::size_t> eocd;
  if (tail.size() >= 22) {
    for (std::size_t offset = tail.size() - 22;; --offset) {
      if (span_le_u32(tail, offset) == eocd_signature &&
          offset + 22 + span_le_u16(tail, offset + 20) == tail.size()) {
        eocd = offset;
        break;
      }
      if (offset == 0)
        break;
    }
  }
  if (!eocd) {
    // Ghidra's ItemSerializer calls closeEntry() but deliberately does not
    // close ZipOutputStream. Its files therefore end after the data
    // descriptor and have no central directory. Accept that exact form.
    if (file_size - zip_offset < 46) {
      throw std::runtime_error("truncated packed ZIP stream");
    }
    seek(stream, zip_offset);
    std::array<std::uint8_t, 30> local{};
    require_read(stream, local, "ZIP local header");
    if (span_le_u32(local, 0) != local_header_signature) {
      throw std::runtime_error("invalid packed ZIP local header");
    }
    ZipEntryInfo info;
    info.flags = span_le_u16(local, 6);
    info.method = span_le_u16(local, 8);
    validate_zip_flags(info.flags);
    const auto name_length = span_le_u16(local, 26);
    const auto extra_length = span_le_u16(local, 28);
    std::vector<std::uint8_t> name(name_length);
    require_read(stream, name, "ZIP local entry name");
    if (std::string_view(reinterpret_cast<const char *>(name.data()),
                         name.size()) != zip_entry_name) {
      throw std::runtime_error("invalid packed ZIP local entry name");
    }
    std::vector<std::uint8_t> extra(extra_length);
    require_read(stream, extra, "ZIP local extra fields");
    const auto local_compressed = span_le_u32(local, 18);
    const auto local_uncompressed = span_le_u32(local, 22);
    const bool need_compressed = local_compressed == 0xffffffffU;
    const bool need_uncompressed = local_uncompressed == 0xffffffffU;
    const auto zip64 = parse_zip64_extra(extra, need_uncompressed,
                                         need_compressed, false, false);
    info.zip64 = need_compressed || need_uncompressed;
    if (info.zip64 && span_le_u16(local, 4) < zip_version_45) {
      throw std::runtime_error("ZIP64 local header has an invalid version");
    }
    if ((info.flags & 0x0008U) == 0) {
      throw std::runtime_error(
          "central-directory-free packed ZIP requires a data descriptor");
    }
    const auto descriptor_size = info.zip64 ? 24ULL : 16ULL;
    const auto data_offset =
        checked_add(checked_add(30ULL, name_length, "ZIP local header"),
                    extra_length, "ZIP local header");
    if (file_size - zip_offset <
        checked_add(data_offset, descriptor_size, "ZIP data descriptor")) {
      throw std::runtime_error("truncated packed ZIP data descriptor");
    }
    std::array<std::uint8_t, 24> descriptor{};
    seek(stream, file_size - descriptor_size);
    const auto descriptor_bytes =
        std::span(descriptor).first(static_cast<std::size_t>(descriptor_size));
    require_read(stream, descriptor_bytes, "ZIP data descriptor");
    if (span_le_u32(descriptor_bytes, 0) != data_descriptor_signature) {
      throw std::runtime_error("missing packed ZIP data descriptor");
    }
    info.crc = span_le_u32(descriptor_bytes, 4);
    info.compressed_size = info.zip64 ? span_le_u64(descriptor_bytes, 8)
                                      : span_le_u32(descriptor_bytes, 8);
    info.uncompressed_size = info.zip64 ? span_le_u64(descriptor_bytes, 16)
                                        : span_le_u32(descriptor_bytes, 12);
    info.local_offset = 0;
    if (info.compressed_size !=
        file_size - zip_offset - data_offset - descriptor_size) {
      throw std::runtime_error("packed ZIP descriptor size mismatch");
    }
    if (zip64.compressed_size && *zip64.compressed_size != 0 &&
        *zip64.compressed_size != info.compressed_size) {
      throw std::runtime_error("ZIP64 local compressed size differs");
    }
    if (zip64.uncompressed_size && *zip64.uncompressed_size != 0 &&
        *zip64.uncompressed_size != info.uncompressed_size) {
      throw std::runtime_error("ZIP64 local uncompressed size differs");
    }
    return info;
  }
  const auto eocd_offset = *eocd;
  const auto tail_absolute = file_size - tail.size();
  const auto eocd_absolute = tail_absolute + eocd_offset;
  const auto disk_number = span_le_u16(tail, eocd_offset + 4);
  const auto central_disk = span_le_u16(tail, eocd_offset + 6);
  const auto entries_on_disk = span_le_u16(tail, eocd_offset + 8);
  const auto total_entries = span_le_u16(tail, eocd_offset + 10);
  const auto central_size32 = span_le_u32(tail, eocd_offset + 12);
  const auto central_offset32 = span_le_u32(tail, eocd_offset + 16);
  const bool has_zip64_locator =
      eocd_offset >= 20 &&
      span_le_u32(tail, eocd_offset - 20) == zip64_locator_signature;
  const bool has_zip64_end =
      has_zip64_locator || disk_number == 0xffffU || central_disk == 0xffffU ||
      entries_on_disk == 0xffffU || total_entries == 0xffffU ||
      central_size32 == 0xffffffffU || central_offset32 == 0xffffffffU;
  std::uint64_t central_size = central_size32;
  std::uint64_t central_offset = central_offset32;
  std::uint64_t expected_central_end = eocd_absolute;
  if (has_zip64_end) {
    if (eocd_absolute < checked_add(zip_offset, 20, "ZIP64 locator")) {
      throw std::runtime_error("missing ZIP64 end locator");
    }
    const auto locator_absolute = eocd_absolute - 20;
    seek(stream, locator_absolute);
    std::array<std::uint8_t, 20> locator{};
    require_read(stream, locator, "ZIP64 end locator");
    if (span_le_u32(locator, 0) != zip64_locator_signature ||
        span_le_u32(locator, 4) != 0 || span_le_u32(locator, 16) != 1) {
      throw std::runtime_error("invalid or multi-disk ZIP64 locator");
    }
    const auto zip64_end_absolute =
        checked_add(zip_offset, span_le_u64(locator, 8), "ZIP64 end offset");
    if (zip64_end_absolute >= locator_absolute ||
        locator_absolute - zip64_end_absolute < 56) {
      throw std::runtime_error("ZIP64 end record exceeds packed file");
    }
    seek(stream, zip64_end_absolute);
    std::array<std::uint8_t, 56> zip64_end{};
    require_read(stream, zip64_end, "ZIP64 end record");
    if (span_le_u32(zip64_end, 0) != zip64_eocd_signature) {
      throw std::runtime_error("invalid ZIP64 end record");
    }
    if (span_le_u16(zip64_end, 14) < zip_version_45) {
      throw std::runtime_error("ZIP64 end record has an invalid version");
    }
    const auto record_size = span_le_u64(zip64_end, 4);
    if (record_size < 44 ||
        checked_add(zip64_end_absolute,
                    checked_add(12, record_size, "ZIP64 end record"),
                    "ZIP64 end record") != locator_absolute) {
      throw std::runtime_error("invalid ZIP64 end-record size");
    }
    if (span_le_u32(zip64_end, 16) != 0 || span_le_u32(zip64_end, 20) != 0 ||
        span_le_u64(zip64_end, 24) != 1 || span_le_u64(zip64_end, 32) != 1) {
      throw std::runtime_error(
          "packed item must contain one single-disk ZIP entry");
    }
    central_size = span_le_u64(zip64_end, 40);
    central_offset = span_le_u64(zip64_end, 48);
    expected_central_end = zip64_end_absolute;
    if ((disk_number != 0xffffU && disk_number != 0) ||
        (central_disk != 0xffffU && central_disk != 0) ||
        (entries_on_disk != 0xffffU && entries_on_disk != 1) ||
        (total_entries != 0xffffU && total_entries != 1) ||
        (central_size32 != 0xffffffffU && central_size32 != central_size) ||
        (central_offset32 != 0xffffffffU &&
         central_offset32 != central_offset)) {
      throw std::runtime_error("ZIP32 and ZIP64 end records differ");
    }
  } else if (disk_number != 0 || central_disk != 0 || entries_on_disk != 1 ||
             total_entries != 1) {
    throw std::runtime_error("packed item must contain exactly one ZIP entry");
  }
  const auto central_absolute =
      checked_add(zip_offset, central_offset, "ZIP central directory offset");
  if (central_absolute > file_size ||
      central_size > file_size - central_absolute ||
      checked_add(central_absolute, central_size, "ZIP central directory") !=
          expected_central_end) {
    throw std::runtime_error("ZIP central directory exceeds packed file");
  }
  seek(stream, central_absolute);
  std::array<std::uint8_t, 46> header{};
  require_read(stream, header, "ZIP central header");
  if (span_le_u32(header, 0) != central_header_signature) {
    throw std::runtime_error("invalid ZIP central header");
  }
  ZipEntryInfo info;
  info.flags = span_le_u16(header, 8);
  info.method = span_le_u16(header, 10);
  validate_zip_flags(info.flags);
  info.crc = span_le_u32(header, 16);
  const auto compressed32 = span_le_u32(header, 20);
  const auto uncompressed32 = span_le_u32(header, 24);
  const auto local_offset32 = span_le_u32(header, 42);
  const auto disk_start = span_le_u16(header, 34);
  const auto name_length = span_le_u16(header, 28);
  const auto extra_length = span_le_u16(header, 30);
  const auto comment_length = span_le_u16(header, 32);
  std::vector<std::uint8_t> name(name_length);
  require_read(stream, name, "ZIP entry name");
  if (std::string_view(reinterpret_cast<const char *>(name.data()),
                       name.size()) != zip_entry_name) {
    throw std::runtime_error("packed ZIP entry is not FOLDER_ITEM");
  }
  std::vector<std::uint8_t> extra(extra_length);
  require_read(stream, extra, "ZIP central extra fields");
  std::vector<std::uint8_t> comment(comment_length);
  require_read(stream, comment, "ZIP central entry comment");
  const bool need_uncompressed = uncompressed32 == 0xffffffffU;
  const bool need_compressed = compressed32 == 0xffffffffU;
  const bool need_local_offset = local_offset32 == 0xffffffffU;
  const bool need_disk_start = disk_start == 0xffffU;
  const auto zip64 =
      parse_zip64_extra(extra, need_uncompressed, need_compressed,
                        need_local_offset, need_disk_start);
  if (!need_disk_start && disk_start != 0) {
    throw std::runtime_error("multi-disk packed ZIP is not supported");
  }
  info.compressed_size =
      need_compressed ? *zip64.compressed_size : compressed32;
  info.uncompressed_size =
      need_uncompressed ? *zip64.uncompressed_size : uncompressed32;
  info.local_offset = need_local_offset ? *zip64.local_offset : local_offset32;
  info.central_offset = central_offset;
  info.has_central_directory = true;
  info.zip64 = has_zip64_end || need_uncompressed || need_compressed ||
               need_local_offset || need_disk_start;
  if (info.zip64 && span_le_u16(header, 6) < zip_version_45) {
    throw std::runtime_error("ZIP64 central header has an invalid version");
  }
  if (46ULL + name_length + extra_length + comment_length != central_size) {
    throw std::runtime_error("unexpected packed ZIP central directory size");
  }
  return info;
}

std::uint64_t read_local_data_offset(std::ifstream &stream,
                                     std::uint64_t zip_offset,
                                     const ZipEntryInfo &info,
                                     std::uint64_t file_size) {
  const auto local_absolute =
      checked_add(zip_offset, info.local_offset, "ZIP local header offset");
  if (local_absolute > file_size || file_size - local_absolute < 30) {
    throw std::runtime_error("ZIP local header exceeds packed file");
  }
  seek(stream, local_absolute);
  std::array<std::uint8_t, 30> header{};
  require_read(stream, header, "ZIP local header");
  if (span_le_u32(header, 0) != local_header_signature ||
      span_le_u16(header, 6) != info.flags ||
      span_le_u16(header, 8) != info.method) {
    throw std::runtime_error("ZIP local and central headers differ");
  }
  const auto name_length = span_le_u16(header, 26);
  const auto extra_length = span_le_u16(header, 28);
  std::vector<std::uint8_t> name(name_length);
  require_read(stream, name, "ZIP local entry name");
  if (std::string_view(reinterpret_cast<const char *>(name.data()),
                       name.size()) != zip_entry_name) {
    throw std::runtime_error("invalid ZIP local entry name");
  }
  std::vector<std::uint8_t> extra(extra_length);
  require_read(stream, extra, "ZIP local extra fields");
  const auto local_compressed32 = span_le_u32(header, 18);
  const auto local_uncompressed32 = span_le_u32(header, 22);
  const bool need_local_compressed = local_compressed32 == 0xffffffffU;
  const bool need_local_uncompressed = local_uncompressed32 == 0xffffffffU;
  const auto local_zip64 = parse_zip64_extra(
      extra, need_local_uncompressed, need_local_compressed, false, false);
  if ((need_local_compressed || need_local_uncompressed) &&
      span_le_u16(header, 4) < zip_version_45) {
    throw std::runtime_error("ZIP64 local header has an invalid version");
  }
  const auto local_compressed =
      need_local_compressed ? *local_zip64.compressed_size
                            : static_cast<std::uint64_t>(local_compressed32);
  const auto local_uncompressed =
      need_local_uncompressed
          ? *local_zip64.uncompressed_size
          : static_cast<std::uint64_t>(local_uncompressed32);
  const auto data_offset = checked_add(
      checked_add(checked_add(local_absolute, 30, "ZIP local header"),
                  name_length, "ZIP local header"),
      extra_length, "ZIP local header");
  if (data_offset > file_size ||
      info.compressed_size > file_size - data_offset) {
    throw std::runtime_error("ZIP entry data exceeds packed file");
  }
  const bool uses_descriptor = (info.flags & 0x0008U) != 0;
  if (uses_descriptor) {
    if ((local_compressed != 0 && local_compressed != info.compressed_size) ||
        (local_uncompressed != 0 &&
         local_uncompressed != info.uncompressed_size)) {
      throw std::runtime_error("ZIP local and central sizes differ");
    }
  } else if (span_le_u32(header, 14) != info.crc ||
             local_compressed != info.compressed_size ||
             local_uncompressed != info.uncompressed_size) {
    throw std::runtime_error("ZIP local and central metadata differ");
  }
  const auto data_end =
      checked_add(data_offset, info.compressed_size, "ZIP entry data");
  const auto boundary = info.has_central_directory
                            ? checked_add(zip_offset, info.central_offset,
                                          "ZIP central directory offset")
                            : file_size;
  if (data_end > boundary)
    throw std::runtime_error("ZIP structures overlap");
  if (uses_descriptor) {
    const auto descriptor_size = boundary - data_end;
    if (descriptor_size != 16 && descriptor_size != 24) {
      throw std::runtime_error("invalid ZIP data-descriptor size");
    }
    std::array<std::uint8_t, 24> descriptor{};
    seek(stream, data_end);
    const auto descriptor_bytes =
        std::span(descriptor).first(static_cast<std::size_t>(descriptor_size));
    require_read(stream, descriptor_bytes, "ZIP data descriptor");
    if (span_le_u32(descriptor_bytes, 0) != data_descriptor_signature ||
        span_le_u32(descriptor_bytes, 4) != info.crc) {
      throw std::runtime_error(
          "ZIP data descriptor differs from central entry");
    }
    const auto descriptor_compressed = descriptor_size == 24
                                           ? span_le_u64(descriptor_bytes, 8)
                                           : span_le_u32(descriptor_bytes, 8);
    const auto descriptor_uncompressed =
        descriptor_size == 24 ? span_le_u64(descriptor_bytes, 16)
                              : span_le_u32(descriptor_bytes, 12);
    if (descriptor_compressed != info.compressed_size ||
        descriptor_uncompressed != info.uncompressed_size) {
      throw std::runtime_error("ZIP data-descriptor sizes differ");
    }
  } else if (data_end != boundary) {
    throw std::runtime_error("unexpected bytes before ZIP central directory");
  }
  return data_offset;
}

void write_zip_prefix(std::ostream &output, bool zip64) {
  write_le_u32(output, local_header_signature);
  write_le_u16(output, zip64 ? zip_version_45 : zip_version_20);
  write_le_u16(output, zip_flags);
  write_le_u16(output, deflated_method);
  write_le_u16(output, 0);
  write_le_u16(output, 0);
  write_le_u32(output, 0);
  write_le_u32(output, zip64 ? 0xffffffffU : 0U);
  write_le_u32(output, zip64 ? 0xffffffffU : 0U);
  write_le_u16(output, static_cast<std::uint16_t>(zip_entry_name.size()));
  write_le_u16(output, zip64 ? 20 : 0);
  require_write(
      output,
      std::span(reinterpret_cast<const std::uint8_t *>(zip_entry_name.data()),
                zip_entry_name.size()),
      "ZIP entry name");
  if (zip64) {
    write_le_u16(output, zip64_extra_id);
    write_le_u16(output, 16);
    write_le_u64(output, 0);
    write_le_u64(output, 0);
  }
}

void write_zip_suffix(std::ostream &output, std::uint32_t crc,
                      std::uint64_t compressed_size,
                      std::uint64_t uncompressed_size, bool zip64) {
  if (!zip64 &&
      (compressed_size > (std::numeric_limits<std::uint32_t>::max)() ||
       uncompressed_size > (std::numeric_limits<std::uint32_t>::max)())) {
    throw std::overflow_error("ZIP32 entry size overflow");
  }
  write_le_u32(output, data_descriptor_signature);
  write_le_u32(output, crc);
  if (zip64) {
    write_le_u64(output, compressed_size);
    write_le_u64(output, uncompressed_size);
  } else {
    write_le_u32(output, static_cast<std::uint32_t>(compressed_size));
    write_le_u32(output, static_cast<std::uint32_t>(uncompressed_size));
  }

  const auto local_extra_size = zip64 ? 20ULL : 0ULL;
  const auto descriptor_size = zip64 ? 24ULL : 16ULL;
  const auto central_offset =
      checked_add(checked_add(30ULL + zip_entry_name.size() + local_extra_size,
                              compressed_size, "ZIP central offset"),
                  descriptor_size, "ZIP central offset");
  if (!zip64 && central_offset > (std::numeric_limits<std::uint32_t>::max)()) {
    throw std::overflow_error("ZIP32 central offset overflow");
  }
  write_le_u32(output, central_header_signature);
  write_le_u16(output, zip64 ? zip_version_45 : zip_version_20);
  write_le_u16(output, zip64 ? zip_version_45 : zip_version_20);
  write_le_u16(output, zip_flags);
  write_le_u16(output, deflated_method);
  write_le_u16(output, 0);
  write_le_u16(output, 0);
  write_le_u32(output, crc);
  write_le_u32(output, zip64 ? 0xffffffffU
                             : static_cast<std::uint32_t>(compressed_size));
  write_le_u32(output, zip64 ? 0xffffffffU
                             : static_cast<std::uint32_t>(uncompressed_size));
  write_le_u16(output, static_cast<std::uint16_t>(zip_entry_name.size()));
  write_le_u16(output, zip64 ? 28 : 0);
  write_le_u16(output, 0);
  write_le_u16(output, 0);
  write_le_u16(output, 0);
  write_le_u32(output, 0);
  write_le_u32(output, zip64 ? 0xffffffffU : 0U);
  require_write(
      output,
      std::span(reinterpret_cast<const std::uint8_t *>(zip_entry_name.data()),
                zip_entry_name.size()),
      "ZIP central entry name");
  if (zip64) {
    write_le_u16(output, zip64_extra_id);
    write_le_u16(output, 24);
    write_le_u64(output, uncompressed_size);
    write_le_u64(output, compressed_size);
    write_le_u64(output, 0);
  }
  const auto central_size =
      46ULL + zip_entry_name.size() + (zip64 ? 28ULL : 0ULL);

  if (zip64) {
    const auto zip64_end_offset =
        checked_add(central_offset, central_size, "ZIP64 end offset");
    write_le_u32(output, zip64_eocd_signature);
    write_le_u64(output, 44);
    write_le_u16(output, zip_version_45);
    write_le_u16(output, zip_version_45);
    write_le_u32(output, 0);
    write_le_u32(output, 0);
    write_le_u64(output, 1);
    write_le_u64(output, 1);
    write_le_u64(output, central_size);
    write_le_u64(output, central_offset);
    write_le_u32(output, zip64_locator_signature);
    write_le_u32(output, 0);
    write_le_u64(output, zip64_end_offset);
    write_le_u32(output, 1);
  }

  write_le_u32(output, eocd_signature);
  write_le_u16(output, 0);
  write_le_u16(output, 0);
  write_le_u16(output, zip64 ? 0xffffU : 1U);
  write_le_u16(output, zip64 ? 0xffffU : 1U);
  write_le_u32(output,
               zip64 ? 0xffffffffU : static_cast<std::uint32_t>(central_size));
  write_le_u32(output, zip64 ? 0xffffffffU
                             : static_cast<std::uint32_t>(central_offset));
  write_le_u16(output, 0);
}

bool zip32_deflate_may_overflow(std::uint64_t length) {
  constexpr auto maximum =
      static_cast<std::uint64_t>((std::numeric_limits<std::uint32_t>::max)());
  if (length > maximum)
    return true;
  // A raw DEFLATE stream can always fall back to stored blocks. Reserve a
  // conservative five-byte header per 16 KiB plus stream framing so that the
  // local header format is selected before compression starts.
  const auto blocks = (length + 16382ULL) / 16383ULL;
  const auto overhead = checked_add(blocks * 5ULL, 16ULL, "DEFLATE size bound");
  return overhead > maximum - length;
}

} // namespace

bool is_packed_item(const std::filesystem::path &path) {
  try {
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
      return false;
    seek(stream, 6);
    std::uint64_t magic = 0;
    for (int index = 0; index < 8; ++index) {
      magic = (magic << 8) | read_u8(stream, "packed item probe");
    }
    return magic == packed_magic;
  } catch (...) {
    return false;
  }
}

void pack_item(const std::filesystem::path &input,
               const std::filesystem::path &output,
               const std::string &item_name,
               const std::optional<std::string> &content_type,
               std::int32_t file_type, const PackedItemPackOptions &options,
               const TaskContext &task) {
  if (!std::filesystem::is_regular_file(input)) {
    throw std::invalid_argument("packed item input is not a regular file");
  }
  if (std::filesystem::exists(output)) {
    throw std::runtime_error("packed item output already exists");
  }
  const auto length = std::filesystem::file_size(input);
  if (length >
      static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)())) {
    throw std::length_error("packed item exceeds signed metadata length");
  }
  const bool zip64 = options.force_zip64 || zip32_deflate_may_overflow(length);
  PackedItemMetadata metadata{item_name, content_type, file_type, length};
  (void)encode_modified_utf8(item_name);
  (void)encode_modified_utf8(content_type.value_or(""));
  task.report("packed-item.pack", 0, length);

  const auto temporary = temporary_sibling(output);
  bool installed = false;
  try {
    std::ifstream source(input, std::ios::binary);
    std::ofstream packed(temporary, std::ios::binary | std::ios::trunc);
    if (!source || !packed)
      throw std::runtime_error("unable to open packed item files");
    write_object_header(packed, metadata);
    write_zip_prefix(packed, zip64);

    z_stream compressor{};
    if (deflateInit2(&compressor, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
                     8, Z_DEFAULT_STRATEGY) != Z_OK) {
      throw std::runtime_error("unable to initialize packed item deflate");
    }
    std::array<std::uint8_t, io_buffer_size> input_bytes{};
    std::array<std::uint8_t, io_buffer_size> output_bytes{};
    Crc32 crc;
    std::uint64_t consumed = 0;
    std::uint64_t compressed_size = 0;
    int result = Z_OK;
    try {
      do {
        source.read(reinterpret_cast<char *>(input_bytes.data()),
                    static_cast<std::streamsize>(input_bytes.size()));
        const auto count = source.gcount();
        if (count < 0 || (!source.eof() && !source)) {
          throw std::runtime_error("unable to read packed item input");
        }
        const auto size = static_cast<std::size_t>(count);
        consumed = checked_add(consumed, size, "packed input length");
        crc.update(std::span(input_bytes).first(size));
        task.report("packed-item.pack", consumed, length);
        compressor.next_in = input_bytes.data();
        compressor.avail_in = static_cast<uInt>(size);
        const auto flush = source.eof() ? Z_FINISH : Z_NO_FLUSH;
        do {
          compressor.next_out = output_bytes.data();
          compressor.avail_out = static_cast<uInt>(output_bytes.size());
          result = deflate(&compressor, flush);
          if (result != Z_OK && result != Z_STREAM_END) {
            throw std::runtime_error("packed item deflate failed");
          }
          const auto produced = output_bytes.size() - compressor.avail_out;
          compressed_size =
              checked_add(compressed_size, produced, "packed compressed size");
          require_write(packed, std::span(output_bytes).first(produced),
                        "packed item deflate payload");
        } while (compressor.avail_out == 0 ||
                 (flush == Z_FINISH && result != Z_STREAM_END));
      } while (result != Z_STREAM_END);
    } catch (...) {
      deflateEnd(&compressor);
      throw;
    }
    deflateEnd(&compressor);
    if (consumed != length) {
      throw std::runtime_error(
          "packed item input length changed while packing");
    }
    write_zip_suffix(packed, crc.value(), compressed_size, length, zip64);
    task.checkpoint();
    packed.flush();
    if (!packed)
      throw std::runtime_error("unable to flush packed item");
    packed.close();
    source.close();
    task.checkpoint();
    install_temporary(temporary, output);
    installed = true;
  } catch (...) {
    if (!installed) {
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
    }
    throw;
  }
}

PackedItemReader::PackedItemReader(std::filesystem::path packed_path,
                                   PackedItemReadLimits limits)
    : path_(std::move(packed_path)), limits_(limits) {
  if (limits_.maximum_expansion_ratio == 0) {
    throw std::invalid_argument("packed item expansion ratio must be nonzero");
  }
  std::ifstream stream(path_, std::ios::binary);
  if (!stream)
    throw std::runtime_error("unable to open packed item");
  auto parsed = read_object_header(stream);
  metadata_ = std::move(parsed.first);
  zip_offset_ = parsed.second;
  if (metadata_.length > limits_.maximum_uncompressed_size) {
    throw std::runtime_error("packed item exceeds configured output limit");
  }
}

void PackedItemReader::unpack_to_stream(std::ostream &unpacked,
                                        const TaskContext &task) const {
  const auto file_size = std::filesystem::file_size(path_);
  std::ifstream packed(path_, std::ios::binary);
  if (!packed)
    throw std::runtime_error("unable to reopen packed item");
  const auto info = read_zip_directory(packed, zip_offset_, file_size);
  if (info.method != deflated_method && info.method != stored_method) {
    throw std::runtime_error("unsupported packed ZIP compression method");
  }
  if (info.uncompressed_size != metadata_.length) {
    throw std::runtime_error("packed metadata and ZIP lengths differ");
  }
  if (info.uncompressed_size > limits_.maximum_uncompressed_size ||
      info.compressed_size > limits_.maximum_compressed_size) {
    throw std::runtime_error("packed ZIP exceeds configured resource limits");
  }
  if (info.uncompressed_size > (1ULL << 20) && info.compressed_size != 0 &&
      (info.uncompressed_size - 1) / info.compressed_size >=
          limits_.maximum_expansion_ratio) {
    throw std::runtime_error("packed ZIP exceeds configured expansion ratio");
  }
  const auto data_offset =
      read_local_data_offset(packed, zip_offset_, info, file_size);
  task.report("packed-item.unpack", 0, info.uncompressed_size);
  seek(packed, data_offset);
  std::array<std::uint8_t, io_buffer_size> input_bytes{};
  std::array<std::uint8_t, io_buffer_size> output_bytes{};
  Crc32 crc;
  std::uint64_t remaining = info.compressed_size;
  std::uint64_t produced_total = 0;

  if (info.method == stored_method) {
    while (remaining != 0) {
      const auto count = static_cast<std::size_t>(
          (std::min<std::uint64_t>)(remaining, input_bytes.size()));
      require_read(packed, std::span(input_bytes).first(count),
                   "stored ZIP payload");
      require_write(unpacked, std::span(input_bytes).first(count),
                    "unpacked item payload");
      crc.update(std::span(input_bytes).first(count));
      remaining -= count;
      produced_total =
          checked_add(produced_total, count, "unpacked item length");
      task.report("packed-item.unpack", produced_total, info.uncompressed_size);
    }
  } else {
    z_stream decompressor{};
    if (inflateInit2(&decompressor, -MAX_WBITS) != Z_OK) {
      throw std::runtime_error("unable to initialize packed item inflate");
    }
    int result = Z_OK;
    try {
      while (result != Z_STREAM_END) {
        if (decompressor.avail_in == 0 && remaining != 0) {
          const auto count = static_cast<std::size_t>(
              (std::min<std::uint64_t>)(remaining, input_bytes.size()));
          require_read(packed, std::span(input_bytes).first(count),
                       "deflated ZIP payload");
          decompressor.next_in = input_bytes.data();
          decompressor.avail_in = static_cast<uInt>(count);
          remaining -= count;
        }
        decompressor.next_out = output_bytes.data();
        decompressor.avail_out = static_cast<uInt>(output_bytes.size());
        result = inflate(&decompressor, Z_NO_FLUSH);
        if (result != Z_OK && result != Z_STREAM_END) {
          throw std::runtime_error("packed item inflate failed");
        }
        const auto produced = output_bytes.size() - decompressor.avail_out;
        if (produced_total > metadata_.length ||
            produced > metadata_.length - produced_total) {
          throw std::runtime_error(
              "packed item expands beyond declared length");
        }
        require_write(unpacked, std::span(output_bytes).first(produced),
                      "unpacked item payload");
        crc.update(std::span(output_bytes).first(produced));
        produced_total += produced;
        if (produced != 0) {
          task.report("packed-item.unpack", produced_total,
                      info.uncompressed_size);
        }
        if (decompressor.avail_in == 0 && remaining == 0 && produced == 0 &&
            result != Z_STREAM_END) {
          throw std::runtime_error("truncated packed deflate stream");
        }
      }
      if (remaining != 0 || decompressor.avail_in != 0) {
        throw std::runtime_error(
            "packed deflate stream ended before ZIP boundary");
      }
    } catch (...) {
      inflateEnd(&decompressor);
      throw;
    }
    inflateEnd(&decompressor);
  }

  if (produced_total != info.uncompressed_size ||
      produced_total != metadata_.length || crc.value() != info.crc) {
    throw std::runtime_error("packed item length or CRC mismatch");
  }
  task.report("packed-item.unpack", produced_total, info.uncompressed_size);
}

void PackedItemReader::unpack_to(const std::filesystem::path &output,
                                 const TaskContext &task) const {
  task.checkpoint();
  if (std::filesystem::exists(output)) {
    throw std::runtime_error("packed item unpack output already exists");
  }
  const auto temporary = temporary_sibling(output);
  bool installed = false;
  try {
    std::ofstream unpacked(temporary, std::ios::binary | std::ios::trunc);
    if (!unpacked)
      throw std::runtime_error("unable to create unpack output");
    unpack_to_stream(unpacked, task);
    unpacked.flush();
    if (!unpacked)
      throw std::runtime_error("unable to flush unpacked item");
    unpacked.close();
    task.checkpoint();
    install_temporary(temporary, output);
    installed = true;
  } catch (...) {
    if (!installed) {
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
    }
    throw;
  }
}

void PackedItemReader::verify(const TaskContext &task) const {
  NullStreamBuffer buffer;
  std::ostream sink(&buffer);
  unpack_to_stream(sink, task);
  if (!sink)
    throw std::runtime_error("unable to verify packed item payload");
}

} // namespace llmghidra::db
