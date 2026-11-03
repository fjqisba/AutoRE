/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/packed_database_cache.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#else
#include <sys/stat.h>
#endif

namespace llmghidra::db {
namespace {

constexpr std::string_view cache_prefix = "pdb";
constexpr std::string_view database_prefix = "db.";
constexpr std::string_view database_suffix = ".gbf";
constexpr std::string_view initial_raw_name = "db.1.gbf";
constexpr std::string_view fingerprint_name =
    ".llmghidra-source-fingerprint";
constexpr std::string_view fingerprint_header =
    "LLMGHIDRA_PDB_FINGERPRINT 1";

struct SourceStamp final {
  std::int64_t write_ticks = 0;
  std::uintmax_t size = 0;
  std::uint64_t content_hash = 0;

  friend bool operator==(const SourceStamp &, const SourceStamp &) = default;
};

struct CacheEntry final {
  std::string source_key;
  std::string directory_name;
  SourceStamp source_stamp;
  std::int64_t last_access_ms = 0;
  PackedItemMetadata metadata;
  std::uint64_t raw_hash = 0;
  bool strong_fingerprint = false;
};

class HeldLock final {
public:
  HeldLock(LockFile &lock, std::chrono::milliseconds timeout) : lock_(lock) {
    if (!lock_.create_lock(timeout, true)) {
      throw std::runtime_error("packed database cache lock timeout");
    }
  }
  ~HeldLock() { lock_.remove_lock(); }

  HeldLock(const HeldLock &) = delete;
  HeldLock &operator=(const HeldLock &) = delete;

private:
  LockFile &lock_;
};

std::string path_utf8(const std::filesystem::path &path) {
  // Java ResourceFile/Path stores the platform-native canonical path in its
  // six-field cache.map. Use native separators here for byte-level exchange
  // (POSIX remains '/'; Windows remains '\\').
  const auto value = path.u8string();
  return std::string(reinterpret_cast<const char *>(value.data()), value.size());
}

std::filesystem::path path_from_utf8(const std::string &value) {
  return std::filesystem::path(
      std::u8string(reinterpret_cast<const char8_t *>(value.data()),
                    value.size()));
}

std::filesystem::path normalized_path(const std::filesystem::path &path) {
  std::error_code error;
  auto absolute = std::filesystem::absolute(path, error);
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to resolve packed database path", path, error);
  }
  auto normalized = std::filesystem::weakly_canonical(absolute, error);
  if (error) normalized = absolute.lexically_normal();
  return normalized;
}

std::int64_t now_milliseconds() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::uint64_t hash_file(const std::filesystem::path &path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("unable to hash packed database");
  std::uint64_t hash = 1469598103934665603ULL;
  std::array<char, 64 * 1024> bytes{};
  while (input) {
    input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    const auto count = input.gcount();
    for (std::streamsize index = 0; index < count; ++index) {
      hash ^= static_cast<unsigned char>(bytes[static_cast<std::size_t>(index)]);
      hash *= 1099511628211ULL;
    }
  }
  if (!input.eof()) throw std::runtime_error("unable to read packed database");
  return hash;
}

std::int64_t last_write_milliseconds(const std::filesystem::path &path) {
#if defined(_WIN32)
  WIN32_FILE_ATTRIBUTE_DATA attributes{};
  if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard,
                            &attributes)) {
    throw std::filesystem::filesystem_error(
        "unable to read packed database timestamp", path,
        std::error_code(static_cast<int>(GetLastError()),
                        std::system_category()));
  }
  ULARGE_INTEGER ticks{};
  ticks.LowPart = attributes.ftLastWriteTime.dwLowDateTime;
  ticks.HighPart = attributes.ftLastWriteTime.dwHighDateTime;
  constexpr std::uint64_t windows_epoch_to_unix_100ns =
      116444736000000000ULL;
  if (ticks.QuadPart >= windows_epoch_to_unix_100ns) {
    return static_cast<std::int64_t>(
        (ticks.QuadPart - windows_epoch_to_unix_100ns) / 10000ULL);
  }
  return -static_cast<std::int64_t>(
      (windows_epoch_to_unix_100ns - ticks.QuadPart + 9999ULL) / 10000ULL);
#else
  struct stat attributes {};
  if (::stat(path.c_str(), &attributes) != 0) {
    throw std::filesystem::filesystem_error(
        "unable to read packed database timestamp", path,
        std::error_code(errno, std::generic_category()));
  }
#if defined(__APPLE__)
  const auto seconds = attributes.st_mtimespec.tv_sec;
  const auto nanoseconds = attributes.st_mtimespec.tv_nsec;
#else
  const auto seconds = attributes.st_mtim.tv_sec;
  const auto nanoseconds = attributes.st_mtim.tv_nsec;
#endif
  return static_cast<std::int64_t>(seconds) * 1000 +
         static_cast<std::int64_t>(nanoseconds) / 1000000;
#endif
}

SourceStamp source_stamp(const std::filesystem::path &path) {
  std::error_code error;
  if (!std::filesystem::is_regular_file(path, error) || error) {
    throw std::runtime_error("packed database source does not exist");
  }
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to read packed database size", path, error);
  }
  // Java cache.map persists File.lastModified() as Unix epoch milliseconds.
  // Read the native timestamp directly so the serialized value is exact and
  // does not depend on an implementation-specific std::filesystem clock epoch.
  return {last_write_milliseconds(path),
          size, hash_file(path)};
}

std::uint64_t hash_string(std::string_view value) {
  std::uint64_t hash = 1469598103934665603ULL;
  for (const unsigned char byte : value) {
    hash ^= byte;
    hash *= 1099511628211ULL;
  }
  return hash;
}

bool valid_directory_name(std::string_view value) {
  return value.starts_with(cache_prefix) && value.size() > cache_prefix.size() &&
         value.find('/') == std::string_view::npos &&
         value.find('\\') == std::string_view::npos && value != "." &&
         value != "..";
}

std::filesystem::path entry_directory(const std::filesystem::path &root,
                                      const CacheEntry &entry) {
  if (!valid_directory_name(entry.directory_name)) {
    throw std::runtime_error("invalid packed database cache directory name");
  }
  return root / path_from_utf8(entry.directory_name);
}

std::optional<std::uint64_t> database_version(std::string_view name) {
  if (!name.starts_with(database_prefix) ||
      !name.ends_with(database_suffix)) {
    return std::nullopt;
  }
  const auto digits = name.substr(
      database_prefix.size(),
      name.size() - database_prefix.size() - database_suffix.size());
  if (digits.empty() ||
      std::any_of(digits.begin(), digits.end(),
                  [](const char value) { return value < '0' || value > '9'; })) {
    return std::nullopt;
  }
  std::size_t consumed = 0;
  try {
    const auto version = std::stoull(std::string(digits), &consumed, 10);
    if (consumed == digits.size() && version != 0) return version;
  }
  catch (const std::exception &) {
  }
  return std::nullopt;
}

std::filesystem::path entry_raw_file(const std::filesystem::path &root,
                                     const CacheEntry &entry) {
  const auto directory = entry_directory(root, entry);
  std::filesystem::path current = directory / initial_raw_name;
  std::uint64_t current_version = 0;
  std::error_code error;
  for (const auto &candidate :
       std::filesystem::directory_iterator(directory, error)) {
    if (error) break;
    const auto version = database_version(path_utf8(candidate.path().filename()));
    std::error_code file_error;
    if (version.has_value() && *version > current_version &&
        candidate.is_regular_file(file_error) && !file_error) {
      current = candidate.path();
      current_version = *version;
    }
  }
  return current;
}

std::filesystem::path fingerprint_file(const std::filesystem::path &root,
                                       const CacheEntry &entry) {
  return entry_directory(root, entry) / fingerprint_name;
}

std::vector<std::string> split_legacy_entry(std::string_view line) {
  std::vector<std::string> fields(6);
  std::size_t end = line.size();
  for (std::size_t index = 5; index != 0; --index) {
    const auto separator = line.rfind(',', end == 0 ? 0 : end - 1);
    if (separator == std::string_view::npos || separator == 0 ||
        separator + 1 == end) {
      throw std::invalid_argument("invalid Java cache map entry");
    }
    fields[index] = std::string(line.substr(separator + 1, end - separator - 1));
    end = separator;
  }
  if (end == 0) throw std::invalid_argument("invalid Java cache map path");
  fields[0] = std::string(line.substr(0, end));
  return fields;
}

std::int64_t parse_hex(std::string_view value) {
  if (value.empty()) throw std::invalid_argument("empty cache map number");
  std::size_t consumed = 0;
  const auto parsed = std::stoull(std::string(value), &consumed, 16);
  if (consumed != value.size() || parsed >
      static_cast<unsigned long long>(std::numeric_limits<std::int64_t>::max())) {
    throw std::invalid_argument("invalid cache map number");
  }
  return static_cast<std::int64_t>(parsed);
}

std::uint64_t parse_unsigned_hex(std::string_view value) {
  if (value.empty()) throw std::invalid_argument("empty cache fingerprint number");
  std::size_t consumed = 0;
  const auto parsed = std::stoull(std::string(value), &consumed, 16);
  if (consumed != value.size()) {
    throw std::invalid_argument("invalid cache fingerprint number");
  }
  return parsed;
}

bool load_fingerprint(const std::filesystem::path &root, CacheEntry &entry) {
  std::ifstream input(fingerprint_file(root, entry), std::ios::binary);
  if (!input) return false;
  std::string header;
  std::string write_ticks;
  std::string source_size;
  std::string source_hash;
  std::string raw_size;
  std::string raw_hash;
  if (!std::getline(input, header) || header != fingerprint_header ||
      !(input >> write_ticks >> source_size >> source_hash >> raw_size >>
        raw_hash)) {
    return false;
  }
  try {
    const auto parsed_write_ticks = parse_hex(write_ticks);
    if (parsed_write_ticks != entry.source_stamp.write_ticks) return false;
    entry.source_stamp.size = parse_unsigned_hex(source_size);
    entry.source_stamp.content_hash = parse_unsigned_hex(source_hash);
    entry.metadata.length = parse_unsigned_hex(raw_size);
    entry.raw_hash = parse_unsigned_hex(raw_hash);
    entry.strong_fingerprint = true;
    return true;
  }
  catch (const std::exception &) {
    return false;
  }
}

void save_fingerprint(const std::filesystem::path &root,
                      const CacheEntry &entry) {
  if (!entry.strong_fingerprint) {
    throw std::invalid_argument("cache entry has no strong fingerprint");
  }
  const auto target = fingerprint_file(root, entry);
  auto temporary = target;
  temporary += ".tmp";
  std::error_code ignored;
  std::filesystem::remove(temporary, ignored);
  try {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("unable to create cache fingerprint");
    output << fingerprint_header << '\n' << std::hex
           << entry.source_stamp.write_ticks << ' ' << entry.source_stamp.size
           << ' ' << entry.source_stamp.content_hash << ' '
           << entry.metadata.length << ' ' << entry.raw_hash << std::dec
           << '\n';
    output.flush();
    if (!output) throw std::runtime_error("unable to flush cache fingerprint");
    output.close();
    std::filesystem::remove(target, ignored);
    std::filesystem::rename(temporary, target);
  }
  catch (...) {
    std::filesystem::remove(temporary, ignored);
    throw;
  }
}

std::vector<CacheEntry> load_map(const std::filesystem::path &root,
                                 const std::filesystem::path &map_path,
                                 bool &modified) {
  std::vector<CacheEntry> entries;
  if (!std::filesystem::exists(map_path)) return entries;
  std::ifstream input(map_path, std::ios::binary);
  if (!input) throw std::runtime_error("unable to read packed database cache map");
  std::string line;
  std::set<std::string> keys;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    try {
      const auto fields = split_legacy_entry(line);
      CacheEntry entry;
      entry.source_key = fields[0];
      entry.directory_name = fields[1];
      entry.source_stamp.write_ticks = parse_hex(fields[2]);
      entry.last_access_ms = parse_hex(fields[5]);
      entry.metadata.content_type = fields[3];
      entry.metadata.item_name = fields[4];
      entry.metadata.file_type = 0;
      if (!valid_directory_name(entry.directory_name) ||
          !keys.insert(entry.source_key).second) {
        throw std::invalid_argument("invalid Java cache map entry");
      }
      (void)load_fingerprint(root, entry);
      entries.push_back(std::move(entry));
    }
    catch (const std::exception &) {
      modified = true;
    }
  }
  return entries;
}

void save_map(const std::filesystem::path &map_path,
              const std::vector<CacheEntry> &entries) {
  auto temporary = map_path;
  temporary += ".tmp";
  auto backup = map_path;
  backup += ".bak";
  std::error_code ignored;
  std::filesystem::remove(temporary, ignored);
  std::filesystem::remove(backup, ignored);

  try {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("unable to create cache map");
    for (const auto &entry : entries) {
      const auto content_type = entry.metadata.content_type.value_or("");
      if (content_type.empty() || entry.metadata.item_name.empty() ||
          content_type.find_first_of(",\r\n") != std::string::npos ||
          entry.metadata.item_name.find_first_of(",\r\n") !=
              std::string::npos ||
          entry.source_key.find_first_of("\r\n") != std::string::npos) {
        throw std::runtime_error(
            "packed database metadata cannot be represented in Java cache map");
      }
      output << entry.source_key << ',' << entry.directory_name << ','
             << std::hex << entry.source_stamp.write_ticks << ','
             << content_type << ','
             << entry.metadata.item_name << ',' << entry.last_access_ms
             << std::dec << '\n';
    }
    output.flush();
    if (!output) throw std::runtime_error("unable to flush cache map");
    output.close();

    if (std::filesystem::exists(map_path)) {
      std::filesystem::rename(map_path, backup);
    }
    try {
      std::filesystem::rename(temporary, map_path);
    }
    catch (...) {
      if (std::filesystem::exists(backup) && !std::filesystem::exists(map_path)) {
        std::filesystem::rename(backup, map_path, ignored);
      }
      throw;
    }
    std::filesystem::remove(backup, ignored);
  }
  catch (...) {
    std::filesystem::remove(temporary, ignored);
    throw;
  }
}

std::size_t remove_entry(const std::filesystem::path &root,
                         const CacheEntry &entry) {
  std::error_code error;
  const auto count = std::filesystem::remove_all(entry_directory(root, entry), error);
  if (error) {
    throw std::filesystem::filesystem_error(
        "unable to remove packed database cache entry",
        entry_directory(root, entry), error);
  }
  return count == 0 ? 0 : 1;
}

bool cached_raw_valid(const std::filesystem::path &root,
                      const CacheEntry &entry) {
  std::error_code error;
  const auto raw = entry_raw_file(root, entry);
  if (!std::filesystem::is_regular_file(raw, error) || error) return false;
  const auto size = std::filesystem::file_size(raw, error);
  if (error || size == 0) return false;
  if (!entry.strong_fingerprint) return true;
  return size == entry.metadata.length && hash_file(raw) == entry.raw_hash;
}

std::size_t clean_entries(const std::filesystem::path &root,
                          std::vector<CacheEntry> &entries,
                          std::chrono::milliseconds shelf_life) {
  const auto now = now_milliseconds();
  std::size_t removed = 0;
  auto iterator = entries.begin();
  while (iterator != entries.end()) {
    bool expired = shelf_life.count() >= 0 &&
                   now - iterator->last_access_ms > shelf_life.count();
    std::error_code error;
    const auto source = path_from_utf8(iterator->source_key);
    const bool source_missing =
        !std::filesystem::is_regular_file(source, error) || error;
    if (expired || source_missing || !cached_raw_valid(root, *iterator)) {
      removed += remove_entry(root, *iterator);
      iterator = entries.erase(iterator);
    }
    else {
      ++iterator;
    }
  }

  std::set<std::string> referenced;
  for (const auto &entry : entries) referenced.insert(entry.directory_name);
  std::error_code error;
  for (const auto &candidate : std::filesystem::directory_iterator(root, error)) {
    if (error) break;
    const auto name = path_utf8(candidate.path().filename());
    if (candidate.is_directory() && name.starts_with(cache_prefix) &&
        !referenced.contains(name)) {
      std::error_code remove_error;
      const auto count = std::filesystem::remove_all(candidate.path(), remove_error);
      if (!remove_error && count != 0) ++removed;
    }
  }
  return removed;
}

std::string allocate_directory_name(const std::filesystem::path &root,
                                    std::string_view source_key) {
  std::ostringstream base;
  base << cache_prefix << std::uppercase << std::hex << std::setw(16)
       << std::setfill('0') << hash_string(source_key);
  for (std::uint32_t suffix = 0; suffix < 10000; ++suffix) {
    auto name = base.str();
    if (suffix != 0) name += "-" + std::to_string(suffix);
    if (!std::filesystem::exists(root / path_from_utf8(name))) return name;
  }
  throw std::runtime_error("unable to allocate packed database cache directory");
}

void copy_new_file(const std::filesystem::path &source,
                   const std::filesystem::path &destination) {
  if (std::filesystem::exists(destination)) {
    throw std::runtime_error("cache materialization destination already exists");
  }
  auto temporary = destination;
  temporary += ".cache.tmp";
  std::error_code ignored;
  std::filesystem::remove(temporary, ignored);
  try {
    std::filesystem::copy_file(source, temporary);
    std::filesystem::rename(temporary, destination);
  }
  catch (...) {
    std::filesystem::remove(temporary, ignored);
    throw;
  }
}

CacheEntry make_entry(const std::filesystem::path &root,
                      const std::filesystem::path &source,
                      const SourceStamp &stamp,
                      const PackedItemMetadata &metadata) {
  CacheEntry entry;
  entry.source_key = path_utf8(source);
  entry.directory_name = allocate_directory_name(root, entry.source_key);
  entry.source_stamp = stamp;
  entry.last_access_ms = now_milliseconds();
  entry.metadata = metadata;
  entry.raw_hash = 0;
  entry.strong_fingerprint = true;
  return entry;
}

} // namespace

PackedDatabaseCache::PackedDatabaseCache(PackedDatabaseCacheOptions options)
    : root_(normalized_path(std::move(options.root))),
      map_path_(root_ / "cache.map"),
      lock_(root_, "cache", "u", options.lock_options),
      shelf_life_(options.shelf_life), lock_timeout_(options.lock_timeout) {
  if (root_.empty()) throw std::invalid_argument("cache root is empty");
  std::error_code error;
  std::filesystem::create_directories(root_, error);
  if (error || !std::filesystem::is_directory(root_)) {
    throw std::filesystem::filesystem_error(
        "unable to create packed database cache", root_, error);
  }
}

PackedDatabaseCacheResult PackedDatabaseCache::materialize(
    const std::filesystem::path &packed_path,
    const std::filesystem::path &destination) {
  std::scoped_lock local(mutex_);
  HeldLock held(lock_, lock_timeout_);
  const auto source = normalized_path(packed_path);
  const auto source_key = path_utf8(source);
  bool map_modified = false;
  auto entries = load_map(root_, map_path_, map_modified);
  if (clean_entries(root_, entries, shelf_life_) != 0) map_modified = true;

  const auto existing =
      std::find_if(entries.begin(), entries.end(), [&](const CacheEntry &entry) {
        return entry.source_key == source_key;
      });
  if (existing != entries.end()) {
    const auto current = source_stamp(source);
    if (existing->strong_fingerprint && current == existing->source_stamp &&
        cached_raw_valid(root_, *existing)) {
      copy_new_file(entry_raw_file(root_, *existing), destination);
      existing->last_access_ms = now_milliseconds();
      save_map(map_path_, entries);
      return {existing->metadata, true};
    }

    // A cache directory created by Ghidra has no native sidecar because the
    // Java cache.map only persists last-modified time.  Adopt it without
    // trusting timestamp alone: compare the cached *.gbf with a freshly
    // unpacked payload once, then persist the strong source/raw fingerprints.
    if (!existing->strong_fingerprint &&
        current.write_ticks == existing->source_stamp.write_ticks &&
        cached_raw_valid(root_, *existing)) {
      auto validation = destination;
      validation += ".source-validation.tmp";
      std::error_code ignored;
      std::filesystem::remove(validation, ignored);
      try {
        PackedItemReader reader(source);
        if (reader.metadata().file_type != 0) {
          throw std::runtime_error("packed cache source is not a database");
        }
        copy_new_file(entry_raw_file(root_, *existing), destination);
        reader.unpack_to(validation);
        const auto cached_hash = hash_file(destination);
        const auto validation_hash = hash_file(validation);
        const bool payload_matches =
            std::filesystem::file_size(destination) ==
                std::filesystem::file_size(validation) &&
            cached_hash == validation_hash;
        std::filesystem::remove(validation, ignored);
        if (payload_matches) {
          existing->source_stamp = current;
          existing->metadata = reader.metadata();
          existing->raw_hash = cached_hash;
          existing->strong_fingerprint = true;
          existing->last_access_ms = now_milliseconds();
          save_fingerprint(root_, *existing);
          save_map(map_path_, entries);
          return {existing->metadata, true};
        }
        std::filesystem::remove(destination, ignored);
      }
      catch (...) {
        std::filesystem::remove(validation, ignored);
        std::filesystem::remove(destination, ignored);
        throw;
      }
    }
    remove_entry(root_, *existing);
    entries.erase(existing);
    map_modified = true;
  }

  for (int attempt = 0; attempt < 3; ++attempt) {
    const auto before = source_stamp(source);
    PackedItemReader reader(source);
    if (reader.metadata().file_type != 0) {
      throw std::runtime_error("packed cache source is not a database");
    }
    auto entry = make_entry(root_, source, before, reader.metadata());
    const auto directory = entry_directory(root_, entry);
    std::filesystem::create_directory(directory);
    try {
      reader.unpack_to(entry_raw_file(root_, entry));
      const auto after = source_stamp(source);
      if (!(after == before)) {
        remove_entry(root_, entry);
        if (attempt == 2) {
          throw std::runtime_error(
              "packed database changed repeatedly while caching");
        }
        continue;
      }
      entry.raw_hash = hash_file(entry_raw_file(root_, entry));
      save_fingerprint(root_, entry);
      copy_new_file(entry_raw_file(root_, entry), destination);
      entries.push_back(entry);
      save_map(map_path_, entries);
      return {entry.metadata, false};
    }
    catch (...) {
      std::error_code ignored;
      std::filesystem::remove(destination, ignored);
      remove_entry(root_, entry);
      throw;
    }
  }
  if (map_modified) save_map(map_path_, entries);
  throw std::runtime_error("unable to materialize packed database cache entry");
}

void PackedDatabaseCache::publish(
    const std::filesystem::path &packed_path,
    const std::filesystem::path &raw_database) {
  std::scoped_lock local(mutex_);
  HeldLock held(lock_, lock_timeout_);
  const auto source = normalized_path(packed_path);
  const auto raw = normalized_path(raw_database);
  PackedItemReader reader(source);
  if (reader.metadata().file_type != 0 ||
      std::filesystem::file_size(raw) != reader.metadata().length) {
    throw std::runtime_error("cache publish source does not match packed database");
  }
  const auto stamp = source_stamp(source);
  bool modified = false;
  auto entries = load_map(root_, map_path_, modified);
  clean_entries(root_, entries, shelf_life_);
  const auto key = path_utf8(source);
  for (auto iterator = entries.begin(); iterator != entries.end();) {
    if (iterator->source_key == key) {
      remove_entry(root_, *iterator);
      iterator = entries.erase(iterator);
    }
    else {
      ++iterator;
    }
  }
  auto entry = make_entry(root_, source, stamp, reader.metadata());
  std::filesystem::create_directory(entry_directory(root_, entry));
  try {
    copy_new_file(raw, entry_raw_file(root_, entry));
    entry.raw_hash = hash_file(entry_raw_file(root_, entry));
    save_fingerprint(root_, entry);
    entries.push_back(entry);
    save_map(map_path_, entries);
  }
  catch (...) {
    remove_entry(root_, entry);
    throw;
  }
}

void PackedDatabaseCache::purge(const std::filesystem::path &packed_path) {
  std::scoped_lock local(mutex_);
  HeldLock held(lock_, lock_timeout_);
  const auto key = path_utf8(normalized_path(packed_path));
  bool modified = false;
  auto entries = load_map(root_, map_path_, modified);
  for (auto iterator = entries.begin(); iterator != entries.end();) {
    if (iterator->source_key == key) {
      remove_entry(root_, *iterator);
      iterator = entries.erase(iterator);
      modified = true;
    }
    else {
      ++iterator;
    }
  }
  if (modified) save_map(map_path_, entries);
}

bool PackedDatabaseCache::contains(
    const std::filesystem::path &packed_path) {
  std::scoped_lock local(mutex_);
  HeldLock held(lock_, lock_timeout_);
  const auto source = normalized_path(packed_path);
  const auto key = path_utf8(source);
  bool modified = false;
  auto entries = load_map(root_, map_path_, modified);
  if (clean_entries(root_, entries, shelf_life_) != 0) modified = true;
  for (auto iterator = entries.begin(); iterator != entries.end(); ++iterator) {
    const auto &entry = *iterator;
    if (entry.source_key != key) continue;
    const auto current = source_stamp(source);
    const bool source_matches =
        entry.strong_fingerprint ? entry.source_stamp == current
                                 : entry.source_stamp.write_ticks ==
                                       current.write_ticks;
    if (source_matches && cached_raw_valid(root_, entry)) {
      if (modified) save_map(map_path_, entries);
      return true;
    }
    remove_entry(root_, entry);
    entries.erase(iterator);
    save_map(map_path_, entries);
    return false;
  }
  if (modified) save_map(map_path_, entries);
  return false;
}

std::size_t PackedDatabaseCache::cleanup() {
  std::scoped_lock local(mutex_);
  HeldLock held(lock_, lock_timeout_);
  bool modified = false;
  auto entries = load_map(root_, map_path_, modified);
  const auto removed = clean_entries(root_, entries, shelf_life_);
  if (modified || removed != 0) save_map(map_path_, entries);
  return removed;
}

} // namespace llmghidra::db
