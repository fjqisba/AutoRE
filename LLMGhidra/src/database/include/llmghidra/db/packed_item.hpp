/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/task_control.hpp"

#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>

namespace llmghidra::db {

// Metadata stored by Ghidra's ItemSerializer before the embedded ZIP stream.
struct PackedItemMetadata final {
  std::string item_name;
  std::optional<std::string> content_type;
  std::int32_t file_type = 0;
  std::uint64_t length = 0;
};

// ZIP64 can be forced for interoperability and boundary testing without
// manufacturing a multi-gigabyte input. Production callers normally leave
// this false; pack_item() selects ZIP64 automatically when a ZIP32 field may
// overflow.
struct PackedItemPackOptions final {
  bool force_zip64 = false;
};

// Resource limits are checked before any output is installed and again while
// inflating. Callers handling intentionally larger trusted archives can raise
// them explicitly instead of disabling structural ZIP validation.
struct PackedItemReadLimits final {
  std::uint64_t maximum_uncompressed_size = 1ULL << 40; // 1 TiB
  std::uint64_t maximum_compressed_size = 1ULL << 40;   // 1 TiB
  std::uint64_t maximum_expansion_ratio = 4096;
};

// Performs the same prefix probe as ItemSerializer.isPackedFile. Complete ZIP
// and payload validation is performed by PackedItemReader::unpack_to().
[[nodiscard]] bool is_packed_item(const std::filesystem::path &path);

// Streams one input file into the container family produced by Ghidra's
// ItemSerializer. Existing output paths are rejected; failures leave no output.
void pack_item(const std::filesystem::path &input,
               const std::filesystem::path &output,
               const std::string &item_name,
               const std::optional<std::string> &content_type,
               std::int32_t file_type,
               const PackedItemPackOptions &options = {},
               const TaskContext &task = {});

class PackedItemReader final {
public:
  explicit PackedItemReader(
      std::filesystem::path packed_path,
      PackedItemReadLimits limits = PackedItemReadLimits{});

  [[nodiscard]] const PackedItemMetadata &metadata() const noexcept {
    return metadata_;
  }
  [[nodiscard]] const std::filesystem::path &path() const noexcept {
    return path_;
  }

  // Streams and validates the sole FOLDER_ITEM entry. Existing outputs are
  // rejected; CRC, ZIP size and ObjectStream metadata length must all agree.
  void unpack_to(const std::filesystem::path &output,
                 const TaskContext &task = {}) const;

  // Streams the complete entry through the inflater and validates all
  // metadata, descriptor, length and CRC fields without materializing output.
  void verify(const TaskContext &task = {}) const;

private:
  void unpack_to_stream(std::ostream &output, const TaskContext &task) const;

  std::filesystem::path path_;
  PackedItemMetadata metadata_;
  PackedItemReadLimits limits_;
  std::uint64_t zip_offset_ = 0;
};

} // namespace llmghidra::db
