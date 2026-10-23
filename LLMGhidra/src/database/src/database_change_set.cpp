/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/db/database_change_set.hpp"

#include "llmghidra/db/database_handle.hpp"
#include "llmghidra/db/local_buffer_file.hpp"

#include <stdexcept>

namespace llmghidra::db {

void write_database_change_set(
    DatabaseChangeSet &change_set,
    const std::shared_ptr<LocalBufferFile> &destination, bool is_recovery_save,
    const TaskContext &task) {
  if (!destination || destination->closed() || destination->read_only()) {
    throw std::invalid_argument(
        "change-set destination must be an open writable buffer file");
  }
  if (destination->index_count() != 0) {
    throw std::invalid_argument(
        "change-set destination must be an empty buffer file");
  }

  try {
    task.checkpoint();
    // DBChangeSet.write receives a fresh, database-backed handle.  Use the
    // destination's buffer size so the serialized file can be consumed by the
    // same Ghidra database layer on every host.
    DatabaseHandle scratch(destination->buffer_size());
    change_set.write(scratch, is_recovery_save);
    task.checkpoint();
    if (scratch.transaction_active()) {
      throw std::logic_error(
          "DatabaseChangeSet::write left an active transaction");
    }
    if (scratch.has_uncommitted_changes()) {
      throw std::logic_error(
          "DatabaseChangeSet::write left uncommitted database changes");
    }
    scratch.save_as(destination, false, task);
    // save_as() makes the destination read-only.  Closing it here releases the
    // file descriptor before managed-save or recovery publication takes place.
    destination->close();
  } catch (...) {
    const auto path = destination->path();
    try {
      if (!destination->closed() && !destination->read_only()) {
        (void)destination->delete_file();
      } else {
        destination->close();
        std::error_code error;
        std::filesystem::remove(path, error);
      }
    } catch (...) {
    }
    throw;
  }
}

void read_database_change_set(DatabaseChangeSet &change_set,
                              const std::filesystem::path &path,
                              const TaskContext &task) {
  if (!std::filesystem::is_regular_file(path)) {
    throw std::invalid_argument("change-set file does not exist");
  }

  task.checkpoint();
  auto source = std::make_shared<LocalBufferFile>(
      path, LocalBufferFile::OpenMode::read_only);
  DatabaseHandle database(
      source, BufferManager::default_cache_size,
      static_cast<std::int32_t>(BufferManager::default_undo_count), true);
  task.checkpoint();
  change_set.read(database);
  task.checkpoint();
  database.close();
}

} // namespace llmghidra::db
