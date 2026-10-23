/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/task_control.hpp"

#include <filesystem>
#include <memory>

namespace llmghidra::db {

class DatabaseHandle;
class LocalBufferFile;

// Application-level change data associated with a Ghidra database.  The
// handle passed to read/write is owned by the caller and is never retained by
// an implementation, matching db.DBChangeSet's lifetime contract.
class DatabaseChangeSet {
public:
  virtual ~DatabaseChangeSet() = default;

  virtual void read(DatabaseHandle &database) = 0;
  virtual void write(DatabaseHandle &database, bool is_recovery_save) = 0;
};

using DBChangeSet = DatabaseChangeSet;

// Serialize a change set into a newly-created, writable Ghidra buffer file.
// The destination is made read-only on success.  The helper owns the
// temporary DatabaseHandle used by the callback and never retains the file.
void write_database_change_set(
    DatabaseChangeSet &change_set,
    const std::shared_ptr<LocalBufferFile> &destination, bool is_recovery_save,
    const TaskContext &task = {});

// Open a serialized Ghidra change-set file read-only and dispatch it to the
// application callback.  The callback executes synchronously while the
// temporary DatabaseHandle is valid.
void read_database_change_set(DatabaseChangeSet &change_set,
                              const std::filesystem::path &path,
                              const TaskContext &task = {});

} // namespace llmghidra::db
