/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstdint>
#include <memory>

namespace llmghidra::db {

class Field;
class Record;

// Native counterparts of Ghidra's RecordIterator, DBLongIterator and
// DBFieldIterator contracts.  Implementations remain valid across table
// mutations by relocating their logical cursor from the last observed key.
class RecordIterator {
public:
  virtual ~RecordIterator() = default;
  [[nodiscard]] virtual bool has_next() = 0;
  [[nodiscard]] virtual bool has_previous() = 0;
  [[nodiscard]] virtual std::unique_ptr<Record> next() = 0;
  [[nodiscard]] virtual std::unique_ptr<Record> previous() = 0;
  [[nodiscard]] virtual bool delete_last() = 0;
};

class LongKeyIterator {
public:
  virtual ~LongKeyIterator() = default;
  [[nodiscard]] virtual bool has_next() = 0;
  [[nodiscard]] virtual bool has_previous() = 0;
  [[nodiscard]] virtual std::int64_t next() = 0;
  [[nodiscard]] virtual std::int64_t previous() = 0;
  [[nodiscard]] virtual bool delete_last() = 0;
};

class FieldKeyIterator {
public:
  virtual ~FieldKeyIterator() = default;
  [[nodiscard]] virtual bool has_next() = 0;
  [[nodiscard]] virtual bool has_previous() = 0;
  [[nodiscard]] virtual std::unique_ptr<Field> next() = 0;
  [[nodiscard]] virtual std::unique_ptr<Field> previous() = 0;
  [[nodiscard]] virtual bool delete_last() = 0;
};

} // namespace llmghidra::db
