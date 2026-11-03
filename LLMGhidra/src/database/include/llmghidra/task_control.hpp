/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace llmghidra {

class OperationCancelled final : public std::runtime_error {
public:
  OperationCancelled();
};

class CancellationToken;

// Move-only lifetime for a cancellation callback. Destroying or resetting the
// registration waits for an already-running callback and prevents later
// invocation, so callbacks may safely capture operation-local references.
class CancellationRegistration final {
public:
  CancellationRegistration() = default;
  ~CancellationRegistration();
  CancellationRegistration(CancellationRegistration &&) noexcept;
  CancellationRegistration &operator=(CancellationRegistration &&) noexcept;
  CancellationRegistration(const CancellationRegistration &) = delete;
  CancellationRegistration &
  operator=(const CancellationRegistration &) = delete;

  void reset() noexcept;

private:
  struct Impl;
  explicit CancellationRegistration(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;

  friend class CancellationToken;
};

class CancellationSource;

// Cheap copyable view of shared cancellation state. A default token is never
// cancelled, so all long-running APIs can accept TaskContext without nullable
// token ownership or Java-style monitor lifetimes.
class CancellationToken final {
public:
  CancellationToken() = default;

  [[nodiscard]] bool is_cancelled() const noexcept;
  void throw_if_cancelled() const;
  [[nodiscard]] CancellationRegistration
  register_callback(std::function<void()> callback) const;

private:
  struct State;
  explicit CancellationToken(std::shared_ptr<const State> state);
  std::shared_ptr<const State> state_;

  friend class CancellationSource;
};

class CancellationSource final {
public:
  CancellationSource();

  [[nodiscard]] CancellationToken token() const noexcept;
  void cancel() noexcept;
  [[nodiscard]] bool is_cancelled() const noexcept;

private:
  std::shared_ptr<CancellationToken::State> state_;
};

struct ProgressEvent final {
  std::string_view operation;
  std::uint64_t completed = 0;
  std::uint64_t total = 0;
};

class ProgressSink {
public:
  virtual ~ProgressSink() = default;
  virtual void report(const ProgressEvent &event) noexcept = 0;
};

// One stable context is threaded through pack/unpack, managed saves,
// checkpoints, scans and verification. Progress callbacks are observational;
// cancellation is the only control path and is checked explicitly.
struct TaskContext final {
  CancellationToken cancellation;
  ProgressSink *progress = nullptr;

  void checkpoint() const;
  void report(std::string_view operation, std::uint64_t completed,
              std::uint64_t total) const;
};

} // namespace llmghidra
