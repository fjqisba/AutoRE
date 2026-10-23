/* SPDX-License-Identifier: Apache-2.0 */
#include "llmghidra/task_control.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <utility>
#include <vector>

namespace llmghidra {

namespace {

struct CancellationCallbackSlot final {
  std::recursive_mutex mutex;
  bool active = true;
  std::function<void()> callback;
};

} // namespace

struct CancellationToken::State final {
  std::atomic_bool cancelled{false};
  mutable std::mutex callbacks_mutex;
  mutable std::vector<std::weak_ptr<CancellationCallbackSlot>> callbacks;
};

struct CancellationRegistration::Impl final {
  explicit Impl(std::shared_ptr<CancellationCallbackSlot> callback_slot)
      : slot(std::move(callback_slot)) {}

  std::shared_ptr<CancellationCallbackSlot> slot;
};

OperationCancelled::OperationCancelled()
    : std::runtime_error("operation cancelled") {}

CancellationRegistration::CancellationRegistration(
    std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

CancellationRegistration::~CancellationRegistration() { reset(); }

CancellationRegistration::CancellationRegistration(
    CancellationRegistration &&) noexcept = default;

CancellationRegistration &
CancellationRegistration::operator=(CancellationRegistration &&other) noexcept {
  if (this != &other) {
    reset();
    impl_ = std::move(other.impl_);
  }
  return *this;
}

void CancellationRegistration::reset() noexcept {
  if (!impl_)
    return;
  auto slot = std::move(impl_->slot);
  impl_.reset();
  if (!slot)
    return;
  std::scoped_lock lock(slot->mutex);
  slot->active = false;
  slot->callback = {};
}

CancellationToken::CancellationToken(std::shared_ptr<const State> state)
    : state_(std::move(state)) {}

bool CancellationToken::is_cancelled() const noexcept {
  return state_ && state_->cancelled.load(std::memory_order_acquire);
}

void CancellationToken::throw_if_cancelled() const {
  if (is_cancelled())
    throw OperationCancelled();
}

CancellationRegistration
CancellationToken::register_callback(std::function<void()> callback) const {
  if (!state_ || !callback)
    return {};

  auto slot = std::make_shared<CancellationCallbackSlot>();
  slot->callback = std::move(callback);
  bool invoke_now = false;
  {
    std::scoped_lock lock(state_->callbacks_mutex);
    auto &callbacks = state_->callbacks;
    callbacks.erase(
        std::remove_if(callbacks.begin(), callbacks.end(),
                       [](const auto &entry) { return entry.expired(); }),
        callbacks.end());
    if (state_->cancelled.load(std::memory_order_acquire)) {
      invoke_now = true;
    } else {
      callbacks.emplace_back(slot);
    }
  }

  if (invoke_now) {
    std::scoped_lock lock(slot->mutex);
    try {
      slot->callback();
    } catch (...) {
    }
    slot->active = false;
    slot->callback = {};
    return {};
  }
  return CancellationRegistration(
      std::make_unique<CancellationRegistration::Impl>(slot));
}

CancellationSource::CancellationSource()
    : state_(std::make_shared<CancellationToken::State>()) {}

CancellationToken CancellationSource::token() const noexcept {
  return CancellationToken(state_);
}

void CancellationSource::cancel() noexcept {
  if (state_->cancelled.exchange(true, std::memory_order_acq_rel))
    return;

  std::vector<std::shared_ptr<CancellationCallbackSlot>> callbacks;
  {
    std::scoped_lock lock(state_->callbacks_mutex);
    for (auto iterator = state_->callbacks.begin();
         iterator != state_->callbacks.end();) {
      if (auto callback = iterator->lock()) {
        callbacks.push_back(std::move(callback));
        ++iterator;
      } else {
        iterator = state_->callbacks.erase(iterator);
      }
    }
  }

  for (const auto &slot : callbacks) {
    std::scoped_lock lock(slot->mutex);
    if (!slot->active)
      continue;
    try {
      slot->callback();
    } catch (...) {
    }
    slot->active = false;
    slot->callback = {};
  }
}

bool CancellationSource::is_cancelled() const noexcept {
  return state_->cancelled.load(std::memory_order_acquire);
}

void TaskContext::checkpoint() const { cancellation.throw_if_cancelled(); }

void TaskContext::report(std::string_view operation, std::uint64_t completed,
                         std::uint64_t total) const {
  checkpoint();
  if (progress)
    progress->report({operation, completed, total});
  checkpoint();
}

} // namespace llmghidra
