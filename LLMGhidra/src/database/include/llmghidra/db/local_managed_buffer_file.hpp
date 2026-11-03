/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "llmghidra/db/buffer_file_manager.hpp"
#include "llmghidra/db/change_map.hpp"
#include "llmghidra/db/local_buffer_file.hpp"
#include "llmghidra/db/version_file.hpp"
#include "llmghidra/db/version_file_handler.hpp"
#include "llmghidra/task_control.hpp"

#include <condition_variable>
#include <cstdint>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace llmghidra::db {

// Version-aware LocalBufferFile. An updateable current view constructs its
// pre-save on a joined background worker using a separate read handle. Waiting
// for that worker is independently cancellable and never cancels the reusable
// pre-save itself.
class LocalManagedBufferFile final
    : public LocalBufferFile,
      public std::enable_shared_from_this<LocalManagedBufferFile> {
public:
  // Initial version writer (manager.current_version() must be zero).
  LocalManagedBufferFile(std::int32_t buffer_size,
                         std::shared_ptr<BufferFileManager> manager,
                         std::int64_t checkin_id);
  // Current read-only view, optionally updateable through pre-save.
  LocalManagedBufferFile(std::shared_ptr<BufferFileManager> manager,
                         bool version_update_enabled,
                         std::int32_t minimum_change_data_version,
                         std::int64_t checkin_id);
  // Historical read-only reconstructed view.
  LocalManagedBufferFile(std::shared_ptr<BufferFileManager> manager,
                         std::int32_t version,
                         std::int32_t minimum_change_data_version);
  ~LocalManagedBufferFile() override;

  LocalManagedBufferFile(const LocalManagedBufferFile &) = delete;
  LocalManagedBufferFile &operator=(const LocalManagedBufferFile &) = delete;

  [[nodiscard]] std::int32_t version() const noexcept { return version_; }
  [[nodiscard]] std::int64_t checkin_id() const noexcept { return checkin_id_; }
  void set_version_comment(std::string comment) {
    comment_ = std::move(comment);
  }
  [[nodiscard]] bool can_save() const noexcept;
  [[nodiscard]] bool save_in_progress() const noexcept;

  [[nodiscard]] std::shared_ptr<LocalManagedBufferFile>
  get_save_file(const TaskContext &task = {});
  [[nodiscard]] std::shared_ptr<LocalBufferFile>
  get_save_change_data_file() const;
  void save_completed(bool commit);
  void create_new_version(LocalManagedBufferFile &destination,
                          std::string comment);
  void update_from(LocalManagedBufferFile &versioned_file,
                   std::int32_t old_version);

  [[nodiscard]] std::shared_ptr<LocalBufferFile>
  next_change_data_file(bool first);
  [[nodiscard]] std::vector<std::uint8_t>
  forward_modification_map(std::int32_t old_version) const;

  [[nodiscard]] std::int64_t file_id() const noexcept override;
  void set_file_id(std::int64_t value) noexcept override;
  [[nodiscard]] std::int32_t index_count() const noexcept override;
  [[nodiscard]] std::int32_t parameter(const std::string &name) const override;
  void set_parameter(std::string name, std::int32_t value) override;
  void clear_parameters() noexcept override;
  [[nodiscard]] std::vector<std::string> parameter_names() const override;
  [[nodiscard]] const std::vector<std::int32_t> &
  free_indexes() const noexcept override;
  void set_free_indexes(std::span<const std::int32_t> indexes) override;
  DataBuffer &get(DataBuffer &buffer, std::int32_t index) override;
  void put(const DataBuffer &buffer, std::int32_t index) override;
  void put_free_block(std::int32_t index,
                      std::int32_t next_free_index) override;
  bool set_read_only() override;
  void close() override;
  [[nodiscard]] std::unique_ptr<InputBlockStream> input_block_stream() override;
  [[nodiscard]] std::unique_ptr<InputBlockStream>
  input_block_stream(std::span<const std::uint8_t> change_map_data) override;
  [[nodiscard]] std::unique_ptr<OutputBlockStream>
  output_block_stream(std::int32_t block_count) override;

private:
  LocalManagedBufferFile(std::filesystem::path presave_path,
                         std::int32_t buffer_size);
  [[nodiscard]] VersionFileHandler::VersionOpener version_opener() const;
  void initialize_historical_view();
  void start_presave();
  void run_presave(std::shared_ptr<LocalManagedBufferFile> presave,
                   CancellationToken cancellation) noexcept;
  void wait_for_presave(const TaskContext &task) const;
  void discard_presave() noexcept;
  void discard_save_files() noexcept;
  void version_buffer_if_needed(std::int32_t index);
  void commit_save_change_data();
  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  checkout_modification_map() const;
  static void copy_file(LocalBufferFile &source, LocalBufferFile &destination,
                        const ChangeMap *changes);
  void notify_version_created();
  void notify_update_ended();
  [[nodiscard]] static std::filesystem::path
  allocate_presave_path(const std::filesystem::path &directory);

  std::shared_ptr<BufferFileManager> manager_;
  std::unique_ptr<VersionFileHandler> version_handler_;
  std::unique_ptr<VersionFile> version_output_;
  std::unique_ptr<ChangeMapFile> change_map_;

  mutable std::mutex lifecycle_mutex_;
  mutable std::mutex presave_mutex_;
  mutable std::condition_variable presave_cv_;
  std::thread presave_worker_;
  CancellationSource presave_cancel_;
  std::exception_ptr presave_error_;
  std::uint64_t presave_completed_ = 0;
  std::uint64_t presave_total_ = 0;
  bool presave_done_ = true;
  bool presave_shutdown_ = false;
  std::shared_ptr<LocalManagedBufferFile> pre_save_file_;
  std::shared_ptr<LocalManagedBufferFile> save_file_;
  std::shared_ptr<LocalBufferFile> save_change_file_;
  std::int32_t version_ = 0;
  std::int32_t minimum_change_data_version_ = -1;
  std::int32_t next_change_data_version_ = -1;
  std::int64_t checkin_id_ = -1;
  std::string comment_;
  bool open_for_update_ = false;
  bool update_end_required_ = false;
  bool version_notified_ = false;
  bool update_notified_ = false;
  bool update_transferred_ = false;

  bool historical_view_ = false;
  std::int64_t historical_file_id_ = 0;
  std::int32_t historical_index_count_ = 0;
  std::vector<std::int32_t> historical_free_indexes_;
  std::map<std::string, std::int32_t> historical_parameters_;
};

} // namespace llmghidra::db
