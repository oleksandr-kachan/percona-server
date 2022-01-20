/* Copyright (c) 2022 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#ifndef LOG_WRITER_V2_H_INCLUDED
#define LOG_WRITER_V2_H_INCLUDED

#include "mysql/plugin_audit.h"

#include "my_dir.h"
#include "my_sys.h"

#include <string>
#include <memory>


namespace audit_log_v2 {

enum AuditLogStrategyType {
  Asynchronous,
  Performance,
  Semisynchronous,
  Synchronous
};

enum AuditLogHandlerType { HandlerFile, HandlerSyslog };

struct LogWriterFileConfig {
  char *name;
  size_t rotate_on_size;
  size_t rotations;
  size_t buffer_size;
  AuditLogStrategyType strategy_type;
};

struct LogWriterSyslogConfig {
  const char *ident;
  int facility;
  int priority;
};

struct FileHandle {
  File file;
  char path[FN_REFLEN];
  size_t path_len;
  mysql_mutex_t lock;
};

/*
 * audit_log_v2_strategy = Asynchronous, Performance, Semisynchronous,
 * Synchronous
 */
class FileWriterStrategy {
 public:
  virtual void do_write() = 0;
  virtual ~FileWriterStrategy() = default;
};

class FileWriterStrategyAsync : public FileWriterStrategy {
 public:
  void do_write() override {}
};

class FileWriterStrategyPerformace : public FileWriterStrategy {
 public:
  void do_write() override {}
};

class FileWriterStrategySemisync : public FileWriterStrategy {
 public:
  void do_write() override {}
};

class FileWriterStrategySync : public FileWriterStrategy {
 public:
  void do_write() override {}
};

class LogWriter {
 public:
  virtual void write(std::string &log_record [[maybe_unused]]) = 0;
  virtual bool open() = 0;
  virtual bool close() = 0;
  virtual bool check_opened() = 0;
  virtual ~LogWriter() = default;
  
  // TODO: implement
  uint64_t get_log_size() const { return 0; }
};

class LogWriterFile : public LogWriter {
 public:
  LogWriterFile() = delete;
  explicit LogWriterFile(LogWriterFileConfig conf);
  ~LogWriterFile() override;

  bool open() override;
  bool close() override;

  void write(std::string &log_record [[maybe_unused]]) override {
    // m_strategy->do_write();
  }

  bool check_opened() override { return m_is_opened; }

 private:
  bool do_open_file() noexcept;
  bool do_close_file() noexcept;

 private:
  LogWriterFileConfig m_config;
  FileHandle m_file_handle;
  bool m_is_opened;
  std::unique_ptr<FileWriterStrategy> m_strategy;
};

class LogWriterSyslog : public LogWriter {
 public:
  LogWriterSyslog() = delete;
  explicit LogWriterSyslog(LogWriterSyslogConfig conf);

  bool open() override { return true; }
  bool close() override { return true; }

  void write(std::string &log_record [[maybe_unused]]) override {}

  bool check_opened() override { return true; }

 private:
  LogWriterSyslogConfig config;
};

std::unique_ptr<FileWriterStrategy> get_log_writer_strategy(
  AuditLogStrategyType strategy_type);

}  // namespace audit_log_v2

#endif  // LOG_WRITER_V2_H_INCLUDED
