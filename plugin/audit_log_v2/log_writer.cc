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

#include "plugin/audit_log_v2/log_writer.h"

#include "plugin/audit_log_v2/audit_error_log.h"

#include "sql/mysqld.h"

namespace audit_log_v2 {
namespace {
#if defined(HAVE_PSI_INTERFACE) && !defined(FLOGGER_NO_PSI)
/* These belong to the service initialization */
//  PSI_mutex_key key_LOCK_logger_service;
//  PSI_mutex_info mutex_list[] = {{
//    &key_LOCK_logger_service,
//    "file_logger::lock",
//    PSI_FLAG_SINGLETON,
//    PSI_VOLATILITY_UNKNOWN,
//    PSI_DOCUMENT_ME}};
#else
//#define key_LOCK_logger_service nullptr
#endif /*HAVE_PSI_INTERFACE && !FLOGGER_NO_PSI*/

}  // namespace

LogWriterFile::LogWriterFile(LogWriterFileConfig conf)
  : m_config{conf}, m_is_opened{false} {}

LogWriterFile::~LogWriterFile() { do_close_file(); }

bool LogWriterFile::open() { return do_open_file(); }

bool LogWriterFile::close() { return do_close_file(); }

bool LogWriterFile::do_open_file() noexcept {
  m_file_handle.path_len = strlen(fn_format(
      m_file_handle.path, m_config.name, mysql_data_home, "", MY_UNPACK_FILENAME));

  //  if (m_file_handle.path_len + n_dig(rotations) + 1 > FN_REFLEN) {
  //    errno = ENAMETOOLONG;
  //    /* File path too long */
  //    return 0;
  //  }

  if ((m_file_handle.file = my_open(
           m_file_handle.path, (O_APPEND | O_CREAT | O_WRONLY), 0666)) < 0) {
    LogPluginErrMsg(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                    "log_writer: Cannot open file %s", m_file_handle.path);
    errno = my_errno();
    /* Check errno for the cause */
    return false;
  }

  MY_STAT stat_arg;
  if (my_fstat(m_file_handle.file, &stat_arg)) {
    LogPluginErrMsg(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                    "log_writer: Cannot stat file %s", m_file_handle.path);
    errno = my_errno();
    my_close(m_file_handle.file, MYF(0));
    m_file_handle.file = -1;
    return false;
  }

  // in case logger is thread safe
  // mysql_mutex_init(key_LOCK_logger_service, &m_file_handle.lock,
  // MY_MUTEX_INIT_FAST);

  /*
   * Write log header upon file opening
   */
  // char buf[128];
  // size_t len;
  // len = header(&stat_arg, buf, sizeof(buf));
  // my_write(m_file_handle.file, (uchar *)buf, len, MYF(0));

  m_is_opened = true;

  return true;
}

bool LogWriterFile::do_close_file() noexcept {
  /*
   * Print footer
   */
  // char buf[128];
  // const size_t len = footer(buf, sizeof(buf));
  // my_write(m_file_handler.file, (uchar *)buf, len, MYF(0));

  // in case logger is thread safe
  // flogger_mutex_destroy(log);

  int result = my_close(m_file_handle.file, MYF(0));

  if (result != 0) {
    errno = my_errno();
    return false;
  }

  m_file_handle.file = -1;
  m_file_handle.path[0] = '\0';
  m_file_handle.path_len = 0;

  // in case logger is thread safe
  // flogger_mutex_destroy(log);

  return true;
}

LogWriterSyslog::LogWriterSyslog(LogWriterSyslogConfig conf) : config{conf} {}

std::unique_ptr<FileWriterStrategy> get_log_writer_strategy(
    AuditLogStrategyType strategy_type) {
  switch (strategy_type) {
    case AuditLogStrategyType::Asynchronous:
      return std::unique_ptr<FileWriterStrategyAsync>(
          new FileWriterStrategyAsync{});
    case AuditLogStrategyType::Performance:
      return std::unique_ptr<FileWriterStrategyPerformace>(
          new FileWriterStrategyPerformace{});
    case AuditLogStrategyType::Semisynchronous:
      return std::unique_ptr<FileWriterStrategySemisync>(
          new FileWriterStrategySemisync{});
    case AuditLogStrategyType::Synchronous:
      return std::unique_ptr<FileWriterStrategySync>(
          new FileWriterStrategySync{});
    default:
      assert(false);
  }
}

}  // namespace audit_log_v2
