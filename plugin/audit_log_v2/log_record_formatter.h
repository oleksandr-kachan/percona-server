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

#ifndef LOG_RECORD_FORMATTER_V2_H_INCLUDED
#define LOG_RECORD_FORMATTER_V2_H_INCLUDED

#include <atomic>
#include <string>
#include <memory>
#include <map>

namespace audit_log_v2 {

struct AuditRecordGeneral;
struct AuditRecordConnection;
struct AuditRecordParse;
struct AuditRecordTableAccess;
struct AuditRecordGlobalVariable;
struct AuditRecordServerStartup;
struct AuditRecordServerShutdown;
struct AuditRecordCommand;
struct AuditRecordQuery;
struct AuditRecordStoredProgram;
struct AuditRecordAuthentication;
struct AuditRecordMessage;

enum class AuditLogFormatType {
  New,
  Old,
  Json,
  Csv,
  // This item must be last in the list
  FormatsCount
};

class LogRecordFormatterBase {
 public:
  virtual std::string apply(const AuditRecordGeneral &audit_record) = 0;
  virtual std::string apply(const AuditRecordConnection &audit_record) = 0;
  virtual std::string apply(const AuditRecordParse &audit_record) = 0;
  virtual std::string apply(const AuditRecordTableAccess &audit_record) = 0;
  virtual std::string apply(const AuditRecordGlobalVariable &audit_record) = 0;
  virtual std::string apply(const AuditRecordServerStartup &audit_record) = 0;
  virtual std::string apply(const AuditRecordServerShutdown &audit_record) = 0;
  virtual std::string apply(const AuditRecordCommand &audit_record) = 0;
  virtual std::string apply(const AuditRecordQuery &audit_record) = 0;
  virtual std::string apply(const AuditRecordStoredProgram &audit_record) = 0;
  virtual std::string apply(const AuditRecordAuthentication &audit_record) = 0;
  virtual std::string apply(const AuditRecordMessage &audit_record) = 0;

  virtual const std::map<char, std::string> &get_escape_rules() noexcept = 0;

  void init_record_id(uint64_t initial_record_id) noexcept {
    m_record_id.store(initial_record_id, std::memory_order_relaxed);
  }

protected:
  std::string make_record_id(uint64_t time) noexcept;
  static std::string make_timestamp(uint64_t time) noexcept;
  std::string make_escaped_string(const std::string &in) noexcept;

private:
  uint64_t get_next_record_id() noexcept {
    return m_record_id.fetch_add(1, std::memory_order_relaxed);
  }

private:
  // Sequence number which will be used for next received audit record.
  // Initialized to current audit log file size during plugin initialization.
  // Incremented by 1 for each logged record.
  std::atomic<uint64_t> m_record_id{0};
};

template <AuditLogFormatType FormatType> class LogRecordFormatter;

/*
 * NEW
 */
template<> class LogRecordFormatter<AuditLogFormatType::New> : public LogRecordFormatterBase {
public:
  std::string apply(const AuditRecordGeneral &audit_record) override;
  std::string apply(const AuditRecordConnection &audit_record) override;
  std::string apply(const AuditRecordParse &audit_record) override;
  std::string apply(const AuditRecordTableAccess &audit_record) override;
  std::string apply(const AuditRecordGlobalVariable &audit_record) override;
  std::string apply(const AuditRecordServerStartup &audit_record) override;
  std::string apply(const AuditRecordServerShutdown &audit_record) override;
  std::string apply(const AuditRecordCommand &audit_record) override;
  std::string apply(const AuditRecordQuery &audit_record) override;
  std::string apply(const AuditRecordStoredProgram &audit_record) override;
  std::string apply(const AuditRecordAuthentication &audit_record) override;
  std::string apply(const AuditRecordMessage &audit_record) override;

  const std::map<char, std::string> &get_escape_rules() noexcept override;

};

/*
 * OLD
 */
template<> class LogRecordFormatter<AuditLogFormatType::Old> : public LogRecordFormatterBase {
  std::string apply(const AuditRecordGeneral &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordConnection &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordParse &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordTableAccess &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordGlobalVariable &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordServerStartup &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordServerShutdown &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordCommand &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordQuery &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordStoredProgram &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordAuthentication &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordMessage &audit_record [[maybe_unused]]) override { return ""; }

  const std::map<char, std::string> &get_escape_rules() noexcept override;
};

/*
 * JSON
 */
template<> class LogRecordFormatter<AuditLogFormatType::Json> : public LogRecordFormatterBase {
  std::string apply(const AuditRecordGeneral &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordConnection &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordParse &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordTableAccess &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordGlobalVariable &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordServerStartup &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordServerShutdown &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordCommand &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordQuery &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordStoredProgram &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordAuthentication &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordMessage &audit_record [[maybe_unused]]) override { return ""; }

  const std::map<char, std::string> &get_escape_rules() noexcept override;
};

/*
 * CSV
 */
template<> class LogRecordFormatter<AuditLogFormatType::Csv> : public LogRecordFormatterBase {
  std::string apply(const AuditRecordGeneral &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordConnection &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordParse &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordTableAccess &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordGlobalVariable &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordServerStartup &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordServerShutdown &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordCommand &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordQuery &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordStoredProgram &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordAuthentication &audit_record [[maybe_unused]]) override { return ""; }
  std::string apply(const AuditRecordMessage &audit_record [[maybe_unused]]) override { return ""; }

  const std::map<char, std::string> &get_escape_rules() noexcept override;
};

using LogRecordFormatterNew = LogRecordFormatter<AuditLogFormatType::New>;
using LogRecordFormatterOld = LogRecordFormatter<AuditLogFormatType::Old>;
using LogRecordFormatterJson = LogRecordFormatter<AuditLogFormatType::Json>;
using LogRecordFormatterCsv = LogRecordFormatter<AuditLogFormatType::Csv>;

std::unique_ptr<LogRecordFormatterBase> get_log_record_formatter(
    AuditLogFormatType format_type);

}  // namespace audit_log_v2

#endif  // LOG_RECORD_FORMATTER_V2_H_INCLUDED
