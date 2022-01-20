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

#ifndef AUDIT_LOG_V2_H_INCLUDED
#define AUDIT_LOG_V2_H_INCLUDED

#include "mysql/plugin_audit.h"

namespace audit_log_v2 {

class AuditRuleRegistry;
class LogRecordFormatterBase;
class LogWriter;
class AuditEventFilter;

class AuditLogger {
 public:
  AuditLogger() = delete;
  AuditLogger(std::unique_ptr<AuditRuleRegistry> audit_rules_registry,
              std::unique_ptr<LogRecordFormatterBase> log_formatter,
              std::unique_ptr<LogWriter> log_writer);

  int notify_event(MYSQL_THD thd, mysql_event_class_t event_class,
                   const void *event);

 private:
  std::unique_ptr<AuditRuleRegistry> m_audit_rules_registry;
  std::unique_ptr<LogRecordFormatterBase> m_log_formatter;
  std::unique_ptr<LogWriter> m_log_writer;
  std::unique_ptr<AuditEventFilter> m_filter;
};

}  // namespace audit_log_v2

#endif  // AUDIT_LOG_V2_H_INCLUDED
