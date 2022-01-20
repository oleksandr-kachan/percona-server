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

#ifndef AUDIT_FILTER_V2_H_INCLUDED
#define AUDIT_FILTER_V2_H_INCLUDED

#include "mysql/plugin_audit.h"

#include "plugin/audit_log_v2/audit_record.h"
#include "plugin/audit_log_v2/audit_rule.h"
#include "plugin/audit_log_v2/audit_rule_registry.h"

#include <map>
#include <string>

namespace audit_log_v2 {

enum class AuditFilterResult {
  Log,   // write event to audit log
  Skip,  // don't write event to audit log
  Block  // event blocked by a rule, server should reject it
};

/*
 * Implements Audit Rule application logic
 */
class AuditEventFilter {
 public:
  template <typename T>
  AuditFilterResult apply(
      const AuditRule *const rule [[maybe_unused]],
      const T &audit_record [[maybe_unused]]) {
    return AuditFilterResult::Log;
  }
};

}  // namespace audit_log_v2

#endif  // AUDIT_FILTER_V2_H_INCLUDED
