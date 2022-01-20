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

#include "plugin/audit_log_v2/audit_rule.h"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"


namespace audit_log_v2 {

AuditRule::AuditRule(const char* rule_str) {
  m_json_rule_doc.Parse(rule_str);
}

std::string AuditRule::to_string() {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  m_json_rule_doc.Accept(writer);

  // Output {"project":"rapidjson","stars":11}
  return buffer.GetString();
}


}  // namespace audit_log_v2
