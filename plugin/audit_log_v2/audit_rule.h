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

#ifndef AUDIT_RULE_V2_H_INCLUDED
#define AUDIT_RULE_V2_H_INCLUDED

#include "my_rapidjson_size_t.h"
#include "rapidjson/document.h"

namespace audit_log_v2 {

class AuditRule {
public:
  AuditRule() = delete;
//  AuditRule(AuditRule &&rule) noexcept { m_json_rule_doc = std::move(rule.m_json_rule_doc); }
  explicit AuditRule(const char* rule_str);
  
  std::string to_string();
  
private:
  rapidjson::Document m_json_rule_doc;
};

}  // namespace audit_log_v2

#endif  // AUDIT_RULE_V2_H_INCLUDED
