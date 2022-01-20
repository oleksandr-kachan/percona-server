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

#ifndef AUDIT_RULE_REGISTRY_V2_H_INCLUDED
#define AUDIT_RULE_REGISTRY_V2_H_INCLUDED

#include "mysql/plugin.h"

#include <string>
#include <map>


namespace audit_log_v2 {

class AuditServices;
class AuditRule;

/*
 * Audit tables structure
 * 
 *   CREATE TABLE IF NOT EXISTS mysql.audit_log_user(
 *       username VARCHAR(32) COLLATE utf8_bin NOT NULL,
 *       userhost VARCHAR(255) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
 *       filtername VARCHAR(255) COLLATE utf8_bin NOT NULL,
 *       PRIMARY KEY (user, host),
 *   FOREIGN KEY (filtername) REFERENCES mysql.audit_log_filter(name)
 *   ) Engine=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_ci;
 *   
 *   CREATE TABLE IF NOT EXISTS mysql.audit_log_filter(
 *       name VARCHAR(255) COLLATE utf8_bin NOT NULL,
 *       filter JSON NOT NULL,
 *   PRIMAR KEY (name)
 *   ) Engine=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_ci;
 */


class AuditRuleRegistry {
  using AuditUsersContainer = std::map<std::pair<std::string, std::string>, std::string>;
  using AuditRulesContainer = std::map<std::string, AuditRule>;

public:
  AuditRuleRegistry() = delete;
  explicit AuditRuleRegistry(std::unique_ptr<AuditServices> audit_services);
  
  /**
   * Load filtering rules from DB
   * 
   * @return true in case filtering rules are loaded successfully,
   *         false otherwise
   */
  bool load();

  /**
   * Get filtering rule by name
   * 
   * @param rule_name Rule name
   * @return Filtering rule
   */
  AuditRule *get_rule(const std::string &filter_name);

  /**
   * Lookup filtering rule by user name and user host
   * 
   * @param user_name User name
   * @param host_name User host name
   * @param rule_name Filtering rule name
   * @return true in case filtering rule assigned to a user was found,
   *         false otherwise
   */
  bool lookup_rule_name(const std::string &user_name, 
                        const std::string &host_name, 
                        std::string &rule_name);

private:
  std::unique_ptr<AuditServices> m_audit_services;

  AuditUsersContainer m_audit_users;
  AuditRulesContainer m_audit_filter_rules;
};

}  // namespace audit_log_v2

#endif  // AUDIT_RULE_REGISTRY_V2_H_INCLUDED
