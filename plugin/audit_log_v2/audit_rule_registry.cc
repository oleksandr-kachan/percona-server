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

#include "plugin/audit_log_v2/audit_error_log.h"
#include "plugin/audit_log_v2/audit_rule_registry.h"
#include "plugin/audit_log_v2/audit_rule.h"
#include "plugin/audit_log_v2/audit_services.h"

#include <mysql/components/services/table_access_service.h>

#include <functional>
#include <type_traits>
#include <tuple>

namespace audit_log_v2 {
namespace {
const char *AUDIT_DB_NAME = "mysql";
const char *AUDIT_USER_TABLE_NAME = "audit_log_user";
const char *AUDIT_FILTER_TABLE_NAME = "audit_log_filter";


/*
 * The audit_log_user table columns description
 */
const size_t AUDIT_LOG_USER_USERNAME = 0;
const size_t AUDIT_LOG_USER_USERHOST = 1;
const size_t AUDIT_LOG_USER_FILTERNAME = 2;
const TA_table_field_def columns_audit_log_user[] = {
    {AUDIT_LOG_USER_USERNAME, "USERNAME", 8, TA_TYPE_VARCHAR, false, 32},
    {AUDIT_LOG_USER_USERHOST, "USERHOST", 8, TA_TYPE_VARCHAR, false, 255},
    {AUDIT_LOG_USER_FILTERNAME, "FILTERNAME", 10, TA_TYPE_VARCHAR, false, 255}
};

/*
 * The audit_log_filter table columns description
 */
const size_t AUDIT_LOG_FILTER_NAME = 0;
const size_t AUDIT_LOG_FILTER_FILTER = 1;
const TA_table_field_def columns_audit_log_filter[] = {
    {AUDIT_LOG_FILTER_NAME, "NAME", 4, TA_TYPE_VARCHAR, false, 255},
    {AUDIT_LOG_FILTER_FILTER, "FILTER", 6, TA_TYPE_JSON, false, 0}
};

class HStringContainer {
public:
//  ~HStringContainer() {
//
//  }
  my_h_string get() {return m_string; }
  my_h_string *get_addr() {return &m_string; }

private:
  my_h_string m_string = nullptr;
};

}  // namespace

AuditRuleRegistry::AuditRuleRegistry(std::unique_ptr<AuditServices> audit_services) 
    : m_audit_services{std::move(audit_services)} {}

AuditRule *AuditRuleRegistry::get_rule(const std::string &rule_name) {
  if (m_audit_filter_rules.count(rule_name) == 0) {
    return nullptr;
  }

  auto it = m_audit_filter_rules.find(rule_name);
  return &it->second;
}

bool AuditRuleRegistry::lookup_rule_name(const std::string &user_name, 
                                         const std::string &host_name, 
                                         std::string &rule_name) {
  if (m_audit_users.count(std::make_pair(user_name, host_name)) == 0) {
    return false;
  }
  
  rule_name = m_audit_users[std::make_pair(user_name, host_name)];
  
  return true;
}

bool AuditRuleRegistry::load() {
  m_audit_users.clear();
  m_audit_filter_rules.clear();

  MYSQL_THD thd;
  my_h_string order_comment_value = nullptr;

  m_audit_services->get_current_thd_srv()->get(&thd);
  m_audit_services->get_string_factory_srv()->create(&order_comment_value);

  auto Table_access_deleter = [this](Table_access ta) {
    m_audit_services->get_ta_factory_srv()->destroy(ta);
  };
  using Table_access_ptr_t = std::unique_ptr<std::remove_pointer<Table_access>::type, decltype(Table_access_deleter)>;

  Table_access_ptr_t access(m_audit_services->get_ta_factory_srv()->create(thd, 2), Table_access_deleter);
  if (access == nullptr) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to init table access service");
    return false;
  }

  size_t ticket_audit_log_user = m_audit_services->get_ta_srv()->add(
      access.get(), AUDIT_DB_NAME, strlen(AUDIT_DB_NAME),
      AUDIT_USER_TABLE_NAME, strlen(AUDIT_USER_TABLE_NAME), TA_READ);
  size_t ticket_audit_log_filter = m_audit_services->get_ta_srv()->add(
      access.get(), AUDIT_DB_NAME, strlen(AUDIT_DB_NAME),
      AUDIT_FILTER_TABLE_NAME, strlen(AUDIT_FILTER_TABLE_NAME), TA_READ);

  if (m_audit_services->get_ta_srv()->begin(access.get()) != 0) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to start table access transaction");
    return false;
  }

  TA_table table_audit_log_user 
      = m_audit_services->get_ta_srv()->get(access.get(), ticket_audit_log_user);
  if (table_audit_log_user == nullptr) {
    // TODO: No tables yet, try creating them 

    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to get an opened audit_log_user table");
    return false;
  }

  if (m_audit_services->get_ta_srv()->check(
          access.get(), table_audit_log_user, columns_audit_log_user, 3) != 0) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to check audit_log_user table fields");
    return false;
  }

  TA_table table_audit_log_filter
      = m_audit_services->get_ta_srv()->get(access.get(), ticket_audit_log_filter);
  if (table_audit_log_filter == nullptr) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to get an opened audit_log_filter table");
    return false;
  }

  if (m_audit_services->get_ta_srv()->check(
          access.get(), table_audit_log_filter, columns_audit_log_filter, 2) != 0) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to check audit_log_filter table fields");
    return false;
  }

  // Read audit_log_user data
  if (m_audit_services->get_ta_scan_srv()->init(access.get(), table_audit_log_user)) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to init full scan of audit_log_user table");
    return false;
  }

  CHARSET_INFO_h utf8 = m_audit_services->get_charset_srv()->get_utf8mb4();

//  auto my_h_string_deleter = [this](my_h_string s) {
//    m_audit_services->get_string_factory_srv()->destroy(s);
//  };
//  using my_h_string_ptr_t = std::unique_ptr<std::remove_pointer<my_h_string>, decltype(my_h_string_deleter)>;
  
  char buff_user_name_value[32 + 1];
  char buff_user_host_value[255 + 1];
  char buff_user_filter_name_value[255 + 1];
  HStringContainer user_name_value;
  HStringContainer user_host_value;
  HStringContainer user_filter_name_value;
  m_audit_services->get_string_factory_srv()->create(user_name_value.get_addr());
  m_audit_services->get_string_factory_srv()->create(user_host_value.get_addr());
  m_audit_services->get_string_factory_srv()->create(user_filter_name_value.get_addr());

  while(true) {
    if (m_audit_services->get_ta_scan_srv()->next(access.get(), table_audit_log_user)) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "Nothing more to read from audit_log_user");
      break;
    }

    if (m_audit_services->get_fa_varchar_srv()->get(
            access.get(), table_audit_log_user,
            AUDIT_LOG_USER_USERNAME, user_name_value.get())) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "Failed to read audit_log_user.username");
      return false;
    }
    if (m_audit_services->get_fa_varchar_srv()->get(
            access.get(), table_audit_log_user,
            AUDIT_LOG_USER_USERHOST, user_host_value.get())) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "Failed to read audit_log_user.userhost");
      return false;
    }
    if (m_audit_services->get_fa_varchar_srv()->get(
            access.get(), table_audit_log_user,
            AUDIT_LOG_USER_FILTERNAME, user_filter_name_value.get())) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "Failed to read audit_log_user.filtername");
      return false;
    }

    m_audit_services->get_string_converter_srv()->convert_to_buffer(
        user_name_value.get(), buff_user_name_value,
        sizeof(buff_user_name_value), utf8);
    m_audit_services->get_string_converter_srv()->convert_to_buffer(
        user_host_value.get(), buff_user_host_value,
        sizeof(buff_user_host_value), utf8);
    m_audit_services->get_string_converter_srv()->convert_to_buffer(
        user_filter_name_value.get(), buff_user_filter_name_value,
        sizeof(buff_user_filter_name_value), utf8);

    LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "audit_log_user username: %s, hostname: %s, filtername: %s",
                    buff_user_name_value, buff_user_host_value,
                    buff_user_filter_name_value);
    
    m_audit_users.insert({{buff_user_name_value, buff_user_host_value}, 
                          buff_user_filter_name_value});
  }

  if (m_audit_services->get_ta_scan_srv()->end(access.get(), table_audit_log_user)) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to end full scan of audit_log_user table");
    return false;
  }

  // Read audit_log_filter data
  if (m_audit_services->get_ta_scan_srv()->init(
          access.get(), table_audit_log_filter)) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to init full scan of audit_log_filter table");
    return false;
  }

  char buff_filter_name_value[255 + 1];
  char buff_filter_filter_value[1024 + 1];
  HStringContainer filter_name_value;
  HStringContainer filter_filter_value;
  m_audit_services->get_string_factory_srv()->create(filter_name_value.get_addr());
  m_audit_services->get_string_factory_srv()->create(filter_filter_value.get_addr());

  while (true) {
    if (m_audit_services->get_ta_scan_srv()->next(access.get(), table_audit_log_filter)) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "Nothing more to read from audit_log_filter");
      break;
    }

    if (m_audit_services->get_fa_varchar_srv()->get(
            access.get(), table_audit_log_filter,
            AUDIT_LOG_FILTER_NAME, filter_name_value.get())) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "Failed to read audit_log_filter.filter");
      return false;
    }
    if (m_audit_services->get_fa_any_srv()->get(
            access.get(), table_audit_log_filter,
            AUDIT_LOG_FILTER_FILTER, filter_filter_value.get())) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                   "Failed to read audit_log_filter.filter");
      return false;
    }

    m_audit_services->get_string_converter_srv()->convert_to_buffer(
        filter_name_value.get(), buff_filter_name_value,
        sizeof(buff_filter_name_value), utf8);
    m_audit_services->get_string_converter_srv()->convert_to_buffer(
        filter_filter_value.get(), buff_filter_filter_value,
        sizeof(buff_filter_filter_value), utf8);

    LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "audit_log_filter name: %s, filter: %s",
                    buff_filter_name_value, buff_filter_filter_value);

    m_audit_filter_rules.emplace(
        std::piecewise_construct, 
        std::forward_as_tuple(buff_filter_name_value), 
        std::forward_as_tuple(buff_filter_filter_value));
  }

  if (m_audit_services->get_ta_scan_srv()->end(access.get(), table_audit_log_filter)) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to end full scan of audit_log_filter table");
    return false;
  }

  return true;
}

  



}  // namespace audit_log_v2
