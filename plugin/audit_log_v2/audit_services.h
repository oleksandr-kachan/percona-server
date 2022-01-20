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

#ifndef AUDIT_SERVICES_V2_H_INCLUDED
#define AUDIT_SERVICES_V2_H_INCLUDED

#include "plugin/audit_log_v2/audit_error_log.h"
#include <mysql/plugin.h>
#include <mysql/components/services/table_access_service.h>


namespace audit_log_v2 {

class AuditServices {
public:
  ~AuditServices();

  /**
   * Initialize required component services
   * 
   * @return true in case services initialized successfully,
   *         false otherwise
   */
  bool init_services();

  /**
   * De-initialize component services
   */
  void deinit_services();

  SERVICE_TYPE(mysql_charset) *get_charset_srv() {
    return m_charset_srv;
  }

  SERVICE_TYPE(mysql_current_thread_reader) *get_current_thd_srv() {
    return m_current_thd_srv;
  }

  SERVICE_TYPE(mysql_string_factory) *get_string_factory_srv() {
    return m_string_factory_srv;
  }

  SERVICE_TYPE(mysql_string_charset_converter) *get_string_converter_srv() {
    return m_string_converter_srv;
  }

  SERVICE_TYPE(table_access_factory_v1) *get_ta_factory_srv() {
    return m_ta_factory_srv;
  }

  SERVICE_TYPE(table_access_v1) *get_ta_srv() {
    return m_ta_srv;
  }

  SERVICE_TYPE(table_access_scan_v1) *get_ta_scan_srv() {
    return m_ta_scan_srv;
  }

  SERVICE_TYPE(field_varchar_access_v1) *get_fa_varchar_srv() {
    return m_fa_varchar_srv;
  }

  SERVICE_TYPE(field_any_access_v1) *get_fa_any_srv() {
    return m_fa_any_srv;
  }

private:
  SERVICE_TYPE(registry) *m_reg_srv = nullptr;
  SERVICE_TYPE(mysql_charset) *m_charset_srv = nullptr;
  SERVICE_TYPE(mysql_current_thread_reader) *m_current_thd_srv = nullptr;
  SERVICE_TYPE(mysql_string_factory) *m_string_factory_srv = nullptr;
  SERVICE_TYPE(mysql_string_charset_converter) *m_string_converter_srv = nullptr;
  SERVICE_TYPE(table_access_factory_v1) *m_ta_factory_srv = nullptr;
  SERVICE_TYPE(table_access_v1) *m_ta_srv = nullptr;
  SERVICE_TYPE(table_access_scan_v1) *m_ta_scan_srv = nullptr;
  SERVICE_TYPE(field_varchar_access_v1) *m_fa_varchar_srv = nullptr;
  SERVICE_TYPE(field_any_access_v1) *m_fa_any_srv = nullptr;
};

}  // namespace audit_log_v2

#endif  // AUDIT_SERVICES_V2_H_INCLUDED
