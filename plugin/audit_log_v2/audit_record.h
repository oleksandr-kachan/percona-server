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

#ifndef AUDIT_RECORD_V2_H_INCLUDED
#define AUDIT_RECORD_V2_H_INCLUDED

#include "mysql/plugin_audit.h"

#include <map>
#include <memory>
#include <string>
#include <variant>

namespace audit_log_v2 {

//  std::string name;  // A string representing the type of instruction that
                     // generated the audit event. Corresponds to event class.
//  std::string record_id;  // A unique identifier for the audit record,
//                          // composed from a sequence number and timestamp.
//                          // For example, 12_2019-10-03T14:06:33
//  std::string timestamp;  // A string representing a UTC value in
//                          // YYYY-MM-DDThh:mm:ss UTC format indicating the date
//                          // and time when the audit event was generated.

struct AuditRecordGeneral {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_general *event;
};

struct AuditRecordConnection {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_connection *event;
};

struct AuditRecordParse {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_parse *event;
};

/*
 * The mysql_event_authorization not supported by plugin
 */

struct AuditRecordTableAccess {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_table_access *event;
};

struct AuditRecordGlobalVariable {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_global_variable *event;
};

struct AuditRecordServerStartup {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_server_startup *event;
};

struct AuditRecordServerShutdown {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_server_shutdown *event;
};

struct AuditRecordCommand {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_command *event;
};

struct AuditRecordQuery {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_query *event;
};

struct AuditRecordStoredProgram {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_stored_program *event;
};

struct AuditRecordAuthentication {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_authentication *event;
};

struct AuditRecordMessage {
  std::string name;
  mysql_event_class_t event_class;
  const mysql_event_message *event;
};

using AuditRecordVariant = std::variant<AuditRecordGeneral,
                                        AuditRecordConnection,
                                        AuditRecordParse,
                                        AuditRecordTableAccess,
                                        AuditRecordGlobalVariable,
                                        AuditRecordServerStartup,
                                        AuditRecordServerShutdown,
                                        AuditRecordCommand,
                                        AuditRecordQuery,
                                        AuditRecordStoredProgram,
                                        AuditRecordAuthentication,
                                        AuditRecordMessage>;

AuditRecordVariant get_audit_record(mysql_event_class_t event_class,
                                    const void *event);

}  // namespace audit_log_v2

#endif  // AUDIT_RECORD_V2_H_INCLUDED
