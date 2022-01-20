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

#include "plugin/audit_log_v2/audit_record.h"

namespace audit_log_v2 {
namespace {
  const std::string AUDIT_EVENT_NAME_GENERAL = "general";
  const std::string AUDIT_EVENT_NAME_CONNECTION = "connection";
  const std::string AUDIT_EVENT_NAME_PARSE = "parse";
  const std::string AUDIT_EVENT_NAME_TABLE_ACCESS = "table_access";
  const std::string AUDIT_EVENT_NAME_GLOBAL_VARIABLE = "global_variable";
  const std::string AUDIT_EVENT_NAME_SERVER_STARTUP = "server_startup";
  const std::string AUDIT_EVENT_NAME_SERVER_SHUTDOWN = "server_shutdown";
  const std::string AUDIT_EVENT_NAME_COMMAND = "command";
  const std::string AUDIT_EVENT_NAME_QUERY = "query";
  const std::string AUDIT_EVENT_NAME_STORED_PROGRAM = "stored_program";
  const std::string AUDIT_EVENT_NAME_AUTHENTICATION = "authentication";
  const std::string AUDIT_EVENT_NAME_MESSAGE = "message";

}  // namespace


AuditRecordVariant get_audit_record(mysql_event_class_t event_class,
                                    const void *event) {
  switch (event_class) {
    case MYSQL_AUDIT_GENERAL_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<0>, 
        AuditRecordGeneral{
          AUDIT_EVENT_NAME_GENERAL, 
          event_class, 
          static_cast<const mysql_event_general *>(event)}};
    }
    case MYSQL_AUDIT_CONNECTION_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<1>, 
        AuditRecordConnection{
          AUDIT_EVENT_NAME_CONNECTION, 
          event_class, 
          static_cast<const mysql_event_connection *>(event)}};
    }
    case MYSQL_AUDIT_PARSE_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<2>, 
        AuditRecordParse{
          AUDIT_EVENT_NAME_PARSE, 
          event_class, 
          static_cast<const mysql_event_parse *>(event)}};
    }
    case MYSQL_AUDIT_TABLE_ACCESS_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<3>, 
        AuditRecordTableAccess{AUDIT_EVENT_NAME_TABLE_ACCESS, event_class, static_cast<const mysql_event_table_access *>(event)}};
    }
    case MYSQL_AUDIT_GLOBAL_VARIABLE_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<4>, 
        AuditRecordGlobalVariable{AUDIT_EVENT_NAME_GLOBAL_VARIABLE, event_class, static_cast<const mysql_event_global_variable *>(event)}};
    }
    case MYSQL_AUDIT_SERVER_STARTUP_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<5>, 
        AuditRecordServerStartup{AUDIT_EVENT_NAME_SERVER_STARTUP, event_class, static_cast<const mysql_event_server_startup *>(event)}};
    }
    case MYSQL_AUDIT_SERVER_SHUTDOWN_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<6>, 
        AuditRecordServerShutdown{AUDIT_EVENT_NAME_SERVER_SHUTDOWN, event_class, static_cast<const mysql_event_server_shutdown *>(event)}};
    }
    case MYSQL_AUDIT_COMMAND_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<7>, 
        AuditRecordCommand{AUDIT_EVENT_NAME_COMMAND, event_class, static_cast<const mysql_event_command *>(event)}};
    }
    case MYSQL_AUDIT_QUERY_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<8>, 
        AuditRecordQuery{AUDIT_EVENT_NAME_QUERY, event_class, static_cast<const mysql_event_query *>(event)}};
    }
    case MYSQL_AUDIT_STORED_PROGRAM_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<9>, 
        AuditRecordStoredProgram{AUDIT_EVENT_NAME_STORED_PROGRAM, event_class, static_cast<const mysql_event_stored_program *>(event)}};
    }
    case MYSQL_AUDIT_AUTHENTICATION_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<10>, 
        AuditRecordAuthentication{AUDIT_EVENT_NAME_AUTHENTICATION, event_class, static_cast<const mysql_event_authentication *>(event)}};
    }
    case MYSQL_AUDIT_MESSAGE_CLASS: {
      return AuditRecordVariant{
        std::in_place_index<11>, 
        AuditRecordMessage{AUDIT_EVENT_NAME_MESSAGE, event_class, static_cast<const mysql_event_message *>(event)}};
    }

    default:
      break;
      // Log "unknown event class" error
  }

  assert(false);
}

}  // namespace audit_log_v2
