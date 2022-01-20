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

#include "mysql/plugin.h"
#include "typelib.h"

#include "plugin/audit_log_v2/audit_error_log.h"

#include "plugin/audit_log_v2/audit_log.h"
#include "plugin/audit_log_v2/audit_record.h"
#include "plugin/audit_log_v2/audit_rule.h"
#include "plugin/audit_log_v2/audit_rule_registry.h"
#include "plugin/audit_log_v2/audit_services.h"
#include "plugin/audit_log_v2/audit_filter.h"
#include "plugin/audit_log_v2/audit_rule_registry.h"
#include "plugin/audit_log_v2/log_record_formatter.h"
#include "plugin/audit_log_v2/log_writer.h"

#include <syslog.h>

#include <memory>

#include <variant>

#define PLUGIN_VERSION 0x0100

namespace audit_log_v2 {
namespace {
AuditLogger *audit_logger = nullptr;

// System vars
char *audit_log_file;
const char default_audit_log_file[] = "audit_v2.log";
ulong audit_log_handler = AuditLogHandlerType::HandlerFile;
ulonglong audit_log_rotate_on_size = 0;
ulonglong audit_log_rotations = 0;
ulong audit_log_strategy = AuditLogStrategyType::Asynchronous;
ulonglong audit_log_buffer_size = 1048576;

// Syslog related vars
char *audit_log_syslog_ident;
const char default_audit_log_syslog_ident[] = "percona-audit-v2";
ulong audit_log_syslog_facility = 0;
ulong audit_log_syslog_priority = 0;

const int audit_log_syslog_facility_codes[] = {
  LOG_USER,     LOG_AUTHPRIV, LOG_CRON,   LOG_DAEMON, LOG_FTP,    LOG_KERN,
  LOG_LPR,      LOG_MAIL,     LOG_NEWS,
#if (defined LOG_SECURITY)
  LOG_SECURITY,
#endif
  LOG_SYSLOG,   LOG_AUTH,     LOG_UUCP,   LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2,
  LOG_LOCAL3,   LOG_LOCAL4,   LOG_LOCAL5, LOG_LOCAL6, LOG_LOCAL7, 0};

const char *audit_log_syslog_facility_names[] = {
  "LOG_USER",     "LOG_AUTHPRIV", "LOG_CRON",   "LOG_DAEMON",
  "LOG_FTP",      "LOG_KERN",     "LOG_LPR",    "LOG_MAIL",
  "LOG_NEWS",
#if (defined LOG_SECURITY)
  "LOG_SECURITY",
#endif
  "LOG_SYSLOG",   "LOG_AUTH",     "LOG_UUCP",   "LOG_LOCAL0",
  "LOG_LOCAL1",   "LOG_LOCAL2",   "LOG_LOCAL3", "LOG_LOCAL4",
  "LOG_LOCAL5",   "LOG_LOCAL6",   "LOG_LOCAL7", 0};

const int audit_log_syslog_priority_codes[] = {
  LOG_INFO,   LOG_ALERT, LOG_CRIT,  LOG_ERR, LOG_WARNING,
  LOG_NOTICE, LOG_EMERG, LOG_DEBUG, 0};

void my_plugin_perror() noexcept {
  char errbuf[MYSYS_STRERROR_SIZE];
  my_strerror(errbuf, sizeof(errbuf), errno);
  LogPluginErrMsg(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "Error: %s", errbuf);
}

/**
 * Get log writer instance configured according to plugin configuration
 * 
 * @return pointer to audit log writer instance
 */
std::unique_ptr<LogWriter> get_log_writer() noexcept {
  std::unique_ptr<LogWriter> writer;

  if (audit_log_handler == AuditLogHandlerType::HandlerFile) {
    LogWriterFileConfig conf{
        audit_log_file,
        audit_log_rotate_on_size,
        audit_log_rotations,
        audit_log_buffer_size,
        static_cast<AuditLogStrategyType>(audit_log_strategy),
    };

    writer = std::make_unique<LogWriterFile>(conf);
    if (!writer->open()) {
      LogPluginErrMsg(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                      "Cannot open file %s", audit_log_file);
      my_plugin_perror();
      return nullptr;
    }
  } else {
    LogWriterSyslogConfig conf{
        audit_log_syslog_ident,
        audit_log_syslog_facility_codes[audit_log_syslog_facility],
        audit_log_syslog_priority_codes[audit_log_syslog_priority],
    };

    writer = std::make_unique<LogWriterSyslog>(conf);
    if (!writer->open()) {
      LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG, "Cannot open syslog");
      my_plugin_perror();
      return nullptr;
    }
  }

  return writer;
}

/**
 * Get user and host name from connection THD instance
 * 
 * @param thd Server thread instance 
 * @param user_name Returned user name
 * @param user_host Returned host name
 * @return true in case usASYNCHRONOUSer and host name are fetched successfuly,
 *         false otherwise
 */
bool get_connection_user(MYSQL_THD thd, std::string &user_name, std::string &user_host) {
  LEX_STRING user, host;
  MYSQL_SECURITY_CONTEXT ctx;

  if (thd_get_security_context(thd, &ctx)) {
    my_message(ER_AUDIT_API_ABORT, "Error: can not get security context",
               MYF(0));
    return false;
  }

  if (security_context_get_option(ctx, "priv_user", &user)) {
    my_message(ER_AUDIT_API_ABORT,
               "Error: can not get priv_user from security context",
               MYF(0));
    return false;
  }

  if (security_context_get_option(ctx, "priv_host", &host)) {
    my_message(ER_AUDIT_API_ABORT,
               "Error: can not get priv_host from security context",
               MYF(0));
    return false;
  }

  user_name = user.str;
  user_host = host.str;

  return true;
}

}  // namespace

/*
 * Plugin system vars
 */

/*
 * The audit_log_file variable is used to specify the filename that’s going to
 * store the audit log. It can contain the path relative to the datadir or
 * absolute path.
 */
static MYSQL_SYSVAR_STR(file, audit_log_file,
                        PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY |
                            PLUGIN_VAR_MEMALLOC,
                        "The name of the log file.", nullptr, nullptr,
                        default_audit_log_file);

/*
 * The audit_log_handler variable is used to configure where the audit log
 * will be written. If it is set to FILE, the log will be written into a file
 * specified by audit_log_file variable. If it is set to SYSLOG, the audit
 * log will be written to syslog.
 */
static const char *audit_log_handler_names[] = {"FILE", "SYSLOG", nullptr};
static TYPELIB audit_log_handler_typelib = {
  array_elements(audit_log_handler_names) - 1, "audit_log_handler_typelib",
  audit_log_handler_names, nullptr};

static MYSQL_SYSVAR_ENUM(handler, audit_log_handler,
                         PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
                         "The audit log handler.", nullptr, nullptr,
                         HandlerFile, &audit_log_handler_typelib);

/*
 * The audit_log_rotate_on_size variable specifies the maximum size of the
 * audit log file. Upon reaching this size, the audit log will be rotated.
 * For this variable to take effect, set the audit_log_handler variable
 * to FILE and the audit_log_rotations variable to a value greater than zero.
 */
void audit_log_rotate_on_size_update(MYSQL_THD thd [[maybe_unused]],
                                     SYS_VAR *var [[maybe_unused]],
                                     void *var_ptr [[maybe_unused]],
                                     const void *save) noexcept {
  ulonglong new_val = *(const ulonglong *)(save);

  /*
   * update log writer
   */
  //  audit_handler_set_option(log_handler,
  //  audit_handler_option_t::ROTATE_ON_SIZE,
  //                           &new_val);

  audit_log_rotate_on_size = new_val;
}

/*
 * The audit_log_rotate_on_size variable specifies the maximum size of the
 * audit log file. Upon reaching this size, the audit log will be rotated.
 * For this variable to take effect, set the audit_log_handler variable to
 * FILE and the audit_log_rotations variable to a value greater than zero.
 */
static MYSQL_SYSVAR_ULONGLONG(
  rotate_on_size, audit_log_rotate_on_size, PLUGIN_VAR_RQCMDARG,
  "Maximum size of the log to start the rotation, if FILE handler is used.",
  nullptr, audit_log_rotate_on_size_update, 0UL, 0UL, ULLONG_MAX, 4096UL);

void audit_log_rotations_update(MYSQL_THD thd [[maybe_unused]],
                                SYS_VAR *var [[maybe_unused]],
                                void *var_ptr [[maybe_unused]],
                                const void *save) noexcept {
  ulonglong new_val = *(const ulonglong *)(save);

  /*
   * update log writer
   */
  //  audit_handler_set_option(log_handler, audit_handler_option_t::ROTATIONS,
  //                           &new_val);

  audit_log_rotations = new_val;
}

/*
 * The audit_log_rotations variable is used to specify how many log files
 * should be kept when audit_log_rotate_on_size variable is set to non-zero
 * value. This variable has effect only when audit_log_handler is set to FILE.
 */
static MYSQL_SYSVAR_ULONGLONG(
  rotations, audit_log_rotations, PLUGIN_VAR_RQCMDARG,
  "Maximum number of rotations to keep, if FILE handler is used.", nullptr,
  audit_log_rotations_update, 0UL, 0UL, 999UL, 1UL);

/*
 * The audit_log_strategy variable is used to specify the audit log strategy.
 * Possible values are: ASYNCHRONOUS, PERFORMANCE, SEMISYNCHRONOUS, SYNCHRONOUS.
 * This variable has effect only when audit_log_handler is set to FILE.
 */
const char *audit_log_strategy_names[] = {
  "ASYNCHRONOUS", "PERFORMANCE", "SEMISYNCHRONOUS", "SYNCHRONOUS", nullptr};
static TYPELIB audit_log_strategy_typelib = {
  array_elements(audit_log_strategy_names) - 1, "audit_log_strategy_typelib",
  audit_log_strategy_names, nullptr};

static MYSQL_SYSVAR_ENUM(strategy, audit_log_strategy,
                         PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
                         "The logging method used by the audit log plugin, "
                         "if FILE handler is used.",
                         nullptr, nullptr, AuditLogStrategyType::Asynchronous,
                         &audit_log_strategy_typelib);

/*
 * The audit_log_buffer_size variable can be used to specify the size of memory
 * buffer used for logging, used when audit_log_strategy variable is set to
 * ASYNCHRONOUS or PERFORMANCE values. This variable has effect only when
 * audit_log_handler is set to FILE.
 */
static MYSQL_SYSVAR_ULONGLONG(
  buffer_size, audit_log_buffer_size,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "The size of the buffer for asynchronous logging, "
  "if FILE handler is used.",
  nullptr, nullptr, 1048576UL, 4096UL, ULLONG_MAX, 4096UL);

/*
 * The audit_log_syslog_ident variable is used to specify the ident value
 * for syslog.
 */
static MYSQL_SYSVAR_STR(
  syslog_ident, audit_log_syslog_ident,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_MEMALLOC,
  "The string that will be prepended to each log message, "
  "if SYSLOG handler is used.",
  nullptr, nullptr, default_audit_log_syslog_ident);

/*
 * The audit_log_syslog_facility variable is used to specify the facility
 * value for syslog.
 */
static TYPELIB audit_log_syslog_facility_typelib = {
  array_elements(audit_log_syslog_facility_names) - 1,
  "audit_log_syslog_facility_typelib", audit_log_syslog_facility_names,
  nullptr};

static MYSQL_SYSVAR_ENUM(
  syslog_facility, audit_log_syslog_facility, PLUGIN_VAR_RQCMDARG,
  "The syslog facility to assign to messages, if SYSLOG handler is used.",
  nullptr, nullptr, 0, &audit_log_syslog_facility_typelib);


SYS_VAR *audit_log_system_variables[] = {
  MYSQL_SYSVAR(file),
  //  MYSQL_SYSVAR(policy),
  MYSQL_SYSVAR(strategy),
  //  MYSQL_SYSVAR(format),
  MYSQL_SYSVAR(buffer_size), MYSQL_SYSVAR(rotate_on_size),
  MYSQL_SYSVAR(rotations),
  //  MYSQL_SYSVAR(flush),
  MYSQL_SYSVAR(handler), MYSQL_SYSVAR(syslog_ident),
  //  MYSQL_SYSVAR(syslog_priority),
  MYSQL_SYSVAR(syslog_facility),
  //  MYSQL_SYSVAR(record_buffer),
  //  MYSQL_SYSVAR(query_stack),
  //  MYSQL_SYSVAR(exclude_accounts),
  //  MYSQL_SYSVAR(include_accounts),
  //  MYSQL_SYSVAR(exclude_databases),
  //  MYSQL_SYSVAR(include_databases),
  //  MYSQL_SYSVAR(exclude_commands),
  //  MYSQL_SYSVAR(include_commands),
  //  MYSQL_SYSVAR(local),
  //  MYSQL_SYSVAR(local_ptr),

  nullptr};

SHOW_VAR audit_log_status_variables[] = {

};

/**
 * Initialize the plugin at server start or plugin installation.
 * 
 * @param plugin_info Pointer to plugin info structure
 * @return Initialization status, 0 in case of success or non zero
 *         code otherwise
 */
int audit_log_plugin_init(MYSQL_PLUGIN plugin_info [[maybe_unused]]) {
  auto audit_services = std::make_unique<AuditServices>();
  if (!audit_services->init_services()) {
    return 1;
  }

  LogPluginErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
               "Initializing Audit Log v2...");

  auto audit_rule_registry = std::make_unique<AuditRuleRegistry>(std::move(audit_services));

  if (!audit_rule_registry->load()) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to load filtering rules");
    return 1;
  }

  auto log_writer = get_log_writer();

  if (log_writer == nullptr) {
    return 1;
  }

  auto formatter = get_log_record_formatter(AuditLogFormatType::New);

  if (formatter == nullptr) {
    LogPluginErr(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                 "Failed to init record formatter");
    return 1;
  }

  formatter->init_record_id(log_writer->get_log_size());
  
  audit_logger = new AuditLogger(std::move(audit_rule_registry),
                                 std::move(formatter),
                                 std::move(log_writer));

  return 0;
}

/**
 * Terminate the plugin at server shutdown or plugin deinstallation.
 * 
 * @param arg 
 * @return Plugin deinit status, 0 in case of success or non zero
 *         code otherwise
 */
int audit_log_plugin_deinit(void *arg [[maybe_unused]]) {
  LogPluginErr(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
               "Uninstalled Audit Log v2");

  delete audit_logger;
  audit_logger = nullptr;
  
  return 0;
}

/**
 * Process audit event.
 * 
 * @param thd Connection specific THD instance
 * @param event_class Event class
 * @param event Event info
 * @return Event processing status, 0 in case of success or non-zero code
 *         otherwise
 */
int audit_log_notify(MYSQL_THD thd, mysql_event_class_t event_class,
                     const void *event) {
  return audit_logger->notify_event(thd, event_class, event);
}

AuditLogger::AuditLogger(
  std::unique_ptr<AuditRuleRegistry> audit_rules_registry,
  std::unique_ptr<LogRecordFormatterBase> log_formatter,
  std::unique_ptr<LogWriter> log_writer)
  : m_audit_rules_registry{std::move(audit_rules_registry)},
    m_log_formatter{std::move(log_formatter)},
    m_log_writer{std::move(log_writer)},
    m_filter{std::unique_ptr<AuditEventFilter>(new AuditEventFilter())} {}

int AuditLogger::notify_event(MYSQL_THD thd,
                              mysql_event_class_t event_class,
                              const void *event) {
  LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                  "Audit event %i received ===================", event_class);

  std::string user_name;
  std::string user_host;

  if (!get_connection_user(thd, user_name, user_host)) {
    return 0;
  }

  LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                  "Connection user: %s, host: %s",
                  user_name.c_str(), user_host.c_str());

  // Get connection specific filtering rule
  std::string rule_name;

  if (!m_audit_rules_registry->lookup_rule_name(user_name, user_host, rule_name)) {
    LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "No filtering rule found for user %s@%s, do nothing",
                    user_name.c_str(), user_host.c_str());
    return 0;
  }

  LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                "Found '%s' filtering rule for user %s@%s",
                  rule_name.c_str(), user_name.c_str(), user_host.c_str());

  auto *filter_rule = m_audit_rules_registry->get_rule(rule_name);

  if (filter_rule == nullptr) {
    LogPluginErrMsg(ERROR_LEVEL, ER_LOG_PRINTF_MSG,
                    "Failed to find '%s' filtering rule",
                    rule_name.c_str());
    return 0;
  }

  LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                "Found filtering rule '%s' with the definition '%s'",
                rule_name.c_str(), filter_rule->to_string().c_str());

  // Get actual event type based on event_class
  AuditRecordVariant audit_record = get_audit_record(event_class, event);

  std::string ev_name = std::visit(
      [](const auto& rec) -> std::string { return rec.name; },
      audit_record);
  
  LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                  "Constructed audit record with name '%s'",
                  ev_name.c_str());

  // Apply filtering rule
  AuditFilterResult filter_result = std::visit(
      [this, filter_rule](const auto& rec) -> AuditFilterResult {
        return m_filter->apply(filter_rule, rec);
      },
      audit_record);

  // Event should not be logged
  if (filter_result == AuditFilterResult::Skip) {
    LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "Audit event '%s' with class %i should not be logged",
                    ev_name.c_str(), event_class);
    return 0;
  }

  // Event should be blocked by the server
  if (filter_result == AuditFilterResult::Block) {
    LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                    "Audit event '%s' with class %i should be blocked",
                    ev_name.c_str(), event_class);
    return 0;
  }

  LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                "Writing audit event '%s' with class %i to audit log",
                  ev_name.c_str(), event_class);
  
  // Format event data according to audit_log_v2_format settings
  std::string log_record = std::visit(
      [this](const auto& rec) -> std::string {
        return m_log_formatter->apply(rec);
      },
      audit_record);

  LogPluginErrMsg(INFORMATION_LEVEL, ER_LOG_PRINTF_MSG,
                  "Formatted log record for event '%s': %s",
                  ev_name.c_str(), log_record.c_str());

  // Actual write to log
  m_log_writer->write(log_record);

  return 0;
}

}  // namespace audit_log_v2

static void MY_ATTRIBUTE((constructor)) audit_log_v2_so_init() noexcept {

}

/*
  Plugin type-specific descriptor
*/
static st_mysql_audit audit_log_descriptor = {
  MYSQL_AUDIT_INTERFACE_VERSION,  /* interface version    */
  nullptr,                        /* release_thd function */
  audit_log_v2::audit_log_notify, /* notify function      */
  {                               /* class mask           */
   (unsigned long)MYSQL_AUDIT_GENERAL_ALL,
   (unsigned long)MYSQL_AUDIT_CONNECTION_ALL,
   (unsigned long)MYSQL_AUDIT_PARSE_ALL,
   0,
   (unsigned long)MYSQL_AUDIT_TABLE_ACCESS_ALL,
   (unsigned long)MYSQL_AUDIT_GLOBAL_VARIABLE_ALL,
   (unsigned long)MYSQL_AUDIT_SERVER_STARTUP_ALL,
   (unsigned long)MYSQL_AUDIT_SERVER_SHUTDOWN_ALL,
   (unsigned long)MYSQL_AUDIT_COMMAND_ALL,
   (unsigned long)MYSQL_AUDIT_QUERY_ALL,
   (unsigned long)MYSQL_AUDIT_STORED_PROGRAM_ALL,
   (unsigned long)MYSQL_AUDIT_AUTHENTICATION_ALL,
   (unsigned long)MYSQL_AUDIT_MESSAGE_ALL}};

/*
  Plugin library descriptor
*/
mysql_declare_plugin(audit_log){
  MYSQL_AUDIT_PLUGIN,                   /* type                     */
  &audit_log_descriptor,                /* descriptor               */
  "audit_log_v2",                       /* name                     */
  "Percona LLC and/or its affiliates.", /* author                   */
  "Audit log",                          /* description              */
  PLUGIN_LICENSE_GPL,
  audit_log_v2::audit_log_plugin_init, /* init function            */
  nullptr,
  audit_log_v2::audit_log_plugin_deinit,    /* deinit function          */
  PLUGIN_VERSION,                           /* version                  */
  audit_log_v2::audit_log_status_variables, /* status variables         */
  audit_log_v2::audit_log_system_variables, /* system variables         */
  nullptr,
  0,
} mysql_declare_plugin_end;
