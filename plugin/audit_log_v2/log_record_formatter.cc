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

#include "plugin/audit_log_v2/log_record_formatter.h"

#include "plugin/audit_log_v2/audit_record.h"

#include <iostream>
#include <iomanip>
#include <chrono>


namespace audit_log_v2 {
namespace {

}  // namespace

std::string LogRecordFormatterBase::make_record_id(uint64_t time) noexcept {
  std::stringstream id;
  id << get_next_record_id() << "_" << make_timestamp(time);

  return id.str();
}

std::string LogRecordFormatterBase::make_timestamp(uint64_t time) noexcept {
  std::chrono::system_clock::time_point tp{std::chrono::seconds{time}};
  const std::time_t t = std::chrono::system_clock::to_time_t(tp);
  
  std::stringstream timestamp;
  timestamp << std::put_time(std::localtime(&t), "%FT%T");

  return timestamp.str();
}

std::string LogRecordFormatterBase::make_escaped_string(const std::string &in) noexcept {
  std::string out;
  const std::map<char, std::string> &escape_rules = get_escape_rules();

  for (const char &c : in) {
    const auto it = escape_rules.find(c);
    if (it == escape_rules.end()) {
      out.append(&c, 1);
    } else {
      out.append(it->second);
    }
  }

  return out;
}

const std::map<char, std::string> &LogRecordFormatterNew::get_escape_rules() noexcept {
  // Although most control sequences aren't supported in XML 1.0, we are better
  // off printing them anyway instead of the original control characters
  static const std::map<char, std::string> escape_rules = {
    {0, "?"},       {1, "&#1;"},     {2, "&#2;"},     {3, "&#3;"},
    {4, "&#4;"},    {5, "&#5;"},     {6, "&#6;"},     {7, "&#7;"},
    {8, "&#8;"},    {'\t', "&#9;"},  {'\n', "&#10;"}, {11, "&#11;"},
    {12, "&#12;"},  {'\r', "&#13;"}, {14, "&#14;"},   {15, "&#15;"},
    {16, "&#16;"},  {17, "&#17;"},   {18, "&#18;"},   {19, "&#19;"},
    {20, "&#20;"},  {21, "&#21;"},   {22, "&#22;"},   {23, "&#23;"},
    {24, "&#24;"},  {25, "&#25;"},   {26, "&#26;"},   {27, "&#27;"},
    {28, "&#28;"},  {29, "&#29;"},   {30, "&#30;"},   {31, "&#31;"},
    {'<', "&lt;"},  {'>', "&gt;"},   {'&', "&amp;"},  {'"', "&quot;"}
  };
  
  return escape_rules;
}

std::string LogRecordFormatterNew::apply(const AuditRecordGeneral &audit_record) {
  std::stringstream result;
  result << "<AUDIT_RECORD>\n"
         << "  <NAME>" << audit_record.event->general_command.str << "</NAME>\n"
         << "  <RECORD_ID>" << make_record_id(audit_record.event->general_time) << "</RECORD_ID>\n"
         << "  <TIMESTAMP>" << make_timestamp(audit_record.event->general_time) << "</TIMESTAMP>\n"
         << "  <COMMAND_CLASS>" << audit_record.event->general_sql_command.str << "</COMMAND_CLASS>\n"
         << "  <CONNECTION_ID>" << audit_record.event->general_thread_id << "</CONNECTION_ID>\n"
         << "  <HOST>" << make_escaped_string(audit_record.event->general_host.str) << "</HOST>\n"
         << "  <IP>" << make_escaped_string(audit_record.event->general_ip.str)  << "</IP>\n"
         << "  <USER>" << make_escaped_string(audit_record.event->general_user.str) << "</USER>\n"
         << "  <OS_LOGIN>" << make_escaped_string(audit_record.event->general_external_user.str) << "</OS_LOGIN>\n"
         << "  <SQLTEXT>" << make_escaped_string(audit_record.event->general_query.str) << "</SQLTEXT>\n"
         << "  <STATUS>" << audit_record.event->general_error_code << "</STATUS>\n"
         << "</AUDIT_RECORD>\n";

  return result.str();
}

std::string LogRecordFormatterNew::apply(const AuditRecordConnection &audit_record [[maybe_unused]]) {
  return "";
}

std::string LogRecordFormatterNew::apply(const AuditRecordParse &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordTableAccess &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordGlobalVariable &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordServerStartup &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordServerShutdown &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordCommand &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordQuery &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordStoredProgram &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordAuthentication &audit_record [[maybe_unused]]) {
  return "";
}
std::string LogRecordFormatterNew::apply(const AuditRecordMessage &audit_record [[maybe_unused]]) {
  return "";
}




const std::map<char, std::string> &LogRecordFormatterOld::get_escape_rules() noexcept {
  static const std::map<char, std::string> escape_rules;

  return escape_rules;
}
const std::map<char, std::string> &LogRecordFormatterJson::get_escape_rules() noexcept {
  static const std::map<char, std::string> escape_rules;

  return escape_rules;
}
const std::map<char, std::string> &LogRecordFormatterCsv::get_escape_rules() noexcept {
  static const std::map<char, std::string> escape_rules;

  return escape_rules;
}


template<AuditLogFormatType FormatType>
std::unique_ptr<LogRecordFormatterBase> create_helper() {
  return std::make_unique<LogRecordFormatter<FormatType>>();
}

std::unique_ptr<LogRecordFormatterBase> get_log_record_formatter(
    AuditLogFormatType format_type) {
  using CreateFunc = std::unique_ptr<LogRecordFormatterBase> (*)();
  static const CreateFunc funcs[static_cast<int>(AuditLogFormatType::FormatsCount)] = {
      create_helper<AuditLogFormatType::New>,
      create_helper<AuditLogFormatType::Old>,
      create_helper<AuditLogFormatType::Json>,
      create_helper<AuditLogFormatType::Csv>
  };
  return (*funcs[static_cast<int>(format_type)])();
}

}  // namespace audit_log_v2
