/* Copyright (c) 2023, Percona and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include "vault_client.h"

#include <curl/curl.h>


namespace keyring_vault {
namespace backend {

VaultClient::VaultClient(config::Config_pod const &config)
    : m_resolved_secret_mount_point_version{Vault_version_unknown} {
  Secure_string mount_point_path;
  Secure_string directory_path;
  Vault_version_type mount_point_version = config.secret_mount_point_version;

  if (mount_point_version != Vault_version_v1) {
    std::size_t max_versions;
    bool cas_required;
    Optional_secure_string delete_version_after;

    auto begin_iter = config.secret_mount_point.cbegin();
    auto end_iter = config.secret_mount_point.cend();
    auto delimiter_iter = begin_iter;
    decltype(delimiter_iter) from_iter;
    Secure_string json_response;

    mount_point_version = Vault_version_v1;
    Secure_string partial_path;

    while (delimiter_iter != end_iter && mount_point_version == Vault_version_v1) {
      from_iter = delimiter_iter;
      ++from_iter;
      delimiter_iter = std::find(from_iter, end_iter, mount_point_path_delimiter);
      partial_path.assign(begin_iter, delimiter_iter);
      Secure_string err_msg = "Probing ";
      err_msg += partial_path;
      err_msg += " for being a mount point";

      if (probe_mount_point_config(partial_path, json_response)) {
        err_msg += " unsuccessful - skipped.";
        logger_->log(MY_INFORMATION_LEVEL, err_msg.c_str());
      } else if (parser_->parse_mount_point_config(json_response, max_versions,
                                                   cas_required,
                                                   delete_version_after)) {
        err_msg += " successful but response has unexpected format - skipped.";
        logger_->log(MY_WARNING_LEVEL, err_msg.c_str());
      } else {
        err_msg += " successful - identified kv-v2 secret engine.";
        logger_->log(MY_INFORMATION_LEVEL, err_msg.c_str());
        mount_point_version = Vault_version_v2;
      }
    }

    if (config.secret_mount_point_version == Vault_version_v2 &&
        mount_point_version != Vault_version_v2) {
      mount_point_version = Vault_version_unknown;
      logger_->log(MY_ERROR_LEVEL,
                   "Auto-detected mount point version is not the same as "
                   "specified in 'secret_mount_point_version'.");
    }

    if (mount_point_version == Vault_version_v2) {
      mount_point_path.swap(partial_path);
      if (delimiter_it != en) {
        ++delimiter_it;
        directory_path.assign(delimiter_it, en);
      }
    }
  }

  if (mount_point_version != Vault_version_unknown) {
    m_resolved_secret_mount_point_version = mount_point_version;
    m_mount_point_path.swap(mount_point_path);
    m_directory_path.swap(directory_path);
  }
}

bool VaultClient::http_init() {
  curl_global_init(CURL_GLOBAL_ALL);
  return m_global_curl.create();
}

void VaultClient::http_cleanup() {
  curl_global_cleanup();
  m_global_curl.cleanup();
}



}  // namespace backend
}  // namespace keyring_vault
