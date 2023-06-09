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

#ifndef KEYRING_VAULT_BACKEND_VAULT_CLIENT_INCLUDED
#define KEYRING_VAULT_BACKEND_VAULT_CLIENT_INCLUDED

namespace keyring_vault {
namespace backend {

class VaultClient {
 public:
  explicit VaultClient(config::Config_pod const &config);

  bool list_keys(Secure_string *response) noexcept;
  bool write_key(const Vault_key &key, Secure_string *response) noexcept;
  bool read_key(const Vault_key &key, Secure_string *response) noexcept;
  bool delete_key(const Vault_key &key, Secure_string *response) noexcept;


 private:
  bool http_init();
  void http_cleanup();


 private:
  Global_curl m_global_curl;
  Secure_string m_mount_point_path;
  Secure_string m_directory_path;
  Vault_version_type m_resolved_secret_mount_point_version;
};

}  // namespace backend
}  // namespace keyring_vault

#endif  // KEYRING_VAULT_BACKEND_VAULT_CLIENT_INCLUDED
