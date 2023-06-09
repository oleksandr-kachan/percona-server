/* Copyright (c) 2023, Oracle and/or its affiliates.

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

#include <memory>

#define RAPIDJSON_HAS_STDSTRING 1

#include "my_rapidjson_size_t.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <components/keyrings/keyring_vault/keyring_vault.h>

#include <components/keyrings/common/config/config_reader.h> /* Config_reader */
#include <include/mysql/components/component_implementation.h>

#include <boost/algorithm/string/predicate.hpp>

using keyring_common::config::Config_reader;
using keyring_vault::g_config_pod;

/**
  In order to locate a shared library, we need it to export at least
  one symbol. This way dlsym/GetProcAddress will be able to find it.
*/
DLL_EXPORT int keyring_vault_component_exported_symbol() { return 0; }

namespace keyring_vault {
namespace config {

namespace {

const char option_key_value_delimiter = '=';
const char mount_point_version_auto[] = "AUTO";
const char http_protocol_prefix[] = "http://";
const char https_protocol_prefix[] = "https://";
const char mount_point_path_delimiter = '/';

bool check_config_valid(Config_pod *config_pod) {
  std::ostringstream err_ss;

  // "vault_url": string
  bool vault_url_is_https = false;
  bool vault_url_is_http = boost::starts_with(config_pod->vault_url_, http_protocol_prefix);
  if (!vault_url_is_http)
    vault_url_is_https = boost::starts_with(config_pod->vault_url_, https_protocol_prefix);
  if (!vault_url_is_http && !vault_url_is_https) {
    err_ss << *option_name << " must be either " << http_protocol_prefix
           << " or " << https_protocol_prefix << " URL.";
    logger_->log(MY_ERROR_LEVEL, err_ss.str().c_str());
    return false;
  }

  // "secret_mount_point": string
  if (config_pod->secret_mount_point_[0] == mount_point_path_delimiter) {
    err_ss << *option_name << " must not start with "
           << mount_point_path_delimiter << ".";
    logger_->log(MY_ERROR_LEVEL, err_ss.str().c_str());
    return false;
  }
  if (config_pod->secret_mount_point_[config_pod->secret_mount_point_.size() - 1] ==
      mount_point_path_delimiter) {
    err_ss << *option_name << " must not end with "
           << mount_point_path_delimiter << ".";
    logger_->log(MY_ERROR_LEVEL, err_ss.str().c_str());
    return false;
  }

  // checks for combination op options
  if (!config_pod->vault_ca_.empty() && vault_url_is_http) {
    err_ss << option_labels[option_vault_ca] << " is specified but "
           << option_labels[option_vault_url] << " is " << http_protocol_prefix
           << ".";
    logger_->log(MY_ERROR_LEVEL, err_ss.str().c_str());
    return false;
  }
  if (config_pod->vault_ca_.empty() && vault_url_is_https) {
    err_ss << option_labels[option_vault_ca] << " is not specified but "
           << option_labels[option_vault_url] << " is " << https_protocol_prefix
           << ". "
           << "Please make sure that Vault's CA certificate is trusted by "
              "the machine from "
           << "which you intend to connect to Vault.";

    logger_->log(MY_WARNING_LEVEL, err_ss.str().c_str());
  }

  return true;
}

}  // namespace

char *g_component_path = nullptr;
char *g_instance_path = nullptr;

/* Component metadata */
static const char *s_component_metadata[][2] = {
    {"Component_name", "component_keyring_vault"},
    {"Author", "Percona Corporation"},
    {"License", "GPL"},
    {"Implementation_name", "component_keyring_vault"},
    {"Version", "1.0"}};

/* Config file name */
static const std::string config_file_name = "component_keyring_vault.cnf";

/* Config names */
static const std::string config_options[] = {
    "read_local_config",
    "vault_url",
    "secret_mount_point",
    "vault_ca",
    "token",
    "secret_mount_point_version"};

bool find_and_read_config_file(std::unique_ptr<Config_pod> &config_pod) {
  auto config_pod_tmp = std::make_unique<Config_pod>();
  /* Get shared library location */
  std::string path{g_component_path};

  auto set_config_path = [](std::string &full_path) -> bool {
    if (full_path.length() == 0) return true;
#ifdef _WIN32
    full_path += "\\";
#else
    full_path += "/";
#endif
    full_path.append(config_file_name);
    return false;
  };

  if (set_config_path(path) == true) return true;

  /* Read config file that's located at shared library location */
  auto config_reader = std::make_unique<Config_reader>(path);

  {
    bool read_local_config = false;
    if (config_reader->get_element<bool>(config_options[0],
                                         read_local_config) == false) {
      if (read_local_config == true) {
        config_reader.reset();
        /*
          Read config file from current working directory
          We assume that when control reaches here, binary has set
          current working directory appropriately.
        */
        std::string instance_path{g_instance_path};
        if (set_config_path(instance_path) == true) {
          instance_path = config_file_name;
        }
        config_reader = std::make_unique<Config_reader>(instance_path);
      }
    }
  }

  if (config_reader->get_element<std::string>(config_options[1],
                                              config_pod_tmp.get()->vault_url_)) {
    return true;
  }

  if (config_reader->get_element<std::string>(config_options[2],
                                              config_pod_tmp.get()->secret_mount_point_)) {
    return true;
  }

  if (config_reader->get_element<std::string>(config_options[3],
                                              config_pod_tmp.get()->vault_ca_)) {
    return true;
  }

  if (config_reader->get_element<std::string>(config_options[4],
                                              config_pod_tmp.get()->token_)) {
    return true;
  }

  // by default, when no "secret_mount_point_version" is specified explicitly,
  // it is considered to be AUTO
  config_pod_tmp->secret_mount_point_version_ = Vault_version_auto;
  std::string mount_point_version_raw;

  if (!config_reader->get_element<std::string>(config_options[5], mount_point_version_raw) && mount_point_version_raw != mount_point_version_auto) {
    boost::uint32_t extracted_version = 0;

    if (config_reader->get_element<boost::uint32_t>(config_options[5], extracted_version)) {
      return true;
    }

    if (boost::conversion::try_lexical_convert(secret_mount_point_version_raw, extracted_version)) {
      switch (extracted_version) {
        case 1:
          config_pod_tmp->secret_mount_point_version_ = Vault_version_v1;
          break;
        case 2:
          config_pod_tmp->secret_mount_point_version_ = Vault_version_v2;
          break;
        default: {
          err_ss << *option_name
                 << " in the configuration file must be either 1 or 2.";
          logger_->log(MY_ERROR_LEVEL, err_ss.str().c_str());
          return true;
        }
      }
    }
    else {
      err_ss << *option_name
             << " in the configuration file is neither AUTO nor a numeric "
                "value.";
      logger_->log(MY_ERROR_LEVEL, err_ss.str().c_str());
      return true;
    }
  }

  if (!check_config_valid(config_pod_tmp.get())) {
    return true;
  }

  config_pod.swap(config_pod_tmp);
  return false;
}

bool create_config(std::unique_ptr<std::vector<std::pair<std::string, std::string>>> &metadata) {
  metadata = std::make_unique<std::vector<std::pair<std::string, std::string>>>();
  if (metadata.get() == nullptr) return true;
  keyring_vault::config::Config_pod config_pod;
  bool global_config_available = false;
  if (g_config_pod != nullptr) {
    config_pod = *g_config_pod;
    global_config_available = true;
  }

  for (auto entry : keyring_vault::config::s_component_metadata) {
    metadata.get()->push_back(std::make_pair(entry[0], entry[1]));
  }

  metadata.get()->push_back(std::make_pair(
      "vault_url",
      ((global_config_available)
           ? ((config_pod.vault_url.length() == 0) ? "<NONE>"
                                                    : config_pod.vault_url)
           : "<NOT APPLICABLE>")));


  metadata.get()->push_back(std::make_pair(
      "secret_mount_point",
      ((global_config_available)
           ? ((config_pod.secret_mount_point.length() == 0) ? "<NONE>"
                                                    : config_pod.secret_mount_point)
           : "<NOT APPLICABLE>")));

  metadata.get()->push_back(std::make_pair(
      "vault_ca",
      ((global_config_available)
           ? ((config_pod.vault_ca.length() == 0) ? "<NONE>"
                                                    : config_pod.vault_ca)
           : "<NOT APPLICABLE>")));

  metadata.get()->push_back(std::make_pair(
      "token",
      ((global_config_available)
           ? ((config_pod.token.length() == 0) ? "<NONE>"
                                                    : config_pod.token)
           : "<NOT APPLICABLE>")));

  std::string mount_point_version_str{"<NOT APPLICABLE>"};

  if (global_config_available) {
    switch (config_pod.secret_mount_point_version) {
      case Vault_version_auto:
        mount_point_version_str = mount_point_version_auto;
        break;
      case Vault_version_v1:
        mount_point_version_str = "1";
        break;
      case Vault_version_v2:
        mount_point_version_str = "2";
        break;
      case Vault_version_unknown:
      default:
        mount_point_version_str = "<NONE>";
        break;
    }
  }

  metadata.get()->push_back(std::make_pair("secret_mount_point_version", mount_point_version_str));

  return false;
}

}  // namespace config
}  // namespace keyring_vault
