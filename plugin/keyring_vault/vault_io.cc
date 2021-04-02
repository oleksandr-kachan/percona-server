#include "vault_io.h"
#include <sstream>
#include "vault_credentials_parser.h"
#include "vault_keys_list.h"

#include <boost/lexical_cast/try_lexical_convert.hpp>

#include <curl/curl.h>

namespace keyring {

bool Vault_io::init(std::string *keyring_storage_url) {
  Vault_credentials_parser vault_credentials_parser(logger);
  Vault_credentials vault_credentials;
  return vault_credentials_parser.parse(*keyring_storage_url,
                                        &vault_credentials) ||
         vault_curl->init(vault_credentials) ||
         adjust_vault_version(vault_credentials);
}

Vault_io::~Vault_io() {
  delete vault_curl;
  delete vault_parser;
}

bool Vault_io::adjust_vault_version(
    const Vault_credentials &vault_credentials) {
  Vault_version_type vault_version = Vault_version_unknown;
  if (vault_credentials.get_credential("secret_mount_point_version") ==
      "AUTO") {
    static Secure_string err_msg(
        "Could not determine version of Vault Server.");
    Secure_string json_response;
    vault_curl->list_mount_points(&json_response);
    if (vault_parser->get_vault_version(vault_credentials, json_response,
                                        vault_version)) {
      logger->log(MY_ERROR_LEVEL,
                  (err_msg + get_errors_from_response(json_response)).c_str());
      return true;
    }
  } else {
    boost::uint32_t extracted_version = 0;
    if (!boost::conversion::try_lexical_convert(
            vault_credentials.get_credential("secret_mount_point_version"),
            extracted_version)) {
      // should have never happened as secret_mount_point_version was previously
      // validated
      logger->log(MY_ERROR_LEVEL, "Failed to read secret_mount_point_version");
      return true;
    }

    switch (extracted_version) {
      case 1:
        vault_version = Vault_version_v1;
        break;
      case 2:
        vault_version = Vault_version_v2;
        break;
    }
  }

  if (vault_version != Vault_version_v1 && vault_version != Vault_version_v2)
    return true;
  vault_curl->set_vault_version(vault_version);
  return false;
}

Secure_string Vault_io::get_errors_from_response(
    const Secure_string &json_response) {
  if (json_response.empty()) return Secure_string();

  Secure_string errors_from_response, err_msg;
  if (vault_parser->parse_errors(json_response, &errors_from_response))
    err_msg = " Error while parsing error messages";
  else if (errors_from_response.size())
    err_msg =
        " Vault has returned the following error(s): " + errors_from_response;
  return err_msg;
}

bool Vault_io::get_serialized_object(ISerialized_object **serialized_object) {
  static Secure_string err_msg("Could not retrieve list of keys from Vault.");
  *serialized_object = nullptr;
  Secure_string json_response;

  if (vault_curl->list_keys(&json_response)) {
    logger->log(MY_ERROR_LEVEL,
                (err_msg + get_errors_from_response(json_response)).c_str());
    return true;
  }
  if (json_response.empty())  // no keys
  {
    *serialized_object = nullptr;
    return false;
  }

  std::unique_ptr<Vault_keys_list> keys(new Vault_keys_list());
  if (vault_parser->parse_keys(json_response, keys.get())) {
    logger->log(MY_ERROR_LEVEL, err_msg.c_str());
    return true;
  }
  if (keys->size() == 0) keys.reset(nullptr);

  *serialized_object = keys.release();
  return false;
}

bool Vault_io::retrieve_key_type_and_data(IKey *key) {
  Secure_string json_response;
  if (vault_curl->read_key(static_cast<const Vault_key &>(*key),
                           &json_response) ||
      vault_parser->parse_key_data(json_response, key,
                                   vault_curl->get_vault_version())) {
    logger->log(MY_ERROR_LEVEL, ("Could not read key from Vault." +
                                 get_errors_from_response(json_response))
                                    .c_str());
    return true;
  }
  return false;
}

ISerializer *Vault_io::get_serializer() { return &vault_key_serializer; }

bool Vault_io::write_key(const Vault_key &key) {
  Secure_string json_response, errors_from_response;
  if (vault_curl->write_key(key, &json_response) ||
      !((errors_from_response = get_errors_from_response(json_response))
            .empty())) {
    errors_from_response.insert(0, "Could not write key to Vault.");
    logger->log(MY_ERROR_LEVEL, errors_from_response.c_str());
    return true;
  }
  return false;
}

bool Vault_io::delete_key(const Vault_key &key) {
  Secure_string json_response, errors_from_response;
  if (vault_curl->delete_key(key, &json_response) ||
      !((errors_from_response = get_errors_from_response(json_response))
            .empty())) {
    logger->log(
        MY_ERROR_LEVEL,
        ("Could not delete key from Vault." + errors_from_response).c_str());
    return true;
  }
  return false;
}

bool Vault_io::flush_to_storage(ISerialized_object *serialized_object) {
  DBUG_ASSERT(serialized_object->has_next_key());
  IKey *vault_key_raw = nullptr;

  if (serialized_object->get_next_key(&vault_key_raw) ||
      vault_key_raw == NULL) {
    delete vault_key_raw;
    return true;
  }
  std::unique_ptr<IKey> vault_key(vault_key_raw);

  return serialized_object->get_key_operation() == STORE_KEY
             ? write_key(static_cast<Vault_key &>(*vault_key))
             : delete_key(static_cast<Vault_key &>(*vault_key));
}

}  // namespace keyring
