#ifndef MYSQL_VAULT_KEYS_CONTAINER_H
#define MYSQL_VAULT_KEYS_CONTAINER_H

#include <boost/core/noncopyable.hpp>
#include "plugin/keyring/common/keys_container.h"

namespace keyring {

class IVault_io;

class Vault_keys_container final : public Keys_container,
                                   private boost::noncopyable {
 public:
  Vault_keys_container(ILogger *logger_value) noexcept
      : Keys_container(logger_value) {}

  bool init(IKeyring_io *keyring_io, std::string keyring_storage_url) override;
  IKey *fetch_key(IKey *key) override;
  virtual void set_curl_timeout(uint timeout);

 private:
  bool flush_to_backup() override;
  IVault_io *vault_io;
};

}  // namespace keyring

#endif  // MYSQL_VAULT_KEYS_CONTAINER_H
