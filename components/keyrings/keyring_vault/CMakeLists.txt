# Copyright (c) 2023, Percona and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is also distributed with certain software (including
# but not limited to OpenSSL) that is licensed under separate terms,
# as designated in a particular file or component or in included license
# documentation. The authors of MySQL hereby grant you an additional
# permission to link the program and your derivative works with the
# separately licensed software that they have included with MySQL.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

# keyring_vault mtr suite is a default suite and must be installed always,
# regardless if the keyring_vault component is built and installed or not.
IF (NOT DEFINED WITH_COMPONENT_KEYRING_VAULT AND
        NOT DEFINED WITHOUT_COMPONENT_KEYRING_VAULT)
  SET(WITH_COMPONENT_KEYRING_VAULT 1)
ENDIF()

IF(NOT WITH_COMPONENT_KEYRING_VAULT)
  RETURN()
ENDIF()

INCLUDE(CheckFunctionExists)
INCLUDE(curl)

MACRO (CHECK_IF_LIB_FOUND lib_name project_name status_mode)
  SET (lib_found_variable_name "${lib_name}_FOUND")
  IF (NOT DEFINED ${lib_found_variable_name} OR NOT ${${lib_found_variable_name}})
    message(${status_mode} "Not building ${project_name}, could not find library: ${lib_name}")
    RETURN()
  ENDIF()
ENDMACRO()

CHECK_IF_LIB_FOUND(CURL "keyring_vault" FATAL_ERROR)
MESSAGE(STATUS "Building keyring_vault component")

ADD_DEFINITIONS(-DLOG_COMPONENT_TAG="component_keyring_vault")

SET(KEYRING_VAULT_SOURCE
  # Component handling
  keyring_vault.cc

  # Config handling
  config/config.cc

  # Encryption handling
  service_implementation/keyring_encryption_service_definition.cc

  # Generator handling
  service_implementation/keyring_generator_service_definition.cc

  # Keyring load handling
  service_implementation/keyring_load_service_definition.cc

  # Keys metadata iterator handling
  service_implementation/keyring_keys_metadata_iterator_service_definition.cc

  # Metadata query handling
  service_implementation/keyring_metadata_query_service_definition.cc

  # Reader handling
  service_implementation/keyring_reader_service_definition.cc

  # Writer handling
  service_implementation/keyring_writer_service_definition.cc

  # Backend handling
  backend/backend.cc
  backend/vault_base64.cc
  backend/vault_curl.cc
  backend/vault_keys_container.cc
  backend/vault_parser_composer.cc

  # Component callbacks
  component_callbacks.cc
)

SET(KEYRING_VAULT_LIBRARIES keyring_common ${CURL_LIBRARY} ${SSL_LIBRARIES} extra::rapidjson)

MYSQL_ADD_COMPONENT(keyring_vault
  ${KEYRING_VAULT_SOURCE}
  LINK_LIBRARIES ${KEYRING_VAULT_LIBRARIES}
  MODULE_ONLY
)

TARGET_INCLUDE_DIRECTORIES(
  component_keyring_vault
  PUBLIC
)

TARGET_INCLUDE_DIRECTORIES(
  component_keyring_vault
  SYSTEM
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${BOOST_PATCHES_DIR}
  ${BOOST_INCLUDE_DIR}
)

IF(APPLE)
  SET_TARGET_PROPERTIES(component_keyring_vault PROPERTIES
    LINK_FLAGS "-undefined dynamic_lookup")
ENDIF()
