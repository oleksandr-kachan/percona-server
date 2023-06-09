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
IF(WITH_KEYRING_VAULT_TEST)
  ADD_SUBDIRECTORY(keyring_vault-test)
ENDIF()

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

INCLUDE_DIRECTORIES(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${BOOST_PATCHES_DIR}
  ${BOOST_INCLUDE_DIR}
  ${CURL_INCLUDE_DIRS}
)











MYSQL_ADD_PLUGIN(keyring_vault
        ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keyring_key.cc
        ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keys_container.cc
        ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keys_iterator.cc
        ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keyring_impl.cc
        vault_io.cc
        vault_key.cc
        vault_base64.cc
        vault_parser_composer.cc
        vault_keys_list.cc
        vault_keys_container.cc
        vault_curl.cc
        vault_credentials_parser.cc
        vault_credentials.cc
        vault_keyring.cc
        LINK_LIBRARIES ${CURL_LIBRARY} ${SSL_LIBRARIES}
        MODULE_ONLY
        MODULE_OUTPUT_NAME "keyring_vault")

# We limit symbols exported on Linux to only those required by server.
IF(LINK_FLAG_NO_UNDEFINED)
    GET_PROPERTY(keyring_vault_link_flags TARGET keyring_vault PROPERTY LINK_FLAGS)
    SET_PROPERTY(TARGET keyring_vault PROPERTY LINK_FLAGS "${keyring_vault_link_flags} -Wl,--version-script=${CMAKE_SOURCE_DIR}/plugin/keyring_vault/keyring_vault.version")
ENDIF()
