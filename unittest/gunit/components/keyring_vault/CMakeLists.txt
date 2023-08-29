IF (NOT DEFINED WITH_COMPONENT_KEYRING_VAULT)
  SET (WITH_COMPONENT_KEYRING_VAULT 1)
ENDIF()
IF(NOT GMOCK_FOUND OR NOT WITH_COMPONENT_KEYRING_VAULT)
    MESSAGE (STATUS "Not building component_keyring_vault unit tests")
    RETURN()
ENDIF()

message(STATUS "Building component_keyring_vault unittests")

ADD_DEFINITIONS(-DLOG_COMPONENT_TAG="component_keyring_vault")

INCLUDE_DIRECTORIES(SYSTEM
        ${GMOCK_INCLUDE_DIRS}
        ${BOOST_PATCHES_DIR}
        ${BOOST_INCLUDE_DIR}
)

INCLUDE_DIRECTORIES(
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/sql
        ${CMAKE_SOURCE_DIR}/components/keyrings/common
        ${CMAKE_SOURCE_DIR}/components/keyrings/keyring_vault
        ${CMAKE_SOURCE_DIR}/unittest/gunit
        ${CMAKE_SOURCE_DIR}/unittest/gunit/components/keyring_vault
)

SET(TESTS
    vault_backend
    vault_config
    vault_parser
)

SET(SRC_FILES)
LIST(APPEND SRC_FILES
  ${CMAKE_SOURCE_DIR}/components/keyrings/common/data/meta.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/common/data/data.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/common/data/pfs_string.cpp
  ${CMAKE_SOURCE_DIR}/components/keyrings/common/utils/utils.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/keyring_vault/config/config.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/keyring_vault/backend/backend.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/keyring_vault/backend/vault_base64.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/keyring_vault/backend/vault_curl.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/keyring_vault/backend/vault_parser_composer.cc
  ${CMAKE_SOURCE_DIR}/components/keyrings/keyring_vault/backend/vault_keys_container.cc
)

ADD_LIBRARY(component_keyring_vault_test STATIC ${SRC_FILES})
ADD_DEPENDENCIES(component_keyring_vault_test GenError)
TARGET_LINK_LIBRARIES(component_keyring_vault_test extra::rapidjson)

SET(ALL_COMPONENT_KEYRING_VAULT_TESTS)
FOREACH(test ${TESTS})
  LIST(APPEND ALL_COMPONENT_KEYRING_VAULT_TESTS ${test}-t.cc)
ENDFOREACH()

MYSQL_ADD_EXECUTABLE(merge_component_keyring_vault_tests-t
  ${ALL_COMPONENT_KEYRING_VAULT_TESTS}
  ENABLE_EXPORTS
  ADD_TEST merge_component_keyring_vault_tests)

TARGET_LINK_LIBRARIES(merge_component_keyring_vault_tests-t
  component_keyring_vault_test
  gunit_large
  perfschema
  sql_main
  strings
  mysys
  sql_gis
  sql_dd
  minchassis
  binlog
  rpl
  rpl_source
  rpl_replica
  ${CURL_LIBRARY}
  ${SSL_LIBRARIES}
  ${ICU_LIBRARIES})

ADD_DEPENDENCIES(merge_component_keyring_vault_tests-t GenError)

FOREACH(test ${TESTS})
  MYSQL_ADD_EXECUTABLE(${test}-t ${test}-t.cc
    ENABLE_EXPORTS SKIP_INSTALL EXCLUDE_FROM_ALL)

  TARGET_LINK_LIBRARIES(${test}-t component_keyring_vault_test gunit_small server_unittest_library ${ICU_LIBRARIES} ${SSL_LIBRARIES})
ENDFOREACH()
