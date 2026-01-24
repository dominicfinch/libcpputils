#
# © Copyright 2025 Dominic Finch
#

cmake_minimum_required (VERSION 3.22)

project("security-service")
set(CMAKE_CXX_STANDARD 17)

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(GENERATED_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/generated)

set(APP_PRETTY_NAME "IAR Security Service")
set(APP_PROJECT_NAME "${PROJECT_NAME}")
set(APP_MAJOR_VERSION   1)
set(APP_MINOR_VERSION   0)
set(APP_PATCH_VERSION   0)
set(APP_REVIS_VERSION   0)

file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_EXT_DIR}/argtable3/*.c
    ${PROJECT_SRC_DIR}/**/**/*.cpp
    ${PROJECT_SRC_DIR}/**/*.cpp
    ${PROJECT_SRC_DIR}/*.cpp
    ${GENERATED_SRC_DIR}/*.cc)
#message(${PROJECT_SRC_FILESET})

configure_file(${PROJECT_INC_DIR}/constants.h.in ${PROJECT_INC_DIR}/constants.h)
add_executable(${PROJECT_NAME} ${PROJECT_SRC_FILESET})

target_include_directories(${PROJECT_NAME} PUBLIC
    ${PROJECT_INC_DIR}
    ${PROJECT_EXT_DIR}
    ${GENERATED_SRC_DIR}
    ${PROJECT_DEP_DIR}/libcpputils/code/lib/include
    /usr/include/jsoncpp
    /usr/include/postgresql/)

target_link_libraries(${PROJECT_NAME} PRIVATE cpputils
    -lspdlog -labsl_synchronization -ljsoncpp
    -lgrpc++ -lprotobuf -lgpr -lstdc++fs 
    -lsoci_core -lsoci_postgresql
    -ldl -lpq -lssl -lcrypto -lpthread)


########################
## Post build tasks ##
########################
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/settings.json ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-settings.json)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_SOURCE_DIR}/etc ${CMAKE_BINARY_DIR}/etc)