cmake_minimum_required (VERSION 3.28)

project("sec-chat-client")
set(CMAKE_CXX_STANDARD 17)

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(APP_PRETTY_NAME "Security Chat Client")
set(APP_MAJOR_VERSION   1)
set(APP_MINOR_VERSION   0)
set(APP_PATCH_VERSION   0)
set(APP_REVIS_VERSION   0)

file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_EXT_DIR}/argtable3/*.c
    ${PROJECT_SRC_DIR}/**/*.cpp
    ${PROJECT_SRC_DIR}/*.cpp)
#message(${PROJECT_SRC_FILESET})

configure_file(${PROJECT_INC_DIR}/constants.h.in ${PROJECT_INC_DIR}/constants.h)

add_executable(${PROJECT_NAME} ${PROJECT_SRC_FILESET})

target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_INC_DIR} ${PROJECT_EXT_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE cpputils jsonrpccpp-client jsonrpccpp-common jsoncpp_lib)

########################
## Post build tasks ##
########################
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/settings.json ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-settings.json)