cmake_minimum_required (VERSION 3.22)

project("sec-chat-client-ui")
set(CMAKE_CXX_STANDARD 14)      # jsonrpc has problems with C17

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(QT_INC_DIR /usr/include/x86_64-linux-gnu/qt5)


set(APP_PRETTY_NAME "Security Chat UI Client")
set(APP_PROJECT_NAME "${PROJECT_NAME}")
set(APP_MAJOR_VERSION   1)
set(APP_MINOR_VERSION   0)
set(APP_PATCH_VERSION   0)
set(APP_REVIS_VERSION   0)

file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_EXT_DIR}/argtable3/*.c
    ${PROJECT_SRC_DIR}/**/*.cpp
    ${PROJECT_SRC_DIR}/*.cpp)

#message(${PROJECT_SRC_FILESET})
#configure_file(${PROJECT_INC_DIR}/constants.h.in ${PROJECT_INC_DIR}/constants.h)

# Needed for Qt
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

add_executable(${PROJECT_NAME} ${PROJECT_SRC_FILESET})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${PROJECT_INC_DIR} ${PROJECT_EXT_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${QT_INC_DIR})

target_link_libraries(${PROJECT_NAME} PRIVATE
    cpputils
    jsonrpccpp-client
    jsonrpccpp-common
    jsoncpp_lib
    Qt5Core
    Qt5Gui
    Qt5WebKitWidgets
    Qt5Widgets)

########################
## Post build tasks ##
########################
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/settings.json ${CMAKE_BINARY_DIR}/${PROJECT_NAME}-settings.json)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_CURRENT_SOURCE_DIR}/logo.svg ${CMAKE_BINARY_DIR}/logo.svg)