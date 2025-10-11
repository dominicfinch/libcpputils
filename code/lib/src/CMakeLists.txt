cmake_minimum_required (VERSION 3.28)

project("cpputils")
set(CMAKE_CXX_STANDARD 17)

option(BUILD_SHARED_LIB "Build the shared library" ON)
option(SSL_LIB_PATH "Path to SSL library" "")
option(CRYPTO_LIB_PATH "Path to crypto library" "")

###########################
## Pre-initialize tasks  ##
###########################

execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(
        COMMAND git log -1 --format=%H
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE)

########################
## Main library build ##
########################
message(${CMAKE_SOURCE_DIR})
set(PROJECT_SRC_DIR ${CMAKE_SOURCE_DIR}/code/lib/src)
set(PROJECT_INC_DIR ${CMAKE_SOURCE_DIR}/code/lib/include)

file(GLOB PROJECT_SRC_FILESET ${PROJECT_SRC_DIR}/*.cpp)

if(UNIX)
    set(LIBS_LINK -lssl -lcrypto -luuid -lstdc++fs)
endif(UNIX)

if(WIN32)
    set(LIBS_LINK -L${SSL_LIB_PATH} -L${CRYPTO_LIB_PATH})
endif(WIN32)

if(BUILD_SHARED_LIB)
    add_library(${PROJECT_NAME} SHARED ${PROJECT_SRC_FILESET})
else()
    add_library(${PROJECT_NAME} ${PROJECT_SRC_FILESET})
endif(BUILD_SHARED_LIB)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INC_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC jsoncpp_lib ${LIBS_LINK})
set_target_properties(${PROJECT_NAME} PROPERTIES EXPORT_NAME ${PROJECT_NAME})
