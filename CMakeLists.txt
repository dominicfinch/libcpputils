cmake_minimum_required(VERSION 3.28)
project(cpputils LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_EXT_DIR ${CMAKE_SOURCE_DIR}/code/ext)

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

# Dependencies
add_subdirectory(dep/jsoncpp)

# Build main library
add_subdirectory(code/lib)

# Build unit tests
add_subdirectory(code/tests/unit)

# Build apps
add_subdirectory(code/apps/sec-chat/server)
add_subdirectory(code/apps/sec-chat/client-cli)
add_subdirectory(code/apps/sec-chat/client-ui)

