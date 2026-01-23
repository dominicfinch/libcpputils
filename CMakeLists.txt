#
# © Copyright 2025 Dominic Finch
#

cmake_minimum_required(VERSION 3.22)
project(iar-security-service LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_DEP_DIR ${CMAKE_SOURCE_DIR}/dep)
set(PROJECT_EXT_DIR ${PROJECT_DEP_DIR}/ext)

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
add_subdirectory(dep/libcpputils)

# Main build
add_subdirectory(code/app)
add_subdirectory(code/tests/unit)