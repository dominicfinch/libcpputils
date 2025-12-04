cmake_minimum_required(VERSION 3.22)
project(cpputils LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT_LIB_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/code/lib)

###########################
## Pre-initialize tasks  ##
###########################

execute_process(
        COMMAND git rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(
        COMMAND git log -1 --format=%H
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE)

# Dependencies
#add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dep/jsoncpp)

# Build main library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/code/lib)

# Build unit tests
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/code/tests/component)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/code/tests/unit)
