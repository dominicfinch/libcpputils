cmake_minimum_required(VERSION 3.28)
project(cpputils LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
add_subdirectory(dep/jsoncpp)

# Build main library
add_subdirectory(code/lib/src)

# Build unit tests
add_subdirectory(code/tests/unit)
