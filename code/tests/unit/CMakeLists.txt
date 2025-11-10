cmake_minimum_required (VERSION 3.22)

project("cpputils-unittests")
set(CMAKE_CXX_STANDARD 17)

option(EXCLUDE_DH_TESTS "Exclude Diffie-Hellman tests in build" ON)
option(EXCLUDE_CERT_TESTS "Exclude certificate builder tests in build" ON)

################
## Main build ##
################

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_SRC_DIR}/*.cpp
    ${PROJECT_SRC_DIR}/tests/*.cpp)

#message(${PROJECT_SRC_FILESET})
if(EXCLUDE_DH_TESTS)
    add_compile_definitions(EXCLUDE_DH_TESTS)
endif(EXCLUDE_DH_TESTS)

if(EXCLUDE_CERT_TESTS)
    add_compile_definitions(EXCLUDE_CERT_TESTS)
endif(EXCLUDE_CERT_TESTS)

#target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INC_DIR})
add_executable(${PROJECT_NAME} ${PROJECT_SRC_FILESET})
target_link_libraries(${PROJECT_NAME} PRIVATE cpputils)
