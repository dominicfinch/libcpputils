cmake_minimum_required (VERSION 3.22)

project("security-service-unittests")
set(CMAKE_CXX_STANDARD 17)

################
## Main build ##
################

set(PROJECT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROJECT_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB PROJECT_SRC_FILESET
    ${PROJECT_SRC_DIR}/*.cpp
    ${PROJECT_SRC_DIR}/tests/*.cpp)

#message(${PROJECT_SRC_FILESET})
add_executable(${PROJECT_NAME} ${PROJECT_SRC_FILESET})

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INC_DIR} ${PROJECT_LIB_ROOT_DIR}/include)
target_link_libraries(${PROJECT_NAME} PUBLIC cpputils -ljsoncpp)

########################
## Post build tasks ##
########################
