cmake_minimum_required(VERSION 3.24)
project(bcrypt)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(fmt REQUIRED)

if (NOT CMAKE_BUILD_TYPE OR (CMAKE_BUILD_TYPE STREQUAL ""))
  set(CMAKE_BUILD_TYPE "Debug")
endif()

string(TOLOWER "${CMAKE_BUILD_TYPE}" build_type)
message(STATUS "Building ${CMAKE_PROJECT_NAME} in ${build_type} mode")

#############################
# BCrypt
#############################

add_library(bcrypt STATIC
  bcrypt.cc
  bcrypt.h
  bcrypt_b64.cc
  bcrypt_b64.h
  blowfish.cc
  blowfish.h)

if (build_type STREQUAL "debug")
  target_compile_options(bcrypt PRIVATE -Wall -Wextra -Wpedantic -Og)
else()
  target_compile_definitions(bcrypt PRIVATE NDEBUG)
  target_compile_options(bcrypt PRIVATE -Wall -Wextra -Wpedantic -Ofast)
endif()

target_compile_features(bcrypt PRIVATE)
target_link_libraries(bcrypt fmt::fmt)

#############################
# Unit tests
#############################

enable_testing()
include(GoogleTest)

add_executable(bcrypt_test bcrypt_test.cc)
target_compile_features(bcrypt_test PRIVATE)
target_link_libraries(bcrypt_test bcrypt gtest gmock gtest_main)
gtest_discover_tests(bcrypt_test)
