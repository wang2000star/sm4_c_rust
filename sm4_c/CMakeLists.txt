cmake_minimum_required(VERSION 3.16)

project(Yux LANGUAGES C)

## Use -std=c11 as default.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)

## if Debug 
#set(CMAKE_BUILD_TYPE "Debug")

## if Release
set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_C_FLAGS_RELEASE "-O2")
#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

include_directories(${CMAKE_SOURCE_DIR}/include)
# add symmetric library
aux_source_directory("${CMAKE_SOURCE_DIR}/src" SYMMETRIC_SRC_LIST)
add_library(Symmetric ${SYMMETRIC_SRC_LIST})
# Output SYMMETRIC_SRC_LIST for debugging
message(STATUS "SYMMETRIC_SRC_LIST: ${SYMMETRIC_SRC_LIST}")

add_subdirectory(tests)