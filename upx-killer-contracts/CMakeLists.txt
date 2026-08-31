cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(upx_killer_contracts LANGUAGES CXX)
endif()

add_library(upx_killer_contracts STATIC
  Application/Coordination/UnpackCoordinator.cpp
  Protocol/EngineHost/EngineHostCodec.cpp)
add_library(upx_killer::contracts ALIAS upx_killer_contracts)

target_include_directories(upx_killer_contracts PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")
target_compile_features(upx_killer_contracts PUBLIC cxx_std_20)
target_compile_options(upx_killer_contracts PRIVATE
  -Wall -Wextra -Wpedantic -Werror)
