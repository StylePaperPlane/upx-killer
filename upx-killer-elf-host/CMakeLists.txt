cmake_minimum_required(VERSION 3.20)
project(upx_killer_elf_host LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

get_filename_component(
  REPOSITORY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
add_subdirectory(
  "${REPOSITORY_ROOT}/upx-killer-contracts"
  "${CMAKE_BINARY_DIR}/upx-killer-contracts")
add_subdirectory(
  "${REPOSITORY_ROOT}/upx-killer-engine"
  "${CMAKE_BINARY_DIR}/upx-killer-engine")

add_library(upx_killer_elf_linux STATIC
  Infrastructure/Linux/Debugging/Breakpoints/LinuxSoftwareBreakpoint.cpp
  Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.cpp
  Infrastructure/Linux/Debugging/Process/LinuxTracedProcess.cpp
  Infrastructure/Linux/Debugging/PtraceElfSnapshotCapture.cpp
  Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.cpp
  Infrastructure/Linux/Pipes/PosixPipeTransport.cpp
  Infrastructure/Linux/Storage/LinuxArtifactPublisher.cpp
  Infrastructure/Linux/Storage/LinuxElfSourceReader.cpp
  Infrastructure/Linux/Verification/LinuxElfImageValidator.cpp)
add_library(upx_killer::elf_linux ALIAS upx_killer_elf_linux)

target_include_directories(upx_killer_elf_linux PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")
target_compile_features(upx_killer_elf_linux PUBLIC cxx_std_20)
target_compile_options(upx_killer_elf_linux PRIVATE
  -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(upx_killer_elf_linux PUBLIC
  upx_killer::contracts
  upx_killer::elf_core
  upx_killer::elf_application)

add_executable(upx_killer_elf_host Application/ElfHostMain.cpp)
target_compile_features(upx_killer_elf_host PRIVATE cxx_std_20)
target_compile_options(upx_killer_elf_host PRIVATE
  -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(upx_killer_elf_host PRIVATE
  upx_killer::contracts
  upx_killer::elf_application
  upx_killer::elf_linux)
