cmake_minimum_required(VERSION 3.20)
project(upx_killer_elf_host LANGUAGES C CXX)

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
  Infrastructure/Linux/Debugging/ThreadContext/LinuxThreadContext.cpp
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

option(UPX_KILLER_BUILD_ELF_TESTS
  "Build Linux ptrace integration tests" OFF)
if(UPX_KILLER_BUILD_ELF_TESTS)
  enable_testing()
  find_package(Threads REQUIRED)

  add_executable(upx_killer_elf_tracee_x64
    Tests/Fixtures/Debugging/Tracee.c)
  target_compile_options(upx_killer_elf_tracee_x64 PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
  target_link_libraries(upx_killer_elf_tracee_x64 PRIVATE Threads::Threads)

  find_program(UPX_KILLER_AS_EXECUTABLE as REQUIRED)
  find_program(UPX_KILLER_LD_EXECUTABLE ld REQUIRED)
  set(UPX_KILLER_ELF_TRACEE32_OBJECT
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_tracee_x86.o")
  set(UPX_KILLER_ELF_TRACEE32
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_tracee_x86")
  add_custom_command(
    OUTPUT "${UPX_KILLER_ELF_TRACEE32}"
    COMMAND "${UPX_KILLER_AS_EXECUTABLE}" --32
      "${CMAKE_CURRENT_SOURCE_DIR}/Tests/Fixtures/Debugging/Tracee32.S"
      -o "${UPX_KILLER_ELF_TRACEE32_OBJECT}"
    COMMAND "${UPX_KILLER_LD_EXECUTABLE}" -m elf_i386
      "${UPX_KILLER_ELF_TRACEE32_OBJECT}"
      -o "${UPX_KILLER_ELF_TRACEE32}"
    DEPENDS Tests/Fixtures/Debugging/Tracee32.S
    VERBATIM)
  add_custom_target(upx_killer_elf_tracee_x86_fixture
    DEPENDS "${UPX_KILLER_ELF_TRACEE32}")

  add_executable(upx_killer_elf_ptrace_tests
    Tests/Integration/Debugging/PtraceScenarioTests.cpp)
  target_compile_options(upx_killer_elf_ptrace_tests PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
  target_link_libraries(upx_killer_elf_ptrace_tests PRIVATE
    upx_killer::elf_linux)
  add_dependencies(upx_killer_elf_ptrace_tests
    upx_killer_elf_tracee_x86_fixture)

  add_test(NAME upx_killer_elf_ptrace_scenarios
    COMMAND upx_killer_elf_ptrace_tests
      $<TARGET_FILE:upx_killer_elf_tracee_x64>
      "${UPX_KILLER_ELF_TRACEE32}")
endif()
