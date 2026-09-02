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
  Infrastructure/Linux/Debugging/Breakpoints/LinuxExecutionBreakpoint.cpp
  Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.cpp
  Infrastructure/Linux/Debugging/Process/LinuxTracedProcess.cpp
  Infrastructure/Linux/Debugging/ElfSnapshotCaptureRouter.cpp
  Infrastructure/Linux/Debugging/PtraceElfSnapshotCapture.cpp
  Infrastructure/Linux/Debugging/Recovery/RecoveredElfLoadBiasResolver.cpp
  Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.cpp
  Infrastructure/Linux/Debugging/SharedObjects/PtraceElfSharedObjectSnapshotCapture.cpp
  Infrastructure/Linux/Debugging/SharedObjects/RecoveredSharedObjectLocator.cpp
  Infrastructure/Linux/Debugging/ThreadContext/LinuxThreadContext.cpp
  Infrastructure/Linux/Loading/ElfSharedObjectLoaderCatalog.cpp
  Infrastructure/Linux/Loading/IsolatedElfLoadVerifier.cpp
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

add_executable(upx_killer_elf_so_loader_x64
  Application/SharedObjectLoader/ElfSharedObjectLoaderMain.c)
target_compile_options(upx_killer_elf_so_loader_x64 PRIVATE
  -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(upx_killer_elf_so_loader_x64 PRIVATE dl)

find_program(UPX_KILLER_AS_EXECUTABLE as REQUIRED)
find_program(UPX_KILLER_LD_EXECUTABLE ld REQUIRED)
find_file(UPX_KILLER_ELF32_LIBC
  NAMES libc.so.6
  PATHS
    /lib32
    /usr/lib32
    /lib/i386-linux-gnu
    /usr/lib/i386-linux-gnu
  NO_DEFAULT_PATH
  REQUIRED)
set(UPX_KILLER_ELF_SO_LOADER32_C_OBJECT
  "${CMAKE_CURRENT_BINARY_DIR}/ElfSharedObjectLoaderMain32.o")
set(UPX_KILLER_ELF_SO_LOADER32_ENTRY_OBJECT
  "${CMAKE_CURRENT_BINARY_DIR}/ElfSharedObjectLoaderEntry32.o")
set(UPX_KILLER_ELF_SO_LOADER32
  "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_so_loader_x86")
add_custom_command(
  OUTPUT "${UPX_KILLER_ELF_SO_LOADER32}"
  COMMAND "${CMAKE_C_COMPILER}" -m32 -fno-pie -fno-stack-protector
    -DUPX_KILLER_CUSTOM_ENTRY -Wall -Wextra -Wpedantic -Werror
    -c
    "${CMAKE_CURRENT_SOURCE_DIR}/Application/SharedObjectLoader/ElfSharedObjectLoaderMain.c"
    -o "${UPX_KILLER_ELF_SO_LOADER32_C_OBJECT}"
  COMMAND "${UPX_KILLER_AS_EXECUTABLE}" --32
    "${CMAKE_CURRENT_SOURCE_DIR}/Application/SharedObjectLoader/ElfSharedObjectLoaderEntry32.S"
    -o "${UPX_KILLER_ELF_SO_LOADER32_ENTRY_OBJECT}"
  COMMAND "${UPX_KILLER_LD_EXECUTABLE}" -m elf_i386
    --dynamic-linker /lib/ld-linux.so.2 -e _start
    "${UPX_KILLER_ELF_SO_LOADER32_ENTRY_OBJECT}"
    "${UPX_KILLER_ELF_SO_LOADER32_C_OBJECT}"
    "${UPX_KILLER_ELF32_LIBC}"
    -o "${UPX_KILLER_ELF_SO_LOADER32}"
  DEPENDS
    Application/SharedObjectLoader/ElfSharedObjectLoaderMain.c
    Application/SharedObjectLoader/ElfSharedObjectLoaderEntry32.S
  VERBATIM)
add_custom_target(upx_killer_elf_so_loader_x86_target ALL
  DEPENDS "${UPX_KILLER_ELF_SO_LOADER32}")
add_dependencies(upx_killer_elf_host
  upx_killer_elf_so_loader_x64
  upx_killer_elf_so_loader_x86_target)

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

  set(UPX_KILLER_ELF_BEHAVIOR32_OBJECT
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_behavior_x86.o")
  set(UPX_KILLER_ELF_BEHAVIOR32
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_behavior_x86")
  add_custom_command(
    OUTPUT "${UPX_KILLER_ELF_BEHAVIOR32_OBJECT}"
    COMMAND "${UPX_KILLER_AS_EXECUTABLE}" --32
      "${CMAKE_CURRENT_SOURCE_DIR}/Tests/Fixtures/ELF32/BehaviorTracee32.S"
      -o "${UPX_KILLER_ELF_BEHAVIOR32_OBJECT}"
    DEPENDS Tests/Fixtures/ELF32/BehaviorTracee32.S
    VERBATIM)
  add_custom_target(upx_killer_elf_behavior_x86_object
    DEPENDS "${UPX_KILLER_ELF_BEHAVIOR32_OBJECT}")
  add_custom_command(
    OUTPUT "${UPX_KILLER_ELF_BEHAVIOR32}"
    COMMAND "${UPX_KILLER_LD_EXECUTABLE}" -m elf_i386
      "${UPX_KILLER_ELF_BEHAVIOR32_OBJECT}"
      -o "${UPX_KILLER_ELF_BEHAVIOR32}"
    DEPENDS upx_killer_elf_behavior_x86_object
    VERBATIM)
  add_custom_target(upx_killer_elf_behavior_x86_fixture
    DEPENDS "${UPX_KILLER_ELF_BEHAVIOR32}")

  set(UPX_KILLER_ELF_DYNAMIC_PIE32_OBJECT
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_dynamic_pie_x86.o")
  set(UPX_KILLER_ELF_DYNAMIC_PIE32
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_dynamic_pie_x86")
  add_custom_command(
    OUTPUT "${UPX_KILLER_ELF_DYNAMIC_PIE32_OBJECT}"
    COMMAND "${CMAKE_C_COMPILER}" -m32 -fPIE -fno-stack-protector
      -fno-asynchronous-unwind-tables -O2 -Wall -Wextra -Wpedantic -Werror
      -c
      "${CMAKE_CURRENT_SOURCE_DIR}/Tests/Fixtures/ELF32/PIE/DynamicPieTracee32.c"
      -o "${UPX_KILLER_ELF_DYNAMIC_PIE32_OBJECT}"
    DEPENDS Tests/Fixtures/ELF32/PIE/DynamicPieTracee32.c
    VERBATIM)
  add_custom_command(
    OUTPUT "${UPX_KILLER_ELF_DYNAMIC_PIE32}"
    COMMAND "${UPX_KILLER_LD_EXECUTABLE}" -m elf_i386 -pie
      --dynamic-linker /lib/ld-linux.so.2 -e _start
      "${UPX_KILLER_ELF_DYNAMIC_PIE32_OBJECT}"
      "${UPX_KILLER_ELF32_LIBC}"
      -o "${UPX_KILLER_ELF_DYNAMIC_PIE32}"
    DEPENDS "${UPX_KILLER_ELF_DYNAMIC_PIE32_OBJECT}"
    VERBATIM)
  add_custom_target(upx_killer_elf_dynamic_pie_x86_fixture
    DEPENDS "${UPX_KILLER_ELF_DYNAMIC_PIE32}")

  set(UPX_KILLER_ELF_STATIC_PIE32_OBJECT
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_static_pie_x86.o")
  set(UPX_KILLER_ELF_STATIC_PIE32
    "${CMAKE_CURRENT_BINARY_DIR}/upx_killer_elf_static_pie_x86")
  add_custom_command(
    OUTPUT "${UPX_KILLER_ELF_STATIC_PIE32_OBJECT}"
    COMMAND "${UPX_KILLER_AS_EXECUTABLE}" --32
      "${CMAKE_CURRENT_SOURCE_DIR}/Tests/Fixtures/ELF32/PIE/StaticPieTracee32.S"
      -o "${UPX_KILLER_ELF_STATIC_PIE32_OBJECT}"
    DEPENDS Tests/Fixtures/ELF32/PIE/StaticPieTracee32.S
    VERBATIM)
  add_custom_command(
    OUTPUT "${UPX_KILLER_ELF_STATIC_PIE32}"
    COMMAND "${UPX_KILLER_LD_EXECUTABLE}" -m elf_i386 -pie
      --no-dynamic-linker -e _start
      "${UPX_KILLER_ELF_STATIC_PIE32_OBJECT}"
      -o "${UPX_KILLER_ELF_STATIC_PIE32}"
    DEPENDS "${UPX_KILLER_ELF_STATIC_PIE32_OBJECT}"
    VERBATIM)
  add_custom_target(upx_killer_elf_static_pie_x86_fixture
    DEPENDS "${UPX_KILLER_ELF_STATIC_PIE32}")

  add_executable(upx_killer_elf_ptrace_tests
    Tests/Integration/Debugging/PtraceScenarioTests.cpp)
  target_compile_options(upx_killer_elf_ptrace_tests PRIVATE
    -Wall -Wextra -Wpedantic -Werror)
  target_link_libraries(upx_killer_elf_ptrace_tests PRIVATE
    upx_killer::elf_linux)
  add_dependencies(upx_killer_elf_ptrace_tests
    upx_killer_elf_tracee_x86_fixture
    upx_killer_elf_behavior_x86_fixture
    upx_killer_elf_dynamic_pie_x86_fixture
    upx_killer_elf_static_pie_x86_fixture)

  add_test(NAME upx_killer_elf_ptrace_scenarios
    COMMAND upx_killer_elf_ptrace_tests
      $<TARGET_FILE:upx_killer_elf_tracee_x64>
      "${UPX_KILLER_ELF_TRACEE32}")
endif()
