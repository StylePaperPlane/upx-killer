cmake_minimum_required(VERSION 3.20)
project(upx_killer_elf_host LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(REPOSITORY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(CONTRACTS_ROOT "${REPOSITORY_ROOT}/upx-killer-contracts")
set(ENGINE_ROOT "${REPOSITORY_ROOT}/upx-killer-engine")

add_executable(upx_killer_elf_host
  Application/ElfHostMain.cpp
  Infrastructure/Linux/Debugging/Breakpoints/LinuxSoftwareBreakpoint.cpp
  Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.cpp
  Infrastructure/Linux/Debugging/Process/LinuxTracedProcess.cpp
  Infrastructure/Linux/Debugging/PtraceElfSnapshotCapture.cpp
  Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.cpp
  Infrastructure/Linux/Pipes/PosixPipeTransport.cpp
  Infrastructure/Linux/Storage/LinuxArtifactPublisher.cpp
  Infrastructure/Linux/Storage/LinuxElfSourceReader.cpp
  Infrastructure/Linux/Verification/LinuxElfImageValidator.cpp
  ${CONTRACTS_ROOT}/Application/Coordination/UnpackCoordinator.cpp
  ${CONTRACTS_ROOT}/Protocol/EngineHost/EngineHostCodec.cpp
  ${ENGINE_ROOT}/Application/ELF/Capabilities/ElfBackendCapabilities.cpp
  ${ENGINE_ROOT}/Application/ELF/Capture/ElfRuntimeCaptureUseCase.cpp
  ${ENGINE_ROOT}/Application/ELF/ElfUnpackBackend.cpp
  ${ENGINE_ROOT}/Application/ELF/Preparation/ElfTargetPreparationUseCase.cpp
  ${ENGINE_ROOT}/Application/ELF/Preparation/ElfTargetProbe.cpp
  ${ENGINE_ROOT}/Application/ELF/Reconstruction/ElfImageReconstructionUseCase.cpp
  ${ENGINE_ROOT}/Core/ELF/OepDiscovery/UpxElfOepLocator.cpp
  ${ENGINE_ROOT}/Core/ELF/DynamicLinking/ElfDynamicMetadataAnalyzer.cpp
  ${ENGINE_ROOT}/Core/ELF/Parsing/ElfParser.cpp
  ${ENGINE_ROOT}/Core/ELF/Reconstruction/ElfImageRebuilder.cpp
  ${ENGINE_ROOT}/Core/ELF/Validation/ElfImageValidator.cpp)

target_include_directories(upx_killer_elf_host PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CONTRACTS_ROOT}"
  "${ENGINE_ROOT}")

target_compile_options(upx_killer_elf_host PRIVATE
  -Wall -Wextra -Wpedantic -Werror)
