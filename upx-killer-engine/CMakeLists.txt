cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(upx_killer_elf_engine LANGUAGES CXX)
endif()

if(NOT TARGET upx_killer::contracts)
  message(FATAL_ERROR
    "upx_killer::contracts must be defined before the ELF engine targets")
endif()

add_library(upx_killer_elf_core STATIC
  Core/ELF/Format/Internal/ElfClassTraits.h
  Core/ELF/DynamicLinking/ElfDynamicMetadataAnalyzer.cpp
  Core/ELF/OepDiscovery/UpxElfOepLocator.cpp
  Core/ELF/Parsing/ElfParser.cpp
  Core/ELF/Reconstruction/ElfImageRebuilder.cpp
  Core/ELF/Validation/ElfImageValidator.cpp)
add_library(upx_killer::elf_core ALIAS upx_killer_elf_core)

target_include_directories(upx_killer_elf_core PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")
target_compile_features(upx_killer_elf_core PUBLIC cxx_std_20)
target_compile_options(upx_killer_elf_core PRIVATE
  -Wall -Wextra -Wpedantic -Werror)

add_library(upx_killer_elf_application STATIC
  Application/ELF/Capabilities/ElfBackendCapabilities.cpp
  Application/ELF/Capture/ElfRuntimeCaptureUseCase.cpp
  Application/ELF/ElfUnpackBackend.cpp
  Application/ELF/Hosting/RemoteElfUnpackBackend.cpp
  Application/ELF/Preparation/ElfTargetPreparationUseCase.cpp
  Application/ELF/Preparation/ElfTargetProbe.cpp
  Application/ELF/Reconstruction/ElfImageReconstructionUseCase.cpp)
add_library(upx_killer::elf_application ALIAS upx_killer_elf_application)

target_include_directories(upx_killer_elf_application PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")
target_compile_features(upx_killer_elf_application PUBLIC cxx_std_20)
target_compile_options(upx_killer_elf_application PRIVATE
  -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(upx_killer_elf_application PUBLIC
  upx_killer::contracts
  upx_killer::elf_core)
