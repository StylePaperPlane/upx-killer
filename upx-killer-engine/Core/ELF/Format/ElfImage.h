#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace upx_killer::engine::elf {

enum class ElfClass : std::uint8_t {
  Bits32,
  Bits64,
};

enum class ElfMachine : std::uint8_t {
  X86,
  X64,
};

enum class ElfImageType : std::uint8_t {
  Executable,
  PositionIndependentExecutable,
  SharedObject,
};

struct ElfVirtualAddress {
  std::uint64_t value{};
};

struct ElfLoadBias {
  std::uint64_t value{};
};

struct ElfProgramHeader {
  std::uint32_t type{};
  std::uint32_t flags{};
  std::uint64_t fileOffset{};
  std::uint64_t virtualAddress{};
  std::uint64_t physicalAddress{};
  std::uint64_t fileSize{};
  std::uint64_t memorySize{};
  std::uint64_t alignment{};
};

struct ElfImageLayout {
  ElfClass imageClass{ElfClass::Bits64};
  ElfMachine machine{ElfMachine::X64};
  ElfImageType imageType{ElfImageType::Executable};
  std::uint64_t entryPoint{};
  std::uint64_t programHeaderOffset{};
  std::uint16_t programHeaderEntrySize{};
  std::uint16_t programHeaderCount{};
  std::uint64_t sectionHeaderOffset{};
  std::uint16_t sectionHeaderEntrySize{};
  std::uint16_t sectionHeaderCount{};
  std::uint32_t flags{};
  std::vector<ElfProgramHeader> programHeaders;

  [[nodiscard]] bool IsExecutableTarget() const noexcept {
    return imageType != ElfImageType::SharedObject;
  }
};

struct CapturedElfSegment {
  std::size_t programHeaderIndex{};
  std::vector<std::byte> fileBytes;
};

struct CapturedElfImage {
  ElfImageLayout layout;
  ElfLoadBias loadBias;
  std::vector<CapturedElfSegment> segments;
};

}  // namespace upx_killer::engine::elf
