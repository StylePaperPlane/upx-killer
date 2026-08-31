#include "pch.h"
#include "Core/BinaryInspection/TargetBinaryInspector.h"

#include <array>
#include <fstream>
#include <system_error>

namespace {
namespace contracts = upx_killer::contracts;

constexpr std::uint16_t PeMachineX86 = 0x014c;
constexpr std::uint16_t PeMachineX64 = 0x8664;
constexpr std::uint16_t PeOptionalMagic32 = 0x010b;
constexpr std::uint16_t PeOptionalMagic64 = 0x020b;
constexpr std::uint16_t PeCharacteristicDll = 0x2000;

constexpr std::uint8_t ElfClass32 = 1;
constexpr std::uint8_t ElfClass64 = 2;
constexpr std::uint8_t ElfDataLittleEndian = 1;
constexpr std::uint16_t ElfTypeExecutable = 2;
constexpr std::uint16_t ElfTypeSharedObject = 3;
constexpr std::uint16_t ElfMachineX86 = 3;
constexpr std::uint16_t ElfMachineX64 = 62;

bool ReadAt(std::ifstream& stream, std::uint64_t fileSize, std::uint64_t offset, void* destination,
            std::size_t length) noexcept {
  if (offset > fileSize || length > fileSize - offset) {
    return false;
  }

  stream.clear();
  stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!stream) {
    return false;
  }

  stream.read(static_cast<char*>(destination), static_cast<std::streamsize>(length));
  return stream.good() || stream.gcount() == static_cast<std::streamsize>(length);
}

std::uint16_t ReadUInt16(std::uint8_t const* bytes, bool littleEndian) noexcept {
  if (littleEndian) {
    return static_cast<std::uint16_t>(bytes[0]) | static_cast<std::uint16_t>(bytes[1] << 8);
  }

  return static_cast<std::uint16_t>(bytes[0] << 8) | static_cast<std::uint16_t>(bytes[1]);
}

std::uint32_t ReadUInt32LittleEndian(std::uint8_t const* bytes) noexcept {
  return static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8) |
         (static_cast<std::uint32_t>(bytes[2]) << 16) |
         (static_cast<std::uint32_t>(bytes[3]) << 24);
}

std::uint32_t ReadUInt32(std::uint8_t const* bytes,
                         bool littleEndian) noexcept {
  std::uint32_t result{};
  for (std::size_t index = 0; index < 4; ++index) {
    auto const source = littleEndian ? index : 3 - index;
    result |= static_cast<std::uint32_t>(bytes[source]) << (index * 8);
  }
  return result;
}

std::uint64_t ReadUInt64(std::uint8_t const* bytes,
                         bool littleEndian) noexcept {
  std::uint64_t result{};
  for (std::size_t index = 0; index < 8; ++index) {
    auto const source = littleEndian ? index : 7 - index;
    result |= static_cast<std::uint64_t>(bytes[source]) << (index * 8);
  }
  return result;
}

upx_killer::core::InspectionResult InspectPe(std::ifstream& stream,
                                             std::filesystem::path const& path,
                                             std::uint64_t fileSize) noexcept {
  using namespace upx_killer::core;

  std::array<std::uint8_t, 64> dosHeader{};
  if (!ReadAt(stream, fileSize, 0, dosHeader.data(), dosHeader.size())) {
    return {std::nullopt, InspectionError::TruncatedFile};
  }

  auto const peOffset = static_cast<std::uint64_t>(ReadUInt32LittleEndian(dosHeader.data() + 0x3c));
  std::array<std::uint8_t, 24> coffHeader{};
  if (!ReadAt(stream, fileSize, peOffset, coffHeader.data(), coffHeader.size())) {
    return {std::nullopt, InspectionError::TruncatedFile};
  }

  if (coffHeader[0] != 'P' || coffHeader[1] != 'E' || coffHeader[2] != 0 || coffHeader[3] != 0) {
    return {std::nullopt, InspectionError::UnsupportedFormat};
  }

  auto const machine = ReadUInt16(coffHeader.data() + 4, true);
  BinaryArchitecture architecture{};
  if (machine == PeMachineX86) {
    architecture = BinaryArchitecture::X86;
  } else if (machine == PeMachineX64) {
    architecture = BinaryArchitecture::X64;
  } else {
    return {std::nullopt, InspectionError::UnsupportedArchitecture};
  }

  auto const optionalHeaderSize = ReadUInt16(coffHeader.data() + 20, true);
  if (optionalHeaderSize < sizeof(std::uint16_t)) {
    return {std::nullopt, InspectionError::TruncatedFile};
  }

  std::array<std::uint8_t, 2> optionalMagicBytes{};
  if (!ReadAt(stream, fileSize, peOffset + coffHeader.size(), optionalMagicBytes.data(),
              optionalMagicBytes.size())) {
    return {std::nullopt, InspectionError::TruncatedFile};
  }

  auto const optionalMagic = ReadUInt16(optionalMagicBytes.data(), true);
  auto const characteristics = ReadUInt16(coffHeader.data() + 22, true);
  auto const isLibrary = (characteristics & PeCharacteristicDll) != 0;
  BinaryFormat format{};

  if (optionalMagic == PeOptionalMagic32) {
    format = isLibrary ? BinaryFormat::Pe32Library : BinaryFormat::Pe32Executable;
  } else if (optionalMagic == PeOptionalMagic64) {
    format = isLibrary ? BinaryFormat::Pe32PlusLibrary : BinaryFormat::Pe32PlusExecutable;
  } else {
    return {std::nullopt, InspectionError::UnsupportedFormat};
  }

  auto const descriptor = contracts::TargetDescriptor{
      contracts::BinaryFamily::Pe,
      optionalMagic == PeOptionalMagic32 ? contracts::BinaryClass::Bits32
                                         : contracts::BinaryClass::Bits64,
      architecture == BinaryArchitecture::X86 ? contracts::CpuArchitecture::X86
                                               : contracts::CpuArchitecture::X64,
      isLibrary ? contracts::ImageKind::SharedLibrary
                : contracts::ImageKind::Executable};
  return {TargetBinaryInfo{path, fileSize, format, architecture, descriptor},
          InspectionError::None};
}

upx_killer::core::InspectionResult InspectElf(std::ifstream& stream,
                                              std::filesystem::path const& path,
                                              std::uint64_t fileSize) noexcept {
  using namespace upx_killer::core;

  std::array<std::uint8_t, 32> header{};
  if (!ReadAt(stream, fileSize, 0, header.data(), header.size())) {
    return {std::nullopt, InspectionError::TruncatedFile};
  }

  auto const elfClass = header[4];
  auto const dataEncoding = header[5];
  if ((elfClass != ElfClass32 && elfClass != ElfClass64) ||
      dataEncoding != ElfDataLittleEndian) {
    return {std::nullopt, InspectionError::UnsupportedFormat};
  }

  constexpr bool littleEndian = true;
  auto const objectType = ReadUInt16(header.data() + 16, littleEndian);
  auto const machine = ReadUInt16(header.data() + 18, littleEndian);

  BinaryArchitecture architecture{};
  if (machine == ElfMachineX86) {
    architecture = BinaryArchitecture::X86;
  } else if (machine == ElfMachineX64) {
    architecture = BinaryArchitecture::X64;
  } else {
    return {std::nullopt, InspectionError::UnsupportedArchitecture};
  }

  auto const entryPoint = elfClass == ElfClass64
                              ? ReadUInt64(header.data() + 24, littleEndian)
                              : ReadUInt32(header.data() + 24, littleEndian);
  auto const executable = objectType == ElfTypeExecutable ||
                          (objectType == ElfTypeSharedObject && entryPoint != 0);
  auto const sharedObject = objectType == ElfTypeSharedObject && entryPoint == 0;
  if (!executable && !sharedObject) {
    return {std::nullopt, InspectionError::UnsupportedFormat};
  }

  BinaryFormat format{};
  if (elfClass == ElfClass32) {
    format = executable ? BinaryFormat::Elf32Executable : BinaryFormat::Elf32SharedObject;
  } else {
    format = executable ? BinaryFormat::Elf64Executable : BinaryFormat::Elf64SharedObject;
  }

  auto const descriptor = contracts::TargetDescriptor{
      contracts::BinaryFamily::Elf,
      elfClass == ElfClass32 ? contracts::BinaryClass::Bits32
                             : contracts::BinaryClass::Bits64,
      architecture == BinaryArchitecture::X86 ? contracts::CpuArchitecture::X86
                                               : contracts::CpuArchitecture::X64,
      executable ? contracts::ImageKind::Executable
                 : contracts::ImageKind::SharedLibrary};
  return {TargetBinaryInfo{path, fileSize, format, architecture, descriptor},
          InspectionError::None};
}
}

namespace upx_killer::core {
InspectionResult TargetBinaryInspector::Inspect(std::filesystem::path const& path) noexcept {
  std::error_code errorCode;
  if (!std::filesystem::exists(path, errorCode)) {
    return {std::nullopt, errorCode ? InspectionError::IoFailure : InspectionError::FileNotFound};
  }

  auto const fileSize = std::filesystem::file_size(path, errorCode);
  if (errorCode) {
    return {std::nullopt, errorCode == std::errc::permission_denied ? InspectionError::AccessDenied
                                                                    : InspectionError::IoFailure};
  }

  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {std::nullopt, InspectionError::AccessDenied};
  }

  std::array<std::uint8_t, 4> signature{};
  if (!ReadAt(stream, fileSize, 0, signature.data(), signature.size())) {
    return {std::nullopt, InspectionError::TruncatedFile};
  }

  if (signature[0] == 'M' && signature[1] == 'Z') {
    return InspectPe(stream, path, fileSize);
  }

  if (signature[0] == 0x7f && signature[1] == 'E' && signature[2] == 'L' && signature[3] == 'F') {
    return InspectElf(stream, path, fileSize);
  }

  return {std::nullopt, InspectionError::UnsupportedFormat};
}
}
