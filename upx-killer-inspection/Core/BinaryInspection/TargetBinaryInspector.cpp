#include "Core/BinaryInspection/TargetBinaryInspector.h"
#include "Core/BinaryInspection/Internal/UpxPackerDetector.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <span>
#include <system_error>
#include <vector>

namespace {
namespace contracts = upx_killer::contracts;
namespace inspection = upx_killer::core::binary_inspection::internal;

constexpr std::uint16_t PeMachineX86 = 0x014c;
constexpr std::uint16_t PeMachineX64 = 0x8664;
constexpr std::uint16_t PeOptionalMagic32 = 0x010b;
constexpr std::uint16_t PeOptionalMagic64 = 0x020b;
constexpr std::uint16_t PeCharacteristicDll = 0x2000;
constexpr std::uint32_t PeSectionMemExecute = 0x20000000;
constexpr std::size_t PeSectionHeaderSize = 40;
constexpr std::uint16_t MaximumPeSections = 96;

constexpr std::uint8_t ElfClass32 = 1;
constexpr std::uint8_t ElfClass64 = 2;
constexpr std::uint8_t ElfDataLittleEndian = 1;
constexpr std::uint16_t ElfTypeExecutable = 2;
constexpr std::uint16_t ElfTypeSharedObject = 3;
constexpr std::uint16_t ElfMachineX86 = 3;
constexpr std::uint16_t ElfMachineX64 = 62;
constexpr std::uint32_t ElfProgramTypeLoad = 1;
constexpr std::uint32_t ElfProgramTypeDynamic = 2;
constexpr std::uint32_t ElfProgramFlagExecute = 1;
constexpr std::uint32_t ElfProgramFlagWrite = 2;
constexpr std::uint16_t MaximumElfProgramHeaders = 128;
constexpr std::uint64_t ElfDynamicTagSoname = 14;

constexpr std::uint64_t InspectionWindowSize = 1024 * 1024;

struct ScanWindows {
  std::vector<std::byte> prefix;
  std::vector<std::byte> suffix;
};

bool ReadAt(std::ifstream& stream,
            std::uint64_t fileSize,
            std::uint64_t offset,
            void* destination,
            std::size_t length) noexcept {
  if (offset > fileSize || length > fileSize - offset ||
      offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
    return false;
  }

  stream.clear();
  stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!stream) return false;
  stream.read(static_cast<char*>(destination), static_cast<std::streamsize>(length));
  return stream.good() || stream.gcount() == static_cast<std::streamsize>(length);
}

std::optional<ScanWindows> ReadScanWindows(std::ifstream& stream,
                                           std::uint64_t fileSize) noexcept {
  try {
    ScanWindows windows;
    auto const prefixSize = static_cast<std::size_t>(std::min(fileSize, InspectionWindowSize));
    windows.prefix.resize(prefixSize);
    if (prefixSize != 0 && !ReadAt(stream, fileSize, 0, windows.prefix.data(), prefixSize))
      return std::nullopt;

    if (fileSize > InspectionWindowSize) {
      auto const suffixSize = static_cast<std::size_t>(std::min(fileSize, InspectionWindowSize));
      windows.suffix.resize(suffixSize);
      if (!ReadAt(stream, fileSize, fileSize - suffixSize, windows.suffix.data(), suffixSize))
        return std::nullopt;
    }
    return windows;
  } catch (...) {
    return std::nullopt;
  }
}

std::uint16_t ReadUInt16(std::uint8_t const* bytes, bool littleEndian = true) noexcept {
  if (littleEndian)
    return static_cast<std::uint16_t>(bytes[0]) |
           (static_cast<std::uint16_t>(bytes[1]) << 8);
  return (static_cast<std::uint16_t>(bytes[0]) << 8) |
         static_cast<std::uint16_t>(bytes[1]);
}

std::uint32_t ReadUInt32(std::uint8_t const* bytes, bool littleEndian = true) noexcept {
  std::uint32_t result{};
  for (std::size_t index = 0; index < 4; ++index) {
    auto const source = littleEndian ? index : 3 - index;
    result |= static_cast<std::uint32_t>(bytes[source]) << (index * 8);
  }
  return result;
}

std::uint64_t ReadUInt64(std::uint8_t const* bytes, bool littleEndian = true) noexcept {
  std::uint64_t result{};
  for (std::size_t index = 0; index < 8; ++index) {
    auto const source = littleEndian ? index : 7 - index;
    result |= static_cast<std::uint64_t>(bytes[source]) << (index * 8);
  }
  return result;
}

bool HasSectionName(std::array<std::uint8_t, PeSectionHeaderSize> const& section,
                    char const* name,
                    std::size_t length) noexcept {
  return std::equal(name, name + length, section.begin());
}

bool ContainsAddress(std::uint32_t address,
                     std::uint32_t start,
                     std::uint32_t virtualSize,
                     std::uint32_t rawSize) noexcept {
  auto const span = std::max(virtualSize, rawSize);
  return address >= start && static_cast<std::uint64_t>(address - start) < span;
}

upx_killer::core::InspectionResult InspectPe(std::ifstream& stream,
                                             std::filesystem::path const& path,
                                             std::uint64_t fileSize,
                                             ScanWindows const& windows) noexcept {
  using namespace upx_killer::core;

  std::array<std::uint8_t, 64> dosHeader{};
  if (!ReadAt(stream, fileSize, 0, dosHeader.data(), dosHeader.size()))
    return {std::nullopt, InspectionError::TruncatedFile};

  auto const peOffset = static_cast<std::uint64_t>(ReadUInt32(dosHeader.data() + 0x3c));
  std::array<std::uint8_t, 24> coffHeader{};
  if (!ReadAt(stream, fileSize, peOffset, coffHeader.data(), coffHeader.size()))
    return {std::nullopt, InspectionError::TruncatedFile};
  if (coffHeader[0] != 'P' || coffHeader[1] != 'E' || coffHeader[2] != 0 || coffHeader[3] != 0)
    return {std::nullopt, InspectionError::UnsupportedFormat};

  auto const machine = ReadUInt16(coffHeader.data() + 4);
  BinaryArchitecture architecture{};
  if (machine == PeMachineX86)
    architecture = BinaryArchitecture::X86;
  else if (machine == PeMachineX64)
    architecture = BinaryArchitecture::X64;
  else
    return {std::nullopt, InspectionError::UnsupportedArchitecture};

  auto const sectionCount = ReadUInt16(coffHeader.data() + 6);
  auto const optionalHeaderSize = ReadUInt16(coffHeader.data() + 20);
  if (sectionCount == 0 || sectionCount > MaximumPeSections || optionalHeaderSize < 20)
    return {std::nullopt, InspectionError::TruncatedFile};

  std::array<std::uint8_t, 20> optionalHeaderPrefix{};
  auto const optionalHeaderOffset = peOffset + coffHeader.size();
  if (!ReadAt(stream, fileSize, optionalHeaderOffset, optionalHeaderPrefix.data(),
              optionalHeaderPrefix.size()))
    return {std::nullopt, InspectionError::TruncatedFile};

  auto const optionalMagic = ReadUInt16(optionalHeaderPrefix.data());
  auto const entryPoint = ReadUInt32(optionalHeaderPrefix.data() + 16);
  auto const characteristics = ReadUInt16(coffHeader.data() + 22);
  auto const isLibrary = (characteristics & PeCharacteristicDll) != 0;
  BinaryFormat format{};
  if (optionalMagic == PeOptionalMagic32 && machine == PeMachineX86)
    format = isLibrary ? BinaryFormat::Pe32Library : BinaryFormat::Pe32Executable;
  else if (optionalMagic == PeOptionalMagic64 && machine == PeMachineX64)
    format = isLibrary ? BinaryFormat::Pe32PlusLibrary : BinaryFormat::Pe32PlusExecutable;
  else
    return {std::nullopt, InspectionError::UnsupportedFormat};

  auto const sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;
  bool hasUpx0{};
  bool hasUpx1{};
  bool hasSparseDestination{};
  bool entryInPackedExecutableSection{};
  std::uint32_t largestSparseDestination{};
  std::uint32_t packedEntryRawSize{};
  for (std::uint16_t index = 0; index < sectionCount; ++index) {
    auto const sectionOffset = sectionTableOffset +
                               static_cast<std::uint64_t>(index) * PeSectionHeaderSize;
    std::array<std::uint8_t, PeSectionHeaderSize> section{};
    if (!ReadAt(stream, fileSize, sectionOffset, section.data(), section.size()))
      return {std::nullopt, InspectionError::TruncatedFile};

    hasUpx0 = hasUpx0 || HasSectionName(section, "UPX0", 4);
    hasUpx1 = hasUpx1 || HasSectionName(section, "UPX1", 4);
    auto const virtualSize = ReadUInt32(section.data() + 8);
    auto const virtualAddress = ReadUInt32(section.data() + 12);
    auto const rawSize = ReadUInt32(section.data() + 16);
    auto const sectionCharacteristics = ReadUInt32(section.data() + 36);
    // Markerless detection must be deliberately conservative: ordinary PE files
    // commonly have a small zero-backed .bss section. UPX's unpack destination is
    // a materially larger zero-backed region followed by the packed entry section.
    auto const sparseDestination = virtualSize >= 0x10000 && rawSize == 0 &&
                                   virtualAddress < entryPoint;
    hasSparseDestination = hasSparseDestination || sparseDestination;
    if (sparseDestination) largestSparseDestination = std::max(largestSparseDestination, virtualSize);
    auto const packedEntry = rawSize != 0 &&
                             (sectionCharacteristics & PeSectionMemExecute) != 0 &&
                             ContainsAddress(entryPoint, virtualAddress, virtualSize, rawSize);
    entryInPackedExecutableSection = entryInPackedExecutableSection || packedEntry;
    if (packedEntry) packedEntryRawSize = std::max(packedEntryRawSize, rawSize);
  }

  auto const packerInformation = inspection::UpxPackerDetector::Analyze(
      windows.prefix, windows.suffix,
      {inspection::ContainerFormat::Pe, hasUpx0 && hasUpx1,
       sectionCount <= 4 && hasSparseDestination && entryInPackedExecutableSection &&
           largestSparseDestination > packedEntryRawSize});
  auto const descriptor = contracts::TargetDescriptor{
      contracts::BinaryFamily::Pe,
      optionalMagic == PeOptionalMagic32 ? contracts::BinaryClass::Bits32
                                         : contracts::BinaryClass::Bits64,
      architecture == BinaryArchitecture::X86 ? contracts::CpuArchitecture::X86
                                               : contracts::CpuArchitecture::X64,
      isLibrary ? contracts::ImageKind::SharedLibrary : contracts::ImageKind::Executable};
  return {TargetBinaryInfo{path, fileSize, format, architecture, descriptor, packerInformation},
          InspectionError::None};
}

upx_killer::core::InspectionResult InspectElf(std::ifstream& stream,
                                              std::filesystem::path const& path,
                                              std::uint64_t fileSize,
                                              ScanWindows const& windows) noexcept {
  using namespace upx_killer::core;

  std::array<std::uint8_t, 64> header{};
  if (!ReadAt(stream, fileSize, 0, header.data(), 52))
    return {std::nullopt, InspectionError::TruncatedFile};

  auto const elfClass = header[4];
  auto const dataEncoding = header[5];
  if ((elfClass != ElfClass32 && elfClass != ElfClass64) ||
      dataEncoding != ElfDataLittleEndian)
    return {std::nullopt, InspectionError::UnsupportedFormat};
  if (elfClass == ElfClass64 && !ReadAt(stream, fileSize, 0, header.data(), header.size()))
    return {std::nullopt, InspectionError::TruncatedFile};

  auto const objectType = ReadUInt16(header.data() + 16);
  auto const machine = ReadUInt16(header.data() + 18);
  BinaryArchitecture architecture{};
  if (machine == ElfMachineX86)
    architecture = BinaryArchitecture::X86;
  else if (machine == ElfMachineX64)
    architecture = BinaryArchitecture::X64;
  else
    return {std::nullopt, InspectionError::UnsupportedArchitecture};

  auto const entryPoint = elfClass == ElfClass64 ? ReadUInt64(header.data() + 24)
                                                  : ReadUInt32(header.data() + 24);
  if (objectType != ElfTypeExecutable && objectType != ElfTypeSharedObject)
    return {std::nullopt, InspectionError::UnsupportedFormat};

  auto const programHeaderOffset = elfClass == ElfClass64 ? ReadUInt64(header.data() + 32)
                                                           : ReadUInt32(header.data() + 28);
  auto const sectionHeaderOffset = elfClass == ElfClass64 ? ReadUInt64(header.data() + 40)
                                                           : ReadUInt32(header.data() + 32);
  auto const programHeaderSize = ReadUInt16(header.data() + (elfClass == ElfClass64 ? 54 : 42));
  auto const programHeaderCount = ReadUInt16(header.data() + (elfClass == ElfClass64 ? 56 : 44));
  auto const sectionHeaderCount = ReadUInt16(header.data() + (elfClass == ElfClass64 ? 60 : 48));
  auto const requiredProgramHeaderSize = elfClass == ElfClass64 ? 56u : 32u;
  if (programHeaderCount > MaximumElfProgramHeaders ||
      (programHeaderCount != 0 && programHeaderSize < requiredProgramHeaderSize))
    return {std::nullopt, InspectionError::TruncatedFile};

  std::size_t loadCount{};
  bool entryInExecutableLoad{};
  bool sparseWritableLoad{};
  std::optional<std::pair<std::uint64_t, std::uint64_t>> dynamicRange;
  for (std::uint16_t index = 0; index < programHeaderCount; ++index) {
    auto const offset = programHeaderOffset +
                        static_cast<std::uint64_t>(index) * programHeaderSize;
    std::array<std::uint8_t, 56> programHeader{};
    if (!ReadAt(stream, fileSize, offset, programHeader.data(), requiredProgramHeaderSize))
      return {std::nullopt, InspectionError::TruncatedFile};
    auto const programType = ReadUInt32(programHeader.data());
    auto const programFileOffset =
        elfClass == ElfClass64 ? ReadUInt64(programHeader.data() + 8)
                               : ReadUInt32(programHeader.data() + 4);
    auto const programFileSize =
        elfClass == ElfClass64 ? ReadUInt64(programHeader.data() + 32)
                               : ReadUInt32(programHeader.data() + 16);
    if (programType == ElfProgramTypeDynamic)
      dynamicRange = std::pair{programFileOffset, programFileSize};
    if (programType != ElfProgramTypeLoad) continue;

    ++loadCount;
    auto const flags = ReadUInt32(programHeader.data() + (elfClass == ElfClass64 ? 4 : 24));
    auto const virtualAddress = elfClass == ElfClass64 ? ReadUInt64(programHeader.data() + 16)
                                                       : ReadUInt32(programHeader.data() + 8);
    auto const fileBytes = elfClass == ElfClass64 ? ReadUInt64(programHeader.data() + 32)
                                                   : ReadUInt32(programHeader.data() + 16);
    auto const memoryBytes = elfClass == ElfClass64 ? ReadUInt64(programHeader.data() + 40)
                                                     : ReadUInt32(programHeader.data() + 20);
    if ((flags & ElfProgramFlagWrite) != 0 && memoryBytes > fileBytes &&
        memoryBytes - fileBytes > 0x1000)
      sparseWritableLoad = true;
    if ((flags & ElfProgramFlagExecute) != 0 && entryPoint >= virtualAddress &&
        entryPoint - virtualAddress < memoryBytes)
      entryInExecutableLoad = true;
  }

  bool hasSoname{};
  if (dynamicRange) {
    auto const entrySize = elfClass == ElfClass64 ? 16U : 8U;
    auto const wordSize = elfClass == ElfClass64 ? 8U : 4U;
    if (dynamicRange->first <= fileSize &&
        dynamicRange->second <= fileSize - dynamicRange->first &&
        dynamicRange->second <= InspectionWindowSize &&
        dynamicRange->second % entrySize == 0) {
      std::array<std::uint8_t, 16> entry{};
      for (std::uint64_t cursor = 0; cursor < dynamicRange->second;
           cursor += entrySize) {
        if (!ReadAt(stream, fileSize, dynamicRange->first + cursor,
                    entry.data(), entrySize))
          break;
        auto const tag = wordSize == 8 ? ReadUInt64(entry.data())
                                       : ReadUInt32(entry.data());
        if (tag == 0) break;
        if (tag == ElfDynamicTagSoname) {
          hasSoname = true;
          break;
        }
      }
    }
  }
  auto const sharedObject = objectType == ElfTypeSharedObject &&
                            (entryPoint == 0 || hasSoname);
  auto const executable = objectType == ElfTypeExecutable ||
                          (objectType == ElfTypeSharedObject && !sharedObject &&
                           entryPoint != 0);

  BinaryFormat format{};
  if (elfClass == ElfClass32)
    format = executable ? BinaryFormat::Elf32Executable : BinaryFormat::Elf32SharedObject;
  else
    format = executable ? BinaryFormat::Elf64Executable : BinaryFormat::Elf64SharedObject;

  auto const canonicalPackedLayout = loadCount == 2 && entryInExecutableLoad &&
                                     sparseWritableLoad && sectionHeaderOffset == 0 &&
                                     sectionHeaderCount == 0;
  auto const packerInformation = inspection::UpxPackerDetector::Analyze(
      windows.prefix, windows.suffix,
      {inspection::ContainerFormat::Elf, false, canonicalPackedLayout});
  auto const descriptor = contracts::TargetDescriptor{
      contracts::BinaryFamily::Elf,
      elfClass == ElfClass32 ? contracts::BinaryClass::Bits32 : contracts::BinaryClass::Bits64,
      architecture == BinaryArchitecture::X86 ? contracts::CpuArchitecture::X86
                                               : contracts::CpuArchitecture::X64,
      executable ? contracts::ImageKind::Executable : contracts::ImageKind::SharedLibrary,
      objectType == ElfTypeExecutable
          ? contracts::ImageAddressing::FixedAddress
          : contracts::ImageAddressing::PositionIndependent};
  return {TargetBinaryInfo{path, fileSize, format, architecture, descriptor, packerInformation},
          InspectionError::None};
}
}  // namespace

namespace upx_killer::core {
InspectionResult TargetBinaryInspector::Inspect(std::filesystem::path const& path) noexcept {
  std::error_code errorCode;
  if (!std::filesystem::exists(path, errorCode))
    return {std::nullopt, errorCode ? InspectionError::IoFailure : InspectionError::FileNotFound};

  auto const fileSize = std::filesystem::file_size(path, errorCode);
  if (errorCode)
    return {std::nullopt, errorCode == std::errc::permission_denied
                              ? InspectionError::AccessDenied
                              : InspectionError::IoFailure};

  std::ifstream stream(path, std::ios::binary);
  if (!stream) return {std::nullopt, InspectionError::AccessDenied};

  std::array<std::uint8_t, 4> signature{};
  if (!ReadAt(stream, fileSize, 0, signature.data(), signature.size()))
    return {std::nullopt, InspectionError::TruncatedFile};
  auto windows = ReadScanWindows(stream, fileSize);
  if (!windows) return {std::nullopt, InspectionError::IoFailure};

  if (signature[0] == 'M' && signature[1] == 'Z')
    return InspectPe(stream, path, fileSize, *windows);
  if (signature[0] == 0x7f && signature[1] == 'E' && signature[2] == 'L' &&
      signature[3] == 'F')
    return InspectElf(stream, path, fileSize, *windows);
  return {std::nullopt, InspectionError::UnsupportedFormat};
}
}  // namespace upx_killer::core
