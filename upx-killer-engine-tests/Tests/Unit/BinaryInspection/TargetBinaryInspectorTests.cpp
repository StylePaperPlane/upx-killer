#include "Core/BinaryInspection/TargetBinaryInspector.h"

#include <Windows.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
using upx_killer::core::TargetBinaryInspector;
using upx_killer::core::UpxPackingAssessment;

class TemporaryBinary final {
 public:
  explicit TemporaryBinary(std::span<std::byte const> bytes) {
    auto const nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    path_ = std::filesystem::temp_directory_path() /
            (L"upx-killer-inspection-" + std::to_wstring(nonce) + L".bin");
    std::ofstream stream(path_, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<char const*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("failed to create inspection fixture");
  }

  ~TemporaryBinary() {
    std::error_code ignored;
    std::filesystem::remove(path_, ignored);
  }

  TemporaryBinary(TemporaryBinary const&) = delete;
  TemporaryBinary& operator=(TemporaryBinary const&) = delete;
  [[nodiscard]] std::filesystem::path const& Path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

std::vector<std::byte> MakePe(bool canonicalNames, bool packedLayout, bool packHeader) {
  std::vector<std::byte> bytes(0x800);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x80;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(bytes.data() + 0x80);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt->FileHeader.NumberOfSections = 2;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt->OptionalHeader.AddressOfEntryPoint = 0x2000;
  nt->OptionalHeader.ImageBase = 0x400000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x3000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;

  auto* sections = IMAGE_FIRST_SECTION(nt);
  std::memcpy(sections[0].Name, canonicalNames ? "UPX0" : "AAAA", 4);
  sections[0].Misc.VirtualSize = packedLayout ? 0x20000 : 0x1000;
  sections[0].VirtualAddress = 0x1000;
  sections[0].SizeOfRawData = packedLayout ? 0 : 0x200;
  sections[0].PointerToRawData = packedLayout ? 0 : 0x200;
  sections[0].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
  std::memcpy(sections[1].Name, canonicalNames ? "UPX1" : ".text", 4);
  sections[1].Misc.VirtualSize = 0x1000;
  sections[1].VirtualAddress = 0x2000;
  sections[1].SizeOfRawData = 0x200;
  sections[1].PointerToRawData = 0x400;
  sections[1].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

  if (packHeader) {
    constexpr std::uint8_t header[]{'U', 'P', 'X', '!', 13, 9, 8, 7};
    std::memcpy(bytes.data() + 0x1e0, header, sizeof(header));
  }
  return bytes;
}

void Write16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::byte>(value & 0xff);
  bytes[offset + 1] = static_cast<std::byte>((value >> 8) & 0xff);
}

void Write32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index)
    bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xff);
}

void Write64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index)
    bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xff);
}

std::vector<std::byte> MakeElf64(bool officialBanner) {
  std::vector<std::byte> bytes(0x2000);
  constexpr std::uint8_t identity[]{0x7f, 'E', 'L', 'F', 2, 1, 1};
  std::memcpy(bytes.data(), identity, sizeof(identity));
  Write16(bytes, 16, 3);
  Write16(bytes, 18, 62);
  Write64(bytes, 24, 0x62e8);
  Write64(bytes, 32, 64);
  Write64(bytes, 40, 0);
  Write16(bytes, 52, 64);
  Write16(bytes, 54, 56);
  Write16(bytes, 56, 2);
  Write16(bytes, 58, 0);
  Write16(bytes, 60, 0);

  auto const first = 64u;
  Write32(bytes, first, 1);
  Write32(bytes, first + 4, 6);
  Write64(bytes, first + 8, 0);
  Write64(bytes, first + 16, 0);
  Write64(bytes, first + 32, 0x1000);
  Write64(bytes, first + 40, 0x40e8);
  auto const second = first + 56;
  Write32(bytes, second, 1);
  Write32(bytes, second + 4, 5);
  Write64(bytes, second + 8, 0x1000);
  Write64(bytes, second + 16, 0x5000);
  Write64(bytes, second + 32, 0x1000);
  Write64(bytes, second + 40, 0x1db5);

  if (officialBanner) {
    constexpr std::string_view banner =
        "UPX executable packer http://upx.sf.net $ UPX 4.22 Copyright (C) 1996-2024";
    std::memcpy(bytes.data() + 0x1200, banner.data(), banner.size());
  }
  return bytes;
}
}  // namespace

int RunBinaryInspectionTests() {
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  {
    TemporaryBinary target{MakePe(true, true, true)};
    auto const result = TargetBinaryInspector::Inspect(target.Path());
    expect(result.Succeeded(), "standard UPX-like PE parses");
    expect(result.info && result.info->packerInformation.assessment ==
                              UpxPackingAssessment::LikelyStandard,
           "canonical PE layout and PackHeader are standard UPX evidence");
    expect(result.info && result.info->packerInformation.packHeaderVersion == 13,
           "UPX PackHeader version is preserved separately from release version");
  }
  {
    TemporaryBinary target{MakePe(false, true, true)};
    auto const result = TargetBinaryInspector::Inspect(target.Path());
    expect(result.info && result.info->packerInformation.assessment ==
                              UpxPackingAssessment::LikelyModified,
           "renamed packed PE sections are reported as possibly modified");
  }
  {
    TemporaryBinary target{MakePe(false, true, false)};
    auto const result = TargetBinaryInspector::Inspect(target.Path());
    expect(result.info && result.info->packerInformation.assessment ==
                              UpxPackingAssessment::LikelyModified,
           "structural packed PE evidence survives a stripped UPX marker");
  }
  {
    TemporaryBinary target{MakePe(false, false, false)};
    auto const result = TargetBinaryInspector::Inspect(target.Path());
    expect(result.info && result.info->packerInformation.assessment ==
                              UpxPackingAssessment::NotDetected,
           "ordinary PE layout is not labeled as UPX");
  }
  {
    auto bytes = MakePe(false, true, false);
    reinterpret_cast<IMAGE_NT_HEADERS32*>(bytes.data() + 0x80)->FileHeader.NumberOfSections = 5;
    TemporaryBinary target{bytes};
    auto const result = TargetBinaryInspector::Inspect(target.Path());
    expect(result.info && result.info->packerInformation.assessment ==
                              UpxPackingAssessment::NotDetected,
           "a multi-section PE with large zero-backed data is not treated as markerless UPX");
  }
  {
    TemporaryBinary target{MakeElf64(true)};
    auto const result = TargetBinaryInspector::Inspect(target.Path());
    expect(result.info && result.info->packerInformation.assessment ==
                              UpxPackingAssessment::LikelyStandard,
           "canonical ELF stub banner is standard UPX evidence");
    expect(result.info && result.info->packerInformation.releaseVersion == "4.22",
           "ELF UPX release version is extracted from the official stub banner");
  }
  {
    TemporaryBinary target{MakeElf64(false)};
    auto const result = TargetBinaryInspector::Inspect(target.Path());
    expect(result.info && result.info->packerInformation.assessment ==
                              UpxPackingAssessment::LikelyModified,
           "bannerless canonical packed ELF is reported as possibly modified");
  }
  return failures;
}
