#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"
#include "Core/ELF/OepDiscovery/UpxElfOepLocator.h"
#include "Core/ELF/Parsing/ElfParser.h"
#include "Core/ELF/SharedObjects/LoadedSharedObjectNormalizer.h"
#include "Core/ELF/SharedObjects/UpxSharedObjectLayoutRecoverer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

namespace {
template <typename T>
void Write(std::vector<std::byte>& bytes, std::size_t offset, T value) {
  for (std::size_t index = 0; index < sizeof(T); ++index)
    bytes[offset + index] =
        static_cast<std::byte>((value >> (index * 8)) & 0xff);
}

std::vector<std::byte> MakePackedSharedObject(bool is64Bit) {
  auto const addressWidth = is64Bit ? 8U : 4U;
  auto const headerSize = is64Bit ? 64U : 52U;
  auto const programHeaderSize = is64Bit ? 56U : 32U;
  std::vector<std::byte> bytes(0x3000);
  bytes[0] = std::byte{0x7f};
  bytes[1] = std::byte{'E'};
  bytes[2] = std::byte{'L'};
  bytes[3] = std::byte{'F'};
  bytes[4] = static_cast<std::byte>(is64Bit ? 2 : 1);
  bytes[5] = std::byte{1};
  bytes[6] = std::byte{1};
  Write<std::uint16_t>(bytes, 16, 3);
  Write<std::uint16_t>(bytes, 18, is64Bit ? 62 : 3);
  Write<std::uint32_t>(bytes, 20, 1);

  auto writeAddress = [&](std::size_t offset, std::uint64_t value) {
    if (addressWidth == 8)
      Write<std::uint64_t>(bytes, offset, value);
    else
      Write<std::uint32_t>(bytes, offset,
                           static_cast<std::uint32_t>(value));
  };
  auto const entryOffset = is64Bit ? 24U : 24U;
  auto const phOffsetOffset = is64Bit ? 32U : 28U;
  auto const headerSizeOffset = is64Bit ? 52U : 40U;
  auto const phEntrySizeOffset = is64Bit ? 54U : 42U;
  auto const phCountOffset = is64Bit ? 56U : 44U;
  writeAddress(entryOffset, 0x400);
  writeAddress(phOffsetOffset, headerSize);
  Write<std::uint16_t>(bytes, headerSizeOffset,
                       static_cast<std::uint16_t>(headerSize));
  Write<std::uint16_t>(bytes, phEntrySizeOffset,
                       static_cast<std::uint16_t>(programHeaderSize));
  Write<std::uint16_t>(bytes, phCountOffset, 5);

  auto writeProgramHeader = [&](std::size_t offset, std::uint32_t type,
                                std::uint32_t flags, std::uint64_t fileOffset,
                                std::uint64_t virtualAddress,
                                std::uint64_t fileSize,
                                std::uint64_t memorySize) {
    Write<std::uint32_t>(bytes, offset, type);
    if (is64Bit) {
      Write<std::uint32_t>(bytes, offset + 4, flags);
      writeAddress(offset + 8, fileOffset);
      writeAddress(offset + 16, virtualAddress);
      writeAddress(offset + 24, virtualAddress);
      writeAddress(offset + 32, fileSize);
      writeAddress(offset + 40, memorySize);
      writeAddress(offset + 48, 0x1000);
    } else {
      writeAddress(offset + 4, fileOffset);
      writeAddress(offset + 8, virtualAddress);
      writeAddress(offset + 12, virtualAddress);
      writeAddress(offset + 16, fileSize);
      writeAddress(offset + 20, memorySize);
      Write<std::uint32_t>(bytes, offset + 24, flags);
      writeAddress(offset + 28, 0x1000);
    }
  };

  writeProgramHeader(headerSize, 1, 5, 0, 0, 0x1000, 0x1000);
  writeProgramHeader(headerSize + programHeaderSize, 0, 5, 0x1000,
                     0x1000, 0x20, 0x20);
  writeProgramHeader(headerSize + 2 * programHeaderSize, 0, 4, 0x2000,
                     0x2000, 0x40, 0x40);
  writeProgramHeader(headerSize + 3 * programHeaderSize, 1, 6, 0x1f00,
                     0x3f00, 0x100, 0x100);
  writeProgramHeader(headerSize + 4 * programHeaderSize, 2, 6, 0x1f00,
                     0x3f00, is64Bit ? 64 : 32, is64Bit ? 64 : 32);

  auto const dynamicOffset = 0x1f00U;
  if (is64Bit) {
    Write<std::uint64_t>(bytes, dynamicOffset, 14);
    Write<std::uint64_t>(bytes, dynamicOffset + 8, 1);
    Write<std::uint64_t>(bytes, dynamicOffset + 16, 5);
    Write<std::uint64_t>(bytes, dynamicOffset + 24, 0x180);
    Write<std::uint64_t>(bytes, dynamicOffset + 32, 10);
    Write<std::uint64_t>(bytes, dynamicOffset + 40, 0x30);
    Write<std::uint64_t>(bytes, dynamicOffset + 48, 0);
  } else {
    Write<std::uint32_t>(bytes, dynamicOffset, 14);
    Write<std::uint32_t>(bytes, dynamicOffset + 4, 1);
    Write<std::uint32_t>(bytes, dynamicOffset + 8, 5);
    Write<std::uint32_t>(bytes, dynamicOffset + 12, 0x180);
    Write<std::uint32_t>(bytes, dynamicOffset + 16, 10);
    Write<std::uint32_t>(bytes, dynamicOffset + 20, 0x30);
    Write<std::uint32_t>(bytes, dynamicOffset + 24, 0);
  }
  bytes[0x400] = std::byte{0x90};
  bytes[0x2ff0] = std::byte{'U'};
  bytes[0x2ff1] = std::byte{'P'};
  bytes[0x2ff2] = std::byte{'X'};
  bytes[0x2ff3] = std::byte{'!'};
  return bytes;
}

std::uint64_t Read(std::vector<std::byte> const& bytes, std::size_t offset,
                   std::size_t width) {
  std::uint64_t value{};
  for (std::size_t index = 0; index < width; ++index)
    value |= static_cast<std::uint64_t>(
                 std::to_integer<std::uint8_t>(bytes[offset + index]))
             << (index * 8);
  return value;
}
}  // namespace

int RunElfSharedObjectTests() {
  using namespace upx_killer;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (condition) return;
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  };

  auto const manifest =
      engine::application::ElfBackendCapabilities::Manifest();
  for (auto const is64Bit : {false, true}) {
    auto source = MakePackedSharedObject(is64Bit);
    auto parsed = engine::elf::ElfParser::Parse(source);
    expect(parsed.layout &&
               parsed.layout->imageType == engine::elf::ElfImageType::SharedObject,
           is64Bit ? "ELF64 SO with a UPX stub entry remains a shared object"
                   : "ELF32 SO with a UPX stub entry remains a shared object");
    auto descriptor = parsed.layout
                          ? engine::application::ElfBackendCapabilities::
                                DescriptorFor(*parsed.layout)
                          : std::nullopt;
    expect(descriptor &&
               descriptor->imageKind == contracts::ImageKind::SharedLibrary &&
               descriptor->addressing ==
                   contracts::ImageAddressing::PositionIndependent &&
               std::find(manifest.capabilities.begin(),
                         manifest.capabilities.end(), *descriptor) !=
                   manifest.capabilities.end(),
           is64Bit ? "ELF64 SO has one exact production capability"
                   : "ELF32 SO has one exact production capability");
    auto discovery = parsed.layout
                         ? engine::elf::oep::UpxElfOepLocator::Analyze(
                               source, *parsed.layout)
                         : engine::elf::oep::ElfOepDiscoveryResult{};
    expect(discovery.plan.has_value(),
           is64Bit ? "ELF64 SO uses the class-neutral UPX evidence plan"
                   : "ELF32 SO uses the class-neutral UPX evidence plan");
    auto recovered = parsed.layout
                         ? engine::elf::shared_objects::
                               UpxSharedObjectLayoutRecoverer::Recover(
                                   source, *parsed.layout)
                         : engine::elf::shared_objects::
                               SharedObjectLayoutRecoveryResult{};
    expect(recovered.layout && recovered.layout->entryPoint == 0 &&
               std::count_if(recovered.layout->programHeaders.begin(),
                             recovered.layout->programHeaders.end(),
                             [](auto const& header) {
                               return header.type == 1;
                             }) == 4,
           is64Bit ? "ELF64 UPX SO layout restores four load segments"
                   : "ELF32 UPX SO layout restores four load segments");
    if (recovered.layout) {
      auto const width = is64Bit ? 8U : 4U;
      auto const dynamicFileOffset = 0x1f00U;
      auto runtimeDynamic = std::vector<std::byte>(
          source.begin() + dynamicFileOffset,
          source.begin() + dynamicFileOffset + (is64Bit ? 64U : 32U));
      auto const loadBias = is64Bit ? 0x7f0000000000ULL : 0x71000000ULL;
      Write(runtimeDynamic, width * 3,
            is64Bit ? loadBias + 0x180 : loadBias + 0x180);
      engine::elf::CapturedElfImage captured{
          *recovered.layout,
          {loadBias},
          {{3, std::move(runtimeDynamic)}}};
      auto normalized = engine::elf::shared_objects::
          LoadedSharedObjectNormalizer::Normalize(captured, *parsed.layout);
      expect(normalized.normalized &&
                 Read(captured.segments.front().fileBytes, width * 3, width) ==
                     0x180,
             is64Bit ? "ELF64 SO dynamic pointers are load-bias normalized"
                     : "ELF32 SO dynamic pointers are load-bias normalized");

      auto overflowing = captured;
      overflowing.layout.programHeaders.front().virtualAddress =
          std::numeric_limits<std::uint64_t>::max();
      overflowing.layout.programHeaders.front().memorySize = 2;
      auto rejected = engine::elf::shared_objects::
          LoadedSharedObjectNormalizer::Normalize(overflowing, *parsed.layout);
      expect(!rejected.normalized &&
                 rejected.detailCode ==
                     "elf.shared_object.load_range_overflow",
             is64Bit ? "ELF64 SO load-range overflow fails closed"
                     : "ELF32 SO load-range overflow fails closed");
    }
  }
  return failures;
}
