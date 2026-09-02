#include "Core/ELF/OepDiscovery/UpxElfOepLocator.h"
#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"
#include "Core/ELF/Reconstruction/ElfImageRebuilder.h"
#include "Core/ELF/Validation/ElfImageValidator.h"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
template <typename T>
void Write(std::vector<std::byte>& bytes, std::size_t offset, T value) {
  for (std::size_t index = 0; index < sizeof(T); ++index)
    bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xff);
}

std::vector<std::byte> MakeElf64(bool pie = false) {
  std::vector<std::byte> bytes(0x3000);
  bytes[0] = std::byte{0x7f};
  bytes[1] = std::byte{0x45};
  bytes[2] = std::byte{0x4c};
  bytes[3] = std::byte{0x46};
  bytes[4] = std::byte{2};
  bytes[5] = std::byte{1};
  bytes[6] = std::byte{1};
  Write<std::uint16_t>(bytes, 16, pie ? 3 : 2);
  Write<std::uint16_t>(bytes, 18, 62);
  Write<std::uint32_t>(bytes, 20, 1);
  auto const base = pie ? 0ull : 0x400000ull;
  Write<std::uint64_t>(bytes, 24, base + 0x1000);
  Write<std::uint64_t>(bytes, 32, 64);
  Write<std::uint16_t>(bytes, 52, 64);
  Write<std::uint16_t>(bytes, 54, 56);
  Write<std::uint16_t>(bytes, 56, 2);

  Write<std::uint32_t>(bytes, 64, 1);
  Write<std::uint32_t>(bytes, 68, 5);
  Write<std::uint64_t>(bytes, 72, 0);
  Write<std::uint64_t>(bytes, 80, base);
  Write<std::uint64_t>(bytes, 96, 0x2000);
  Write<std::uint64_t>(bytes, 104, 0x2000);
  Write<std::uint64_t>(bytes, 112, 0x1000);

  auto const second = 64 + 56;
  Write<std::uint32_t>(bytes, second, 1);
  Write<std::uint32_t>(bytes, second + 4, 6);
  Write<std::uint64_t>(bytes, second + 8, 0x2000);
  Write<std::uint64_t>(bytes, second + 16, base + 0x2000);
  Write<std::uint64_t>(bytes, second + 32, 0x1000);
  Write<std::uint64_t>(bytes, second + 40, 0x3000);
  Write<std::uint64_t>(bytes, second + 48, 0x1000);
  bytes[0x1000] = std::byte{0xc3};
  bytes[0x2500] = std::byte{0x42};
  return bytes;
}
}

int RunElfCoreTests() {
  using namespace upx_killer::engine::elf;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  auto source = MakeElf64();
  auto parsed = ElfParser::Parse(source);
  expect(parsed.layout.has_value(), "ELF64 x86-64 executable parses");
  expect(parsed.layout && parsed.layout->entryPoint == 0x401000,
         "ELF entry point is retained");
  auto descriptor = parsed.layout
                        ? upx_killer::engine::application::
                              ElfBackendCapabilities::DescriptorFor(
                                  *parsed.layout)
                        : std::nullopt;
  auto manifest =
      upx_killer::engine::application::ElfBackendCapabilities::Manifest();
  expect(descriptor &&
             descriptor->addressing ==
                 upx_killer::contracts::ImageAddressing::FixedAddress &&
             manifest.capabilities.size() == 4 &&
             std::find(manifest.capabilities.begin(), manifest.capabilities.end(),
                       *descriptor) != manifest.capabilities.end(),
         "ELF64 fixed-address descriptor has an exact manifest capability");
  auto pie = ElfParser::Parse(MakeElf64(true));
  expect(pie.layout &&
             pie.layout->imageType == ElfImageType::PositionIndependentExecutable,
         "ET_DYN with entry is classified as PIE");
  auto pieDescriptor = pie.layout
                           ? upx_killer::engine::application::
                                 ElfBackendCapabilities::DescriptorFor(*pie.layout)
                           : std::nullopt;
  expect(pieDescriptor &&
             pieDescriptor->addressing ==
                 upx_killer::contracts::ImageAddressing::PositionIndependent &&
             descriptor && *pieDescriptor != *descriptor,
         "ELF64 PIE and ET_EXEC expose distinct capabilities");

  auto structuralDiscovery =
      oep::UpxElfOepLocator::Analyze(source, *parsed.layout);
  expect(structuralDiscovery.plan &&
             structuralDiscovery.plan->hasStructuralEvidence,
         "sectionless sparse UPX layout survives marker changes");
  auto ordinary = source;
  Write<std::uint64_t>(ordinary, 40, 0x2800);
  Write<std::uint16_t>(ordinary, 58, 64);
  Write<std::uint16_t>(ordinary, 60, 1);
  auto ordinaryLayout = ElfParser::Parse(ordinary);
  expect(ordinaryLayout.layout &&
             !oep::UpxElfOepLocator::Analyze(ordinary,
                                             *ordinaryLayout.layout)
                  .plan,
         "ordinary sectioned ELF is not classified as modified UPX");

  auto invalid = source;
  invalid[4] = std::byte{3};
  expect(ElfParser::Parse(invalid).error == ElfParseError::UnsupportedClass,
         "unknown ELF class is rejected");

  source.resize(0x3100);
  source[0x3000] = std::byte{'U'};
  source[0x3001] = std::byte{'P'};
  source[0x3002] = std::byte{'X'};
  source[0x3003] = std::byte{'!'};
  auto discovery = oep::UpxElfOepLocator::Analyze(source, *parsed.layout);
  expect(discovery.plan && discovery.plan->hasUpxMarker,
         "UPX marker produces an ELF OEP discovery plan");

  CapturedElfImage captured{};
  captured.layout = *parsed.layout;
  captured.segments.push_back({0, {source.begin(), source.begin() + 0x2000}});
  captured.segments.push_back({1, {source.begin() + 0x2000,
                                   source.begin() + 0x3000}});
  auto rebuilt = ElfImageRebuilder::Rebuild(captured, 1ull << 20);
  expect(rebuilt.image.has_value(), "captured ELF segments rebuild");
  expect(rebuilt.image && ElfImageValidator::Validate(*rebuilt.image).valid,
         "rebuilt ELF validates");
  return failures;
}
