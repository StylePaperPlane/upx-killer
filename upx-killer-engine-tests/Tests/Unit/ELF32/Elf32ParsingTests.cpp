#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"
#include "Core/ELF/OepDiscovery/UpxElfOepLocator.h"
#include "Core/ELF/Parsing/ElfParser.h"
#include "Core/ELF/Reconstruction/ElfImageRebuilder.h"
#include "Core/ELF/Validation/ElfImageValidator.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
template <typename T>
void Write(std::vector<std::byte>& bytes, std::size_t offset, T value) {
  for (std::size_t index = 0; index < sizeof(T); ++index) {
    bytes[offset + index] =
        static_cast<std::byte>((value >> (index * 8)) & 0xff);
  }
}

std::vector<std::byte> MakeElf32() {
  std::vector<std::byte> bytes(0x3000);
  bytes[0] = std::byte{0x7f};
  bytes[1] = std::byte{'E'};
  bytes[2] = std::byte{'L'};
  bytes[3] = std::byte{'F'};
  bytes[4] = std::byte{1};
  bytes[5] = std::byte{1};
  bytes[6] = std::byte{1};
  Write<std::uint16_t>(bytes, 16, 2);
  Write<std::uint16_t>(bytes, 18, 3);
  Write<std::uint32_t>(bytes, 20, 1);
  Write<std::uint32_t>(bytes, 24, 0x08049000);
  Write<std::uint32_t>(bytes, 28, 52);
  Write<std::uint16_t>(bytes, 40, 52);
  Write<std::uint16_t>(bytes, 42, 32);
  Write<std::uint16_t>(bytes, 44, 3);

  Write<std::uint32_t>(bytes, 52, 1);
  Write<std::uint32_t>(bytes, 56, 0);
  Write<std::uint32_t>(bytes, 60, 0x08048000);
  Write<std::uint32_t>(bytes, 64, 0x08048000);
  Write<std::uint32_t>(bytes, 68, 0x2000);
  Write<std::uint32_t>(bytes, 72, 0x2000);
  Write<std::uint32_t>(bytes, 76, 5);
  Write<std::uint32_t>(bytes, 80, 0x1000);

  constexpr std::size_t second = 52 + 32;
  Write<std::uint32_t>(bytes, second, 1);
  Write<std::uint32_t>(bytes, second + 4, 0x2000);
  Write<std::uint32_t>(bytes, second + 8, 0x0804a000);
  Write<std::uint32_t>(bytes, second + 12, 0x0804a000);
  Write<std::uint32_t>(bytes, second + 16, 0x1000);
  Write<std::uint32_t>(bytes, second + 20, 0x1000);
  Write<std::uint32_t>(bytes, second + 24, 6);
  Write<std::uint32_t>(bytes, second + 28, 0x1000);

  constexpr std::size_t dynamicHeader = second + 32;
  Write<std::uint32_t>(bytes, dynamicHeader, 2);
  Write<std::uint32_t>(bytes, dynamicHeader + 4, 0x2500);
  Write<std::uint32_t>(bytes, dynamicHeader + 8, 0x0804a500);
  Write<std::uint32_t>(bytes, dynamicHeader + 12, 0x0804a500);
  Write<std::uint32_t>(bytes, dynamicHeader + 16, 64);
  Write<std::uint32_t>(bytes, dynamicHeader + 20, 64);
  Write<std::uint32_t>(bytes, dynamicHeader + 24, 6);
  Write<std::uint32_t>(bytes, dynamicHeader + 28, 4);

  auto writeDynamic = [&](std::size_t index, std::uint32_t tag,
                          std::uint32_t value) {
    auto const offset = 0x2500 + index * 8;
    Write(bytes, offset, tag);
    Write(bytes, offset + 4, value);
  };
  writeDynamic(0, 5, 0x0804a200);
  writeDynamic(1, 6, 0x0804a100);
  writeDynamic(2, 10, 0x20);
  writeDynamic(3, 11, 16);
  writeDynamic(4, 17, 0x0804a240);
  writeDynamic(5, 18, 8);
  writeDynamic(6, 19, 8);
  writeDynamic(7, 0, 0);
  bytes[0x1000] = std::byte{0xc3};
  bytes[0x2ff0] = std::byte{'U'};
  bytes[0x2ff1] = std::byte{'P'};
  bytes[0x2ff2] = std::byte{'X'};
  bytes[0x2ff3] = std::byte{'!'};
  return bytes;
}
}  // namespace

int RunElf32ParsingTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (condition) return;
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  };

  auto source = MakeElf32();
  auto parsed = elf::ElfParser::Parse(source);
  expect(parsed.layout.has_value(), "ELF32 x86 executable parses");
  expect(parsed.layout && parsed.layout->imageClass == elf::ElfClass::Bits32,
         "ELF32 class is retained without exposing native headers");
  expect(parsed.layout && parsed.layout->machine == elf::ElfMachine::X86,
         "ELF32 x86 machine is retained");
  expect(parsed.layout && parsed.layout->entryPoint == 0x08049000,
         "ELF32 entry point is widened safely");
  expect(parsed.layout && parsed.layout->programHeaders.size() == 3 &&
             parsed.layout->programHeaders[1].fileOffset == 0x2000,
         "ELF32 program headers use class-specific field offsets");
  expect(parsed.layout &&
             !application::ElfBackendCapabilities::Supports(*parsed.layout),
         "ELF32 remains gated until capture and reconstruction are complete");
  expect(parsed.layout &&
             !application::ElfBackendCapabilities::DescriptorFor(
                  *parsed.layout),
         "ELF32 has no production descriptor before capability registration");
  expect(parsed.layout && elf::oep::UpxElfOepLocator::Analyze(
                              source, *parsed.layout).plan.has_value(),
         "ELF32 UPX evidence uses the class-neutral OEP interface");

  if (parsed.layout) {
    elf::CapturedElfImage captured{};
    captured.layout = *parsed.layout;
    captured.segments.push_back(
        {0, {source.begin(), source.begin() + 0x2000}});
    captured.segments.push_back(
        {1, {source.begin() + 0x2000, source.begin() + 0x3000}});
    auto rebuilt = elf::ElfImageRebuilder::Rebuild(captured, 1ull << 20);
    expect(rebuilt.image.has_value(),
           "ELF32 captured segments and dynamic metadata rebuild");
    expect(rebuilt.image && elf::ElfImageValidator::Validate(*rebuilt.image).valid,
           "ELF32 rebuilt image validates through the shared interface");
    auto rebuiltLayout = rebuilt.image ? elf::ElfParser::Parse(*rebuilt.image)
                                       : elf::ElfParseResult{};
    expect(rebuiltLayout.layout &&
               rebuiltLayout.layout->sectionHeaderEntrySize == 40,
           "ELF32 reconstruction emits 40-byte section headers");
  }

  auto wrongMachine = source;
  Write<std::uint16_t>(wrongMachine, 18, 62);
  expect(elf::ElfParser::Parse(wrongMachine).error ==
             elf::ElfParseError::UnsupportedMachine,
         "ELF32 rejects a class-machine mismatch");

  source.resize(52 + 31);
  expect(elf::ElfParser::Parse(source).error ==
             elf::ElfParseError::InvalidProgramHeaders,
         "ELF32 rejects a truncated program header table");
  return failures;
}
