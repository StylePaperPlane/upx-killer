#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"
#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"
#include "Core/ELF/DynamicLinking/ElfDynamicMetadataAnalyzer.h"
#include "Core/ELF/OepDiscovery/UpxElfOepLocator.h"
#include "Core/ELF/Parsing/ElfParser.h"
#include "Core/ELF/Reconstruction/ElfImageRebuilder.h"
#include "Core/ELF/Validation/ElfImageValidator.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
class MemoryElfSourceReader final
    : public upx_killer::engine::application::elf_preparation::IElfSourceReader {
 public:
  explicit MemoryElfSourceReader(std::vector<std::byte> bytes)
      : bytes_(std::move(bytes)) {}

  [[nodiscard]] upx_killer::engine::application::elf_preparation::
      ElfSourceReadResult
      Read(std::filesystem::path const&,
           std::uint64_t maximumSize) const noexcept override {
    if (bytes_.size() > maximumSize) return {};
    return {bytes_, 0};
  }

 private:
  std::vector<std::byte> bytes_;
};

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
  namespace contracts = upx_killer::contracts;
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
             application::ElfBackendCapabilities::Supports(*parsed.layout),
         "ELF32 production support is selected through the shared capability table");
  auto descriptor = parsed.layout
                        ? application::ElfBackendCapabilities::DescriptorFor(
                              *parsed.layout)
                        : std::nullopt;
  auto manifest = application::ElfBackendCapabilities::Manifest();
  expect(descriptor &&
             descriptor->addressing == contracts::ImageAddressing::FixedAddress &&
             manifest.capabilities.size() == 6 &&
             std::find(manifest.capabilities.begin(), manifest.capabilities.end(),
                       *descriptor) != manifest.capabilities.end(),
         "ELF32 fixed-address descriptor has an exact manifest capability");
  expect(parsed.layout && elf::oep::UpxElfOepLocator::Analyze(
                              source, *parsed.layout).plan.has_value(),
         "ELF32 UPX evidence uses the class-neutral OEP interface");

  auto pieSource = source;
  Write<std::uint16_t>(pieSource, 16, 3);
  auto pie = elf::ElfParser::Parse(pieSource);
  expect(pie.layout &&
             pie.layout->imageType == elf::ElfImageType::PositionIndependentExecutable,
         "ELF32 ET_DYN executable remains representable through the shared model");
  expect(pie.layout &&
             application::ElfBackendCapabilities::Supports(*pie.layout),
         "ELF32 PIE is selected through an exact addressing capability");
  auto pieDescriptor = pie.layout
                           ? application::ElfBackendCapabilities::DescriptorFor(
                                 *pie.layout)
                           : std::nullopt;
  expect(pieDescriptor &&
             pieDescriptor->addressing ==
                 contracts::ImageAddressing::PositionIndependent &&
             descriptor && *pieDescriptor != *descriptor &&
             std::find(manifest.capabilities.begin(), manifest.capabilities.end(),
                       *pieDescriptor) != manifest.capabilities.end(),
         "ELF32 PIE cannot match the fixed-address executable descriptor");

  auto sharedObjectSource = pieSource;
  Write<std::uint32_t>(sharedObjectSource, 24, 0);
  auto sharedObject = elf::ElfParser::Parse(sharedObjectSource);
  expect(sharedObject.layout &&
             sharedObject.layout->imageType == elf::ElfImageType::SharedObject,
         "ELF32 ET_DYN without an entry remains a shared object");
  expect(sharedObject.layout &&
             application::ElfBackendCapabilities::Supports(
                 *sharedObject.layout),
         "ELF32 shared objects use an exact production capability");

  MemoryElfSourceReader pieReader{pieSource};
  application::elf_preparation::ElfTargetPreparationUseCase preparation{
      pieReader};
  contracts::UnpackJobRequest pieRequest{};
  pieRequest.targetPath = L"elf32-pie";
  pieRequest.maximumImageSize = 1ull << 20;
  pieRequest.entryPoint = contracts::EntryPointHint{
      contracts::EntryPointAddressKind::RelativeVirtualAddress, 0x08049000};
  expect(preparation.Execute(pieRequest).target.has_value(),
         "ELF32 PIE accepts an explicit relative entry point");
  pieRequest.entryPoint->kind =
      contracts::EntryPointAddressKind::VirtualAddress;
  auto wrongEntryKind = preparation.Execute(pieRequest);
  expect(!wrongEntryKind.target &&
             wrongEntryKind.failure.category ==
                 contracts::ErrorCategory::InvalidRequest,
         "ELF32 PIE rejects an explicit virtual-address entry point");

  auto damagedDynamic = source;
  Write<std::uint32_t>(damagedDynamic, 0x2500 + 7 * 8, 1);
  expect(parsed.layout &&
             !elf::dynamic_linking::ElfDynamicMetadataAnalyzer::Analyze(
                  damagedDynamic, *parsed.layout)
                  .valid,
         "ELF32 rejects a dynamic table without a terminator");

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
