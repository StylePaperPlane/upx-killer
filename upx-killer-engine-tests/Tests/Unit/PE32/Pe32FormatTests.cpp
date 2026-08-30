#include "Application/Unpacking/TargetExecutionPolicy.h"
#include "Core/PE/Fixing/PeImageFixer.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"
#include "Core/PE/Relocations/RelocationReconstructor.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::vector<std::byte> MakePe32() {
  std::vector<std::byte> bytes(0x600);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x80;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt->FileHeader.NumberOfSections = 2;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt->OptionalHeader.ImageBase = 0x00400000;
  nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  nt->OptionalHeader.BaseOfCode = 0x1000;
  nt->OptionalHeader.BaseOfData = 0x2000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x3000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  auto* sections = IMAGE_FIRST_SECTION(nt);
  std::memcpy(sections[0].Name, ".text", 5);
  sections[0].Misc.VirtualSize = 0x200;
  sections[0].VirtualAddress = 0x1000;
  sections[0].SizeOfRawData = 0x200;
  sections[0].PointerToRawData = 0x200;
  sections[0].Characteristics =
      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  std::memcpy(sections[1].Name, ".data", 5);
  sections[1].Misc.VirtualSize = 0x200;
  sections[1].VirtualAddress = 0x2000;
  sections[1].SizeOfRawData = 0x200;
  sections[1].PointerToRawData = 0x400;
  sections[1].Characteristics =
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
  bytes[0x200] = std::byte{0xc3};
  return bytes;
}

void PutU32(std::vector<std::byte>& bytes, std::uint32_t rva, std::uint32_t value) {
  std::memcpy(bytes.data() + rva, &value, sizeof(value));
}

pe::oep::OepDiscoveryResult AnalyzePe32UpxTail() {
  std::vector<std::byte> source(0x800);
  pe::PeImageLayout layout{};
  layout.format = pe::PeFormat::Pe32;
  layout.entryPoint = {0x2100};
  layout.sizeOfImage = 0x4000;
  pe::PeSection unpacked{};
  std::memcpy(unpacked.name.data(), "UPX0", 4);
  unpacked.virtualAddress = {0x1000};
  unpacked.virtualSize = 0x1000;
  unpacked.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                             IMAGE_SCN_MEM_EXECUTE;
  pe::PeSection stub{};
  std::memcpy(stub.name.data(), "UPX1", 4);
  stub.virtualAddress = {0x2000};
  stub.virtualSize = 0x1000;
  stub.rawOffset = {0x200};
  stub.rawSize = 0x400;
  stub.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
  layout.sections = {unpacked, stub};
  std::memcpy(source.data() + 0x240, "UPX!", 4);
  auto const tailOffset = std::size_t{0x380};
  source[tailOffset] = std::byte{0x61};
  source[tailOffset + 1] = std::byte{0xe9};
  auto const transferRva = std::uint32_t{0x2181};
  auto const targetRva = std::uint32_t{0x1100};
  auto const displacement = static_cast<std::int32_t>(targetRva - (transferRva + 5));
  std::memcpy(source.data() + tailOffset + 2, &displacement, sizeof(displacement));
  return pe::oep::UpxOepLocator::Analyze(source, layout);
}
}

int RunPe32FormatTests() {
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  auto file = MakePe32();
  auto parsed = pe::PeParser::Parse(file);
  expect(parsed.layout && parsed.layout->format == pe::PeFormat::Pe32 &&
             parsed.layout->machine == IMAGE_FILE_MACHINE_I386,
         "PE32 I386 executable parses with an explicit format");
  if (!parsed.layout) return failures;

  auto dllFile = file;
  auto* dllDos = reinterpret_cast<IMAGE_DOS_HEADER*>(dllFile.data());
  auto* dllNt = reinterpret_cast<IMAGE_NT_HEADERS32*>(dllFile.data() + dllDos->e_lfanew);
  dllNt->FileHeader.Characteristics |= IMAGE_FILE_DLL;
  dllNt->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
  auto dll = pe::PeParser::Parse(dllFile);
  expect(dll.layout && dll.layout->imageKind == pe::PeImageKind::DynamicLibrary &&
             dll.layout->sourceLoadPolicy.dynamicBase &&
             !dll.layout->sourceLoadPolicy.highEntropyVa,
         "PE32 DLL parses and exposes its source load policy");
  if (dll.layout) {
    dll.layout->sourceLoadPolicy.hasRelocations = true;
    dll.layout->sourceLoadPolicy.dynamicBase = false;
    dll.layout->preferredImageBase = 0x67380000;
    auto fixedPolicy = application::TargetExecutionPolicy::Resolve(*dll.layout);
    expect(fixedPolicy && fixedPolicy->outputBase.value == 0x67380000 &&
               !fixedPolicy->enableDynamicBase && fixedPolicy->rebuildRelocations,
           "PE32 DLL with relocations but no source ASLR keeps its preferred base and ASLR intent");
    dll.layout->sourceLoadPolicy.dynamicBase = true;
    auto dynamicPolicy = application::TargetExecutionPolicy::Resolve(*dll.layout);
    expect(dynamicPolicy && dynamicPolicy->outputBase.value == 0x00400000 &&
               dynamicPolicy->enableDynamicBase && dynamicPolicy->captureBases[0].value != 0x00400000,
           "ASLR-enabled PE32 DLL separates stable evidence bases from its canonical output base");
  }

  auto oep = AnalyzePe32UpxTail();
  expect(oep.plan && oep.plan->candidates.size() == 1 &&
             oep.plan->candidates.front().transfer.value == 0x2181 &&
             oep.plan->candidates.front().target.value == 0x1100,
         "PE32 popa and direct rel32 tail transfer resolves an OEP candidate");

  constexpr std::array<std::uint64_t, 3> bases{
      0x00400000ull, 0x10000000ull, 0x20000000ull};
  std::array<std::vector<std::byte>, 3> images{
      std::vector<std::byte>(parsed.layout->sizeOfImage),
      std::vector<std::byte>(parsed.layout->sizeOfImage),
      std::vector<std::byte>(parsed.layout->sizeOfImage)};
  std::array<pe::relocations::LoadedImageSnapshot, 3> snapshots{};
  for (std::size_t index = 0; index < images.size(); ++index) {
    std::copy_n(file.begin(), parsed.layout->sizeOfHeaders, images[index].begin());
    images[index][0x1000] = std::byte{0xc3};
    PutU32(images[index], 0x2023,
           static_cast<std::uint32_t>(bases[index] + 0x1000));
    snapshots[index] = {{bases[index]}, images[index]};
  }
  auto relocations = pe::relocations::RelocationReconstructor::Reconstruct(
      snapshots, {}, *parsed.layout, LoadedAddress{bases.front()});
  expect(relocations.plan && relocations.plan->slots.size() == 1 &&
             relocations.plan->slots.front().location.value == 0x2023,
         "three PE32 snapshots recover an unaligned four-byte relocation slot");
  if (!relocations.plan) return failures;
  auto const* block = reinterpret_cast<IMAGE_BASE_RELOCATION const*>(
      relocations.plan->directoryBytes.data());
  auto const* entries = reinterpret_cast<WORD const*>(
      relocations.plan->directoryBytes.data() + sizeof(IMAGE_BASE_RELOCATION));
  expect(block->VirtualAddress == 0x2000 &&
             (entries[0] >> 12) == IMAGE_REL_BASED_HIGHLOW,
         "PE32 relocation directory encodes HIGHLOW entries");

  dumping::DumpedImage dump{};
  dump.loadedBase = {bases.front()};
  dump.bytes = images.front();
  auto fixed = pe::PeImageFixer::Rebuild(
      *parsed.layout, dump,
      {{0x1000}, ImportRebuildPlan{}, std::move(*relocations.plan)});
  expect(fixed.image.has_value(), "PE32 fixer creates a standard image");
  if (!fixed.image) return failures;
  auto repaired = pe::PeParser::Parse(fixed.image->bytes);
  expect(repaired.layout && repaired.layout->format == pe::PeFormat::Pe32 &&
             repaired.layout->preferredImageBase == 0x00400000,
         "PE32 output uses the canonical preferred base");
  if (!repaired.layout) return failures;
  auto const* nt = reinterpret_cast<IMAGE_NT_HEADERS32 const*>(
      fixed.image->bytes.data() + repaired.layout->ntHeaderOffset);
  expect((nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0 &&
             (nt->OptionalHeader.DllCharacteristics &
              IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) == 0,
         "PE32 output enables dynamic base without HIGH_ENTROPY_VA");
  auto fourth = pe::rebasing::PeFileRebaser::Rebase(
      fixed.image->bytes, *repaired.layout, LoadedAddress{0x30000000});
  expect(fourth.image && fourth.image->sourceSlots.size() == 1,
         "PE32 output applies its HIGHLOW table at a fourth base");

  dumping::DumpedImage fixedBaseDump{};
  fixedBaseDump.loadedBase = {parsed.layout->preferredImageBase};
  fixedBaseDump.bytes = images.front();
  auto fixedBase = pe::PeImageFixer::Rebuild(
      *parsed.layout, fixedBaseDump,
      {{0x1000}, ImportRebuildPlan{},
       pe::fixing::FixedImagePlacement{
           LoadedAddress{parsed.layout->preferredImageBase}}});
  expect(fixedBase.image.has_value(),
         "PE32 fixer accepts an explicit faithful fixed-base placement");
  if (!fixedBase.image) return failures;
  auto fixedBaseLayout = pe::PeParser::Parse(fixedBase.image->bytes);
  expect(fixedBaseLayout.layout &&
             fixedBaseLayout.layout->preferredImageBase == parsed.layout->preferredImageBase &&
             fixedBaseLayout.layout->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                     .address.value == 0 &&
             fixedBaseLayout.layout->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].size == 0 &&
             (fixedBaseLayout.layout->characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0 &&
             (fixedBaseLayout.layout->dllCharacteristics &
              (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
               IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)) == 0,
         "fixed-base PE32 output preserves its base without inventing relocations or ASLR");
  return failures;
}
