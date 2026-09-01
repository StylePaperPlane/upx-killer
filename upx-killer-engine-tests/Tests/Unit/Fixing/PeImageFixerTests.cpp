#include "Core/PE/Fixing/PeImageFixer.h"
#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Validation/RebuiltPeImageValidator.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::vector<std::byte> MakePe64() {
  std::vector<std::byte> bytes(0x400);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x80;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + 0x80);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
  nt->FileHeader.NumberOfSections = 1;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt->OptionalHeader.ImageBase = 0x140000000ull;
  nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x2000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  auto* section = IMAGE_FIRST_SECTION(nt);
  std::memcpy(section->Name, ".text", 5);
  section->Misc.VirtualSize = 0x100;
  section->VirtualAddress = 0x1000;
  section->SizeOfRawData = 0x200;
  section->PointerToRawData = 0x200;
  section->Characteristics =
      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  bytes[0x200] = std::byte{0xC3};
  return bytes;
}

pe::relocations::RelocationRebuildPlan MakeRelocations(
    std::uint64_t imageBase, std::uint32_t location = 0x1080,
    std::uint32_t target = 0x1000) {
  pe::relocations::RelocationRebuildPlan plan{};
  plan.preferredImageBase = {imageBase};
  plan.slots.push_back({{location}, {target}});
  plan.directoryBytes.resize(12);
  IMAGE_BASE_RELOCATION block{location & ~0xfffu, 12};
  std::memcpy(plan.directoryBytes.data(), &block, sizeof(block));
  auto* entries = reinterpret_cast<WORD*>(
      plan.directoryBytes.data() + sizeof(block));
  entries[0] = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) |
                                 (location & 0xfffu));
  entries[1] = 0;
  return plan;
}
}

int RunFixerTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };
  auto file = MakePe64();
  auto parsed = pe::PeParser::Parse(file);
  images::CapturedImage dump{};
  dump.loadedAddress = images::ImageAddress{0x180000000ull};
  dump.bytes.resize(0x2000);
  std::copy_n(file.begin(), 0x200, dump.bytes.begin());
  dump.bytes[0x1000] = std::byte{0xC3};

  auto partial = pe::PeImageFixer::Rebuild(
      *parsed.layout, dump,
      {RelativeVirtualAddress{0x1000}, std::nullopt,
       MakeRelocations(dump.loadedAddress.value)});
  expect(partial.Succeeded() && partial.image &&
             partial.image->quality == ArtifactQuality::Partial,
         "basic PE rebuild reports missing imports as partial");

  ImportRebuildPlan imports{};
  ImportModulePlan module{};
  module.moduleName = "KERNEL32.dll";
  module.firstThunk = {0x1000};
  module.symbols.push_back({std::string{"ExitProcess"}, std::nullopt, 0});
  imports.modules.push_back(std::move(module));
  auto complete = pe::PeImageFixer::Rebuild(
      *parsed.layout, dump,
      {RelativeVirtualAddress{0x1000}, std::move(imports),
       MakeRelocations(dump.loadedAddress.value)});
  expect(complete.Succeeded() && complete.image &&
             complete.image->quality == ArtifactQuality::Complete,
         "a valid import plan produces a complete artifact");
  if (complete.image) {
    auto reparsed = pe::PeParser::Parse(complete.image->bytes);
    expect(reparsed.layout &&
               reparsed.layout
                       ->directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
                       .address.value != 0,
           "rebuilt image advertises its import directory");
  }

  auto dynamicFile = MakePe64();
  auto* sourceNt =
      reinterpret_cast<IMAGE_NT_HEADERS64*>(dynamicFile.data() + 0x80);
  sourceNt->OptionalHeader.DllCharacteristics =
      IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
      IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
  auto dynamicParsed = pe::PeParser::Parse(dynamicFile);
  auto dynamic = pe::PeImageFixer::Rebuild(
      *dynamicParsed.layout, dump,
      {RelativeVirtualAddress{0x1000}, ImportRebuildPlan{},
       MakeRelocations(0x140000000ull)});
  expect(dynamic.Succeeded() && dynamic.image,
         "fixer rebuilds a dynamically relocatable image");
  if (dynamic.image) {
    auto reparsed = pe::PeParser::Parse(dynamic.image->bytes);
    expect(reparsed.layout &&
               reparsed.layout->preferredImageBase == 0x140000000ull &&
               reparsed.layout
                       ->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                       .address.value != 0,
           "rebuilt image publishes its canonical base and relocation directory");
    auto validation = pe::validation::RebuiltPeImageValidator::Validate(
        {dynamic.image->bytes, *dynamicParsed.layout,
         LoadedAddress{0x140000000ull}, LoadedAddress{0x1c0000000ull},
         true, 1});
    expect(validation.Succeeded(),
           "core validator accepts a structurally valid relocatable image");
  }
  return failures;
}
