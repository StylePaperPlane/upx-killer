#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Rebasing/NoSourceRelocations/NoSourceRelocationsImagePreparer.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::vector<std::byte> MakePeWithoutSourceRelocations() {
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
  nt->OptionalHeader.ImageBase = 0x400000ull;
  nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x2000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  nt->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                          IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                          IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
  nt->OptionalHeader.CheckSum = 0x12345678;

  auto* section = IMAGE_FIRST_SECTION(nt);
  std::memcpy(section->Name, "UPX1", 4);
  section->Misc.VirtualSize = 0x200;
  section->VirtualAddress = 0x1000;
  section->SizeOfRawData = 0x200;
  section->PointerToRawData = 0x200;
  section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  return bytes;
}

std::vector<std::byte> MakePe32WithAbsoluteUpxStubSource() {
  std::vector<std::byte> bytes(0x600);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x80;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(bytes.data() + 0x80);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt->FileHeader.NumberOfSections = 2;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt->OptionalHeader.ImageBase = 0x00400000;
  nt->OptionalHeader.AddressOfEntryPoint = 0x3100;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x4000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  nt->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                          IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

  auto* sections = IMAGE_FIRST_SECTION(nt);
  std::memcpy(sections[0].Name, "UPX0", 4);
  sections[0].Misc.VirtualSize = 0x2000;
  sections[0].VirtualAddress = 0x1000;
  sections[0].Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                                IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
                                IMAGE_SCN_MEM_WRITE;
  std::memcpy(sections[1].Name, "UPX1", 4);
  sections[1].Misc.VirtualSize = 0x1000;
  sections[1].VirtualAddress = 0x3000;
  sections[1].SizeOfRawData = 0x400;
  sections[1].PointerToRawData = 0x200;
  sections[1].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                                IMAGE_SCN_MEM_READ;

  constexpr std::size_t entryOffset = 0x300;
  constexpr std::byte prologue[] = {
      std::byte{0x60}, std::byte{0xBE},
      std::byte{0x00}, std::byte{0x30}, std::byte{0x40}, std::byte{0x00},
      std::byte{0x8D}, std::byte{0xBE},
      std::byte{0x00}, std::byte{0xE0}, std::byte{0xFF}, std::byte{0xFF},
  };
  std::memcpy(bytes.data() + entryOffset, prologue, sizeof(prologue));
  return bytes;
}
}

int RunNoSourceRelocationsImagePreparerTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  auto source = MakePeWithoutSourceRelocations();
  auto parsed = pe::PeParser::Parse(source);
  expect(parsed.Succeeded(), "no-source-relocations fixture parses");
  if (!parsed.layout) return failures;

  auto prepared = pe::rebasing::NoSourceRelocationsImagePreparer::Prepare(
      source, *parsed.layout, LoadedAddress{0x180000000ull});
  expect(prepared.Succeeded(), "missing source relocations use the dedicated staging path");
  if (prepared.image) {
    auto expected = source;
    auto* expectedNt =
        reinterpret_cast<IMAGE_NT_HEADERS64*>(expected.data() + parsed.layout->ntHeaderOffset);
    expectedNt->OptionalHeader.ImageBase = 0x180000000ull;
    expectedNt->OptionalHeader.DllCharacteristics &= static_cast<WORD>(
        ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
    expect(prepared.image->bytes == expected,
           "no-source staging changes only loader-placement metadata");
    expect(prepared.image->requiredBase.value == 0x180000000ull,
           "no-source staging records the required base");
  }

  auto inconsistent = source;
  auto* inconsistentNt =
      reinterpret_cast<IMAGE_NT_HEADERS64*>(inconsistent.data() + parsed.layout->ntHeaderOffset);
  inconsistentNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1000, 0};
  auto inconsistentLayout = pe::PeParser::Parse(inconsistent);
  auto rejected = pe::rebasing::NoSourceRelocationsImagePreparer::Prepare(
      inconsistent, *inconsistentLayout.layout, LoadedAddress{0x180000000ull});
  expect(
      rejected.error == pe::rebasing::NoSourceRelocationsPreparationError::SourceRelocationsPresent,
      "the no-source path rejects non-empty or inconsistent source relocation metadata");

  auto pe32Source = MakePe32WithAbsoluteUpxStubSource();
  auto pe32Layout = pe::PeParser::Parse(pe32Source);
  expect(pe32Layout.Succeeded(), "PE32 absolute-source UPX stub fixture parses");
  if (pe32Layout.layout) {
    auto pe32Prepared = pe::rebasing::NoSourceRelocationsImagePreparer::Prepare(
        pe32Source, *pe32Layout.layout, LoadedAddress{0x10000000});
    expect(pe32Prepared.Succeeded(),
           "validated PE32 UPX stub absolute source can be staged at a controlled base");
    if (pe32Prepared.image) {
      std::uint32_t stagedSource{};
      std::memcpy(&stagedSource, pe32Prepared.image->bytes.data() + 0x302,
                  sizeof(stagedSource));
      expect(stagedSource == 0x10003000,
             "PE32 UPX staging shifts only the validated compressed-source immediate");
      expect(pe32Prepared.image->stagingOnlySlots.size() == 1 &&
                 pe32Prepared.image->stagingOnlySlots[0].location.value == 0x3102 &&
                 pe32Prepared.image->stagingOnlySlots[0].imageTarget &&
                 pe32Prepared.image->stagingOnlySlots[0].imageTarget->value == 0x3000,
             "PE32 UPX staging identifies its transient absolute-address slot");
    }
  }
  return failures;
}
