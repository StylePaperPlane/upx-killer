#include "Core/PE/Rebasing/PeFileRebaser.h"
#include "Core/PE/Parsing/PeParser.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::vector<std::byte> MakeRelocatablePe() {
  std::vector<std::byte> bytes(0x600);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x80;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + 0x80);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
  nt->FileHeader.NumberOfSections = 2;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt->OptionalHeader.ImageBase = 0x140000000ull;
  nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x3000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  nt->OptionalHeader.DllCharacteristics =
      IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x2000, 12};

  auto* sections = IMAGE_FIRST_SECTION(nt);
  std::memcpy(sections[0].Name, ".text", 5);
  sections[0].Misc.VirtualSize = 0x200;
  sections[0].VirtualAddress = 0x1000;
  sections[0].SizeOfRawData = 0x200;
  sections[0].PointerToRawData = 0x200;
  sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  std::memcpy(sections[1].Name, ".reloc", 6);
  sections[1].Misc.VirtualSize = 0x200;
  sections[1].VirtualAddress = 0x2000;
  sections[1].SizeOfRawData = 0x200;
  sections[1].PointerToRawData = 0x400;
  sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

  auto value = 0x140001100ull;
  std::memcpy(bytes.data() + 0x220, &value, sizeof(value));
  IMAGE_BASE_RELOCATION block{0x1000, 12};
  std::memcpy(bytes.data() + 0x400, &block, sizeof(block));
  auto entries = reinterpret_cast<WORD*>(bytes.data() + 0x408);
  entries[0] = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0x20);
  entries[1] = 0;
  return bytes;
}
}

int RunPeFileRebaserTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  auto source = MakeRelocatablePe();
  auto parsed = pe::PeParser::Parse(source);
  expect(parsed.Succeeded(), "rebasing fixture parses");
  if (!parsed.layout) return failures;

  auto rebased =
      pe::rebasing::PeFileRebaser::Rebase(source, *parsed.layout, LoadedAddress{0x180000000ull});
  expect(rebased.Succeeded(), "packed target is rebased through its source relocation table");
  if (rebased.image) {
    auto const* nt = reinterpret_cast<IMAGE_NT_HEADERS64 const*>(rebased.image->bytes.data() +
                                                                 parsed.layout->ntHeaderOffset);
    std::uint64_t relocated{};
    std::memcpy(&relocated, rebased.image->bytes.data() + 0x220, sizeof(relocated));
    expect(nt->OptionalHeader.ImageBase == 0x180000000ull,
           "rebased file records the required base");
    expect(relocated == 0x180001100ull, "DIR64 source slot receives the exact base delta");
    expect(
        (nt->OptionalHeader.DllCharacteristics &
         (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)) == 0,
        "controlled-base staging disables ASLR");
    expect(rebased.image->sourceSlots.size() == 1 &&
               rebased.image->sourceSlots[0].location.value == 0x1020 &&
               rebased.image->sourceSlots[0].imageTarget &&
               rebased.image->sourceSlots[0].imageTarget->value == 0x1100,
           "source relocation evidence is preserved for stub-residue filtering");
  }

  auto malformed = source;
  auto* entries = reinterpret_cast<WORD*>(malformed.data() + 0x408);
  entries[0] = static_cast<WORD>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x20);
  auto malformedLayout = pe::PeParser::Parse(malformed);
  auto rejected = pe::rebasing::PeFileRebaser::Rebase(malformed, *malformedLayout.layout,
                                                      LoadedAddress{0x180000000ull});
  expect(rejected.error == pe::rebasing::PeFileRebaseError::UnsupportedRelocationType,
         "non-DIR64 source relocations are rejected");
  return failures;
}
