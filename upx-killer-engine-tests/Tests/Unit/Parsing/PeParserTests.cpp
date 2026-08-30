#include "Core/PE/Parsing/PeParser.h"

#include <Windows.h>

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
}

int RunParserTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };
  auto bytes = MakePe64();
  auto parsed = pe::PeParser::Parse(bytes);
  expect(parsed.Succeeded(), "PE32+ AMD64 executable parses");
  expect(parsed.layout && parsed.layout->entryPoint.value == 0x1000,
         "entry point RVA is preserved");
  expect(parsed.layout && parsed.layout->sections.size() == 1,
         "section table is parsed");
  bytes.resize(100);
  expect(pe::PeParser::Parse(bytes).error == pe::PeError::Truncated,
         "truncated image is rejected");
  auto mismatched = MakePe64();
  reinterpret_cast<IMAGE_NT_HEADERS64*>(mismatched.data() + 0x80)
      ->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  expect(pe::PeParser::Parse(mismatched).error ==
             pe::PeError::UnsupportedArchitecture,
         "optional header and machine mismatch is rejected");
  return failures;
}
