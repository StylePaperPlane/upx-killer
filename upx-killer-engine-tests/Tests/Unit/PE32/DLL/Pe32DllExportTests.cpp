#include "Core/PE/Exports/ExportDirectoryAnalyzer.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::vector<std::byte> MakeMappedDll(pe::PeImageLayout& layout) {
  layout = {};
  layout.format = pe::PeFormat::Pe32;
  layout.imageKind = pe::PeImageKind::DynamicLibrary;
  layout.sizeOfImage = 0x4000;
  layout.directories[IMAGE_DIRECTORY_ENTRY_EXPORT] = {{0x2000}, 0x200};
  pe::PeSection text{};
  text.virtualAddress = {0x1000};
  text.virtualSize = 0x1000;
  text.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  pe::PeSection rdata{};
  rdata.virtualAddress = {0x2000};
  rdata.virtualSize = 0x1000;
  rdata.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
  layout.sections = {text, rdata};

  std::vector<std::byte> image(layout.sizeOfImage);
  IMAGE_EXPORT_DIRECTORY directory{};
  directory.Name = 0x2080;
  directory.Base = 1;
  directory.NumberOfFunctions = 2;
  directory.NumberOfNames = 2;
  directory.AddressOfFunctions = 0x2040;
  directory.AddressOfNames = 0x2048;
  directory.AddressOfNameOrdinals = 0x2050;
  std::memcpy(image.data() + 0x2000, &directory, sizeof(directory));
  DWORD functions[]{0x1100, 0x2090};
  DWORD names[]{0x20a0, 0x20a7};
  WORD ordinals[]{0, 1};
  std::memcpy(image.data() + 0x2040, functions, sizeof(functions));
  std::memcpy(image.data() + 0x2048, names, sizeof(names));
  std::memcpy(image.data() + 0x2050, ordinals, sizeof(ordinals));
  std::memcpy(image.data() + 0x2080, "fixture.dll", 12);
  std::memcpy(image.data() + 0x2090, "KERNEL32.Sleep", 15);
  std::memcpy(image.data() + 0x20a0, "Run\0Wait\0", 9);
  return image;
}
}

int RunPe32DllExportTests() {
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };
  pe::PeImageLayout layout{};
  auto image = MakeMappedDll(layout);
  auto result = pe::exports::ExportDirectoryAnalyzer::AnalyzeMapped(image, layout);
  expect(result.directory && result.directory->moduleName == "fixture.dll" &&
             result.directory->functions.size() == 2 &&
             result.directory->functions[0].target &&
             result.directory->functions[1].forwarder &&
             result.directory->codeTargets.size() == 1,
         "DLL export analyzer preserves named code and forwarded exports");

  auto broken = image;
  WORD badOrdinal = 2;
  std::memcpy(broken.data() + 0x2050, &badOrdinal, sizeof(badOrdinal));
  auto rejected = pe::exports::ExportDirectoryAnalyzer::AnalyzeMapped(broken, layout);
  expect(!rejected.directory && rejected.error == pe::exports::ExportDirectoryError::InvalidOrdinal,
         "DLL export analyzer rejects an out-of-range name ordinal");
  return failures;
}
