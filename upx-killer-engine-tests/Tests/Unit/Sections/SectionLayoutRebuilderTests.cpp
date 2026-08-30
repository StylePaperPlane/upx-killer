#include "Core/PE/Sections/SectionLayoutRebuilder.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::sections;

int failures{};

void Expect(bool condition, std::string_view message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

PeSection MakeSection(char const* name, std::uint32_t rva, std::uint32_t size,
                      std::uint32_t characteristics) {
  PeSection section{};
  std::memcpy(section.name.data(), name,
              std::min<std::size_t>(std::strlen(name), section.name.size()));
  section.virtualAddress = {rva};
  section.virtualSize = size;
  section.characteristics = characteristics;
  return section;
}

std::string NameOf(RebuiltSection const& section) {
  auto const end = std::find(section.name.begin(), section.name.end(), '\0');
  return {section.name.begin(), end};
}

RebuiltSection const* SectionAt(SectionLayoutPlan const& plan, std::uint32_t rva) {
  auto const found =
      std::find_if(plan.sections.begin(), plan.sections.end(), [&](RebuiltSection const& section) {
        return rva >= section.virtualAddress.value &&
               rva - section.virtualAddress.value < section.virtualSize;
      });
  return found == plan.sections.end() ? nullptr : &*found;
}

void PackedSectionsBecomeAnalysisGradeSections() {
  PeImageLayout source{};
  source.sizeOfImage = 0x6000;
  source.sectionAlignment = 0x1000;
  source.fileAlignment = 0x200;
  source.sections.push_back(MakeSection("m0dC0de", 0x1000, 0x3000,
                                        IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ |
                                            IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE));
  source.sections.push_back(MakeSection(
      "xYz!42", 0x4000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE));
  source.sections.push_back(
      MakeSection(".rsrc", 0x5000, 0x1000,
                  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE));
  source.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {RelativeVirtualAddress{0x3000},
                                                         sizeof(RUNTIME_FUNCTION)};
  source.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE] = {RelativeVirtualAddress{0x5000}, 0x180};

  std::vector<std::byte> loaded(source.sizeOfImage);
  RUNTIME_FUNCTION function{};
  function.BeginAddress = 0x1100;
  function.EndAddress = 0x1800;
  function.UnwindData = 0x3200;
  std::memcpy(loaded.data() + 0x3000, &function, sizeof(function));

  ImportRebuildPlan imports{};
  ImportModulePlan module{};
  module.moduleName = "KERNEL32.dll";
  module.firstThunk = {0x5400};
  module.symbols.push_back({std::string{"ExitProcess"}, std::nullopt, 0});
  imports.modules.push_back(std::move(module));

  auto const result = SectionLayoutRebuilder::Build(
      source, {loaded, LoadedAddress{0x140000000ull}, RelativeVirtualAddress{0x1200}, &imports});
  Expect(result.Succeeded(), "packed section layout is rebuilt");
  if (!result.plan) return;

  auto const hasPackedName = std::any_of(result.plan->sections.begin(), result.plan->sections.end(),
                                         [](auto const& section) {
                                           auto const name = NameOf(section);
                                           return name == "m0dC0de" || name == "xYz!42";
                                         });
  auto const hasRwx = std::any_of(result.plan->sections.begin(), result.plan->sections.end(),
                                  [](auto const& section) {
                                    return (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
                                           (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                                  });
  Expect(!hasPackedName, "packed section names are not preserved");
  Expect(!hasRwx, "rebuilt layout contains no writable executable section");

  auto const* code = SectionAt(*result.plan, 0x1200);
  auto const* exception = SectionAt(*result.plan, 0x3000);
  auto const* iat = SectionAt(*result.plan, 0x5400);
  Expect(code && NameOf(*code) == ".text", "OEP and runtime functions belong to .text");
  Expect(exception && NameOf(*exception) == ".pdata", "exception directory belongs to .pdata");
  Expect(iat && NameOf(*iat) == ".iat", "operational IAT is mapped as ordinary data, not .rsrc");
}

void Pe32TlsDirectoryIsPreservedOnlyWithValidVaEvidence() {
  PeImageLayout source{};
  source.format = PeFormat::Pe32;
  source.sizeOfImage = 0x4000;
  source.entryPoint = {0x1100};
  source.sectionAlignment = 0x1000;
  source.fileAlignment = 0x200;
  source.sections.push_back(MakeSection(
      ".text", 0x1000, 0x1000,
      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE));
  source.sections.push_back(MakeSection(
      ".data", 0x2000, 0x1000,
      IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE));
  source.directories[IMAGE_DIRECTORY_ENTRY_TLS] = {
      RelativeVirtualAddress{0x2000}, sizeof(IMAGE_TLS_DIRECTORY32)};

  std::vector<std::byte> loaded(source.sizeOfImage);
  IMAGE_TLS_DIRECTORY32 tls{};
  tls.StartAddressOfRawData = 0x00402100;
  tls.EndAddressOfRawData = 0x00402104;
  tls.AddressOfIndex = 0x00402110;
  tls.AddressOfCallBacks = 0x00402120;
  tls.Characteristics = IMAGE_SCN_ALIGN_4BYTES;
  std::memcpy(loaded.data() + 0x2000, &tls, sizeof(tls));
  std::uint32_t callback = 0x00401100;
  std::memcpy(loaded.data() + 0x2120, &callback, sizeof(callback));

  auto valid = SectionLayoutRebuilder::Build(
      source, {loaded, LoadedAddress{0x00400000}, RelativeVirtualAddress{0x1100}, nullptr});
  Expect(valid.plan && valid.plan->tlsDirectory &&
             valid.plan->tlsDirectory->address.value == 0x2000,
         "validated PE32 TLS directory is preserved in the section plan");

  tls.AddressOfCallBacks = 0x70000000;
  std::memcpy(loaded.data() + 0x2000, &tls, sizeof(tls));
  auto invalid = SectionLayoutRebuilder::Build(
      source, {loaded, LoadedAddress{0x00400000}, RelativeVirtualAddress{0x1100}, nullptr});
  Expect(invalid.plan && !invalid.plan->tlsDirectory,
         "out-of-image PE32 TLS pointers are not preserved");
}

void Pe32AutomaticTlsDiscoveryRejectsReservedCharacteristics() {
  PeImageLayout source{};
  source.format = PeFormat::Pe32;
  source.sizeOfImage = 0x5000;
  source.entryPoint = {0x4100};
  source.sectionAlignment = 0x1000;
  source.fileAlignment = 0x200;
  source.sections.push_back(MakeSection(
      "UPX0", 0x1000, 0x3000,
      IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ |
          IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE));
  source.sections.push_back(MakeSection(
      "UPX1", 0x4000, 0x1000,
      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE));

  std::vector<std::byte> loaded(source.sizeOfImage);
  IMAGE_TLS_DIRECTORY32 falseTls{};
  falseTls.StartAddressOfRawData = 0x00401C5D;
  falseTls.EndAddressOfRawData = 0x004024C8;
  falseTls.AddressOfIndex = 0x004029DC;
  falseTls.Characteristics = 0x656E6567;
  std::memcpy(loaded.data() + 0x2800, &falseTls, sizeof(falseTls));

  auto result = SectionLayoutRebuilder::Build(
      source, {loaded, LoadedAddress{0x00400000}, RelativeVirtualAddress{0x246E}, nullptr});
  Expect(result.plan && !result.plan->tlsDirectory,
         "automatic PE32 TLS discovery rejects nonzero reserved characteristics");
  if (!result.plan) return;
  auto const* oep = SectionAt(*result.plan, 0x246E);
  Expect(oep && (oep->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0,
         "rejected false TLS evidence cannot remove execute permission from the OEP page");
}
}

int RunSectionLayoutRebuilderTests() {
  PackedSectionsBecomeAnalysisGradeSections();
  Pe32TlsDirectoryIsPreservedOnlyWithValidVaEvidence();
  Pe32AutomaticTlsDiscoveryRejectsReservedCharacteristics();
  return failures;
}
