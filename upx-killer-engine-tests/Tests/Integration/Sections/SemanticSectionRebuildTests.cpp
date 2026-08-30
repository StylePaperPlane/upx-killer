#include "Core/PE/Fixing/PeImageFixer.h"
#include "Core/PE/Imports/ImportTableValidator.h"
#include "Core/PE/Parsing/PeParser.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;

int failures{};

void Expect(bool condition, std::string_view message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

std::string NameOf(PeSection const& section) {
  auto const end = std::find(section.name.begin(), section.name.end(), '\0');
  return {section.name.begin(), end};
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

PeSection const* SectionAt(PeImageLayout const& layout, std::uint32_t rva) {
  auto const found =
      std::find_if(layout.sections.begin(), layout.sections.end(), [&](PeSection const& section) {
        auto const extent = std::max(section.virtualSize, section.rawSize);
        return rva >= section.virtualAddress.value && rva - section.virtualAddress.value < extent;
      });
  return found == layout.sections.end() ? nullptr : &*found;
}

struct PackedFixture {
  PeImageLayout layout;
  dumping::DumpedImage dump;
  ImportRebuildPlan imports;
};

PackedFixture MakePackedFixture() {
  PackedFixture fixture{};
  fixture.layout.ntHeaderOffset = 0x80;
  fixture.layout.preferredImageBase = 0x140000000ull;
  fixture.layout.entryPoint = {0x4800};
  fixture.layout.sizeOfImage = 0x6000;
  fixture.layout.sizeOfHeaders = 0x400;
  fixture.layout.sectionAlignment = 0x1000;
  fixture.layout.fileAlignment = 0x200;
  fixture.layout.characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
  fixture.layout.sections.push_back(MakeSection("m0dC0de", 0x1000, 0x3000,
                                                IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                                                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                                                    IMAGE_SCN_MEM_EXECUTE));
  fixture.layout.sections.push_back(MakeSection(
      "xYz!42", 0x4000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE));
  fixture.layout.sections.push_back(
      MakeSection(".rsrc", 0x5000, 0x1000,
                  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE));
  fixture.layout.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {RelativeVirtualAddress{0x3000},
                                                                 sizeof(RUNTIME_FUNCTION)};
  fixture.layout.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE] = {RelativeVirtualAddress{0x5000},
                                                                0x180};

  fixture.dump.loadedBase = {0x7ff700000000ull};
  fixture.dump.bytes.resize(fixture.layout.sizeOfImage);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fixture.dump.bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = static_cast<LONG>(fixture.layout.ntHeaderOffset);
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(fixture.dump.bytes.data() +
                                                   fixture.layout.ntHeaderOffset);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
  nt->FileHeader.NumberOfSections = static_cast<WORD>(fixture.layout.sections.size());
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt->FileHeader.Characteristics = fixture.layout.characteristics;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt->OptionalHeader.ImageBase = fixture.layout.preferredImageBase;
  nt->OptionalHeader.AddressOfEntryPoint = fixture.layout.entryPoint.value;
  nt->OptionalHeader.SectionAlignment = fixture.layout.sectionAlignment;
  nt->OptionalHeader.FileAlignment = fixture.layout.fileAlignment;
  nt->OptionalHeader.SizeOfImage = fixture.layout.sizeOfImage;
  nt->OptionalHeader.SizeOfHeaders = fixture.layout.sizeOfHeaders;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {0x3000,
                                                                       sizeof(RUNTIME_FUNCTION)};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] = {0x5000, 0x180};

  RUNTIME_FUNCTION function{};
  function.BeginAddress = 0x4100;
  function.EndAddress = 0x4900;
  function.UnwindData = 0x3200;
  std::memcpy(fixture.dump.bytes.data() + 0x3000, &function, sizeof(function));

  ImportModulePlan module{};
  module.moduleName = "KERNEL32.dll";
  module.firstThunk = {0x5400};
  module.symbols.push_back({std::string{"ExitProcess"}, std::nullopt, 0});
  fixture.imports.modules.push_back(std::move(module));
  return fixture;
}

relocations::RelocationRebuildPlan MakeRelocations() {
  relocations::RelocationRebuildPlan plan{};
  plan.preferredImageBase = {0x140000000ull};
  plan.slots.push_back({{0x2000}, {0x4800}});
  plan.directoryBytes.resize(12);
  IMAGE_BASE_RELOCATION block{0x2000, 12};
  std::memcpy(plan.directoryBytes.data(), &block, sizeof(block));
  auto* entries = reinterpret_cast<WORD*>(plan.directoryBytes.data() + sizeof(block));
  entries[0] = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0);
  entries[1] = 0;
  return plan;
}

void FixerAppliesSemanticSectionLayout() {
  auto fixture = MakePackedFixture();
  auto const fixed =
      PeImageFixer::Rebuild(fixture.layout, fixture.dump,
                            {RelativeVirtualAddress{0x4800}, fixture.imports, MakeRelocations()});
  Expect(fixed.Succeeded(), "semantic section fixture rebuild succeeds");
  if (!fixed.image) return;

  auto const parsed = PeParser::Parse(fixed.image->bytes);
  Expect(parsed.Succeeded(), "semantic section output reparses");
  if (!parsed.layout) return;

  auto const hasPackedName = std::any_of(parsed.layout->sections.begin(),
                                         parsed.layout->sections.end(), [](auto const& section) {
                                           auto const name = NameOf(section);
                                           return name == "m0dC0de" || name == "xYz!42";
                                         });
  auto const hasRwx = std::any_of(parsed.layout->sections.begin(), parsed.layout->sections.end(),
                                  [](auto const& section) {
                                    return (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
                                           (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                                  });
  Expect(!hasPackedName, "final PE does not retain packed section names");
  Expect(!hasRwx, "final PE does not contain writable executable sections");

  auto const* code = SectionAt(*parsed.layout, 0x4800);
  auto const* exception = SectionAt(*parsed.layout, 0x3000);
  auto const* iat = SectionAt(*parsed.layout, 0x5400);
  Expect(code && NameOf(*code) == ".text", "final OEP belongs to .text");
  Expect(exception && NameOf(*exception) == ".pdata",
         "final exception directory belongs to .pdata");
  Expect(iat && NameOf(*iat) == ".iat", "final operational IAT belongs to .iat");
  Expect(imports::ImportTableValidator::Validate(fixed.image->bytes, *parsed.layout),
         "semantic section output retains a valid import table");
  Expect(parsed.layout->preferredImageBase == 0x140000000ull &&
             parsed.layout->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].address.value != 0,
         "semantic section output is a standard relocatable image");
  Expect(std::any_of(parsed.layout->sections.begin(), parsed.layout->sections.end(),
                     [](auto const& section) { return NameOf(section) == ".reloc"; }),
         "semantic section output contains .reloc");
}
}

int RunSemanticSectionRebuildTests() {
  FixerAppliesSemanticSectionLayout();
  return failures;
}
