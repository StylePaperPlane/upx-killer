#include "Core/PE/Imports/ImportDiscovery.h"

#include <Windows.h>

#include <cstring>
#include <iostream>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::imports;

int failures{};

void Expect(bool value, char const* message) {
  if (!value) {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}
}

int RunImportDiscoveryTests() {
  std::vector<std::byte> image(0x3000);
  PeImageLayout layout{};
  layout.sizeOfImage = static_cast<std::uint32_t>(image.size());
  layout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT] = {{0x2000}, 0x20};
  PeSection data{};
  std::memcpy(data.name.data(), ".data", 5);
  data.virtualAddress = {0x1000};
  data.virtualSize = 0x100;
  data.rawSize = 0x100;
  data.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
  layout.sections.push_back(data);

  RuntimeModuleSnapshot runtime{};
  RuntimeModule module{};
  module.moduleName = "kernel32.dll";
  module.imageSize = 0x1000;
  module.exports.push_back({"kernel32.dll",
                            {0x180001000},
                            "createfilew",
                            static_cast<std::uint16_t>(1),
                            true,
                            std::nullopt});
  module.exports.push_back({"kernel32.dll",
                            {0x180001100},
                            "closehandle",
                            static_cast<std::uint16_t>(2),
                            true,
                            std::nullopt});
  module.exports.push_back({"kernel32.dll",
                            {0x180001200},
                            "exported_data",
                            static_cast<std::uint16_t>(3),
                            false,
                            std::nullopt});
  runtime.modules.push_back(module);
  auto first = 0x180001000ull;
  auto second = 0x180001100ull;
  auto third = 0x180001200ull;
  std::memcpy(image.data() + 0x1020, &first, sizeof(first));
  std::memcpy(image.data() + 0x1028, &second, sizeof(second));
  std::memcpy(image.data() + 0x1030, &third, sizeof(third));
  auto result = ImportDiscovery::Discover(image, {}, layout, runtime, layout.entryPoint);
  Expect(result.Succeeded(), "contiguous runtime IAT slots are discovered");
  Expect(result.plan && result.plan->modules.size() == 1 &&
             result.plan->modules[0].symbols.size() == 3,
         "function and data imports form one contiguous module plan");

  RuntimeModule userModule{};
  userModule.moduleName = "user32.dll";
  userModule.imageSize = 0x1000;
  userModule.exports.push_back({"user32.dll",
                                {0x180002000},
                                "first_user_symbol",
                                static_cast<std::uint16_t>(10),
                                true,
                                std::nullopt});
  userModule.exports.push_back({"user32.dll",
                                {0x180002100},
                                "second_user_symbol",
                                static_cast<std::uint16_t>(11),
                                true,
                                std::nullopt});
  runtime.modules.push_back(userModule);
  auto mixedImage = image;
  auto mixedFirst = 0x180002000ull;
  auto mixedSecond = 0x180002100ull;
  auto mixedThird = 0x180001000ull;
  auto mixedFourth = 0x180001100ull;
  std::memcpy(mixedImage.data() + 0x1040, &mixedFirst, sizeof(mixedFirst));
  std::memcpy(mixedImage.data() + 0x1048, &mixedSecond, sizeof(mixedSecond));
  std::memcpy(mixedImage.data() + 0x1050, &mixedThird, sizeof(mixedThird));
  std::memcpy(mixedImage.data() + 0x1058, &mixedFourth, sizeof(mixedFourth));
  auto mixed = ImportDiscovery::Discover(mixedImage, {}, layout, runtime, layout.entryPoint);
  Expect(mixed.Succeeded(), "interleaved runtime import table is discovered");
  Expect(mixed.plan && mixed.plan->modules.size() >= 3,
         "interleaved runtime table is split by provider module");

  auto incidentalImage = image;
  constexpr std::uint64_t ambiguousAddress = 0x180001300ull;
  constexpr std::uint64_t nonzeroBoundary = 0x1122334455667788ull;
  RuntimeModule aliasModule{};
  aliasModule.moduleName = "kernelbase.dll";
  aliasModule.imageSize = 0x1000;
  aliasModule.exports.push_back({"kernelbase.dll", {ambiguousAddress}, "shared_alias",
                                 static_cast<std::uint16_t>(4), true, std::nullopt});
  runtime.modules[0].exports.push_back({"kernel32.dll", {ambiguousAddress}, "shared_alias",
                                        static_cast<std::uint16_t>(4), true, std::nullopt});
  runtime.modules.push_back(std::move(aliasModule));
  std::memcpy(incidentalImage.data() + 0x1078, &nonzeroBoundary,
              sizeof(nonzeroBoundary));
  std::memcpy(incidentalImage.data() + 0x1080, &ambiguousAddress,
              sizeof(ambiguousAddress));
  auto incidental = ImportDiscovery::Discover(incidentalImage, {}, layout, runtime,
                                              layout.entryPoint);
  Expect(incidental.Succeeded() && incidental.plan &&
             incidental.plan->modules.size() == 1 &&
             incidental.plan->modules[0].symbols.size() == 3,
         "ambiguous exported addresses outside a bounded IAT run are ignored");

  auto directoryImage = std::vector<std::byte>(0x3000);
  auto directoryLayout = layout;
  directoryLayout.directories[IMAGE_DIRECTORY_ENTRY_IAT] = {{0x1000}, 0x18};
  std::memcpy(directoryImage.data() + 0x1000, &first, sizeof(first));
  std::memcpy(directoryImage.data() + 0x1008, &second, sizeof(second));
  auto directoryResult = ImportDiscovery::Discover(directoryImage, {}, directoryLayout,
                                                   runtime, directoryLayout.entryPoint);
  Expect(directoryResult.Succeeded() && directoryResult.plan &&
             directoryResult.plan->modules.size() == 1 &&
             directoryResult.plan->modules[0].firstThunk.value == 0x1000 &&
             directoryResult.plan->modules[0].symbols.size() == 2,
         "declared IAT range is authoritative even when it starts at the section boundary");

  auto singletonImage = std::vector<std::byte>(0x3000);
  std::memcpy(singletonImage.data() + 0x1080, &first, sizeof(first));
  auto singleton = ImportDiscovery::Discover(singletonImage, {}, layout, runtime,
                                             layout.entryPoint);
  Expect(singleton.Succeeded() && singleton.plan &&
             singleton.plan->modules.size() == 1 &&
             singleton.plan->modules[0].firstThunk.value == 0x1080 &&
             singleton.plan->modules[0].symbols.size() == 1,
         "a zero-bounded single-slot runtime import is preserved");

  auto pe32Layout = layout;
  pe32Layout.format = PeFormat::Pe32;
  auto pe32Image = std::vector<std::byte>(0x3000);
  constexpr std::uint32_t pe32Target = 0x76001000u;
  std::memcpy(pe32Image.data() + 0x1080, &pe32Target, sizeof(pe32Target));
  RuntimeModuleSnapshot pe32Runtime{};
  RuntimeModule pe32Module{};
  pe32Module.moduleName = "kernel32.dll";
  pe32Module.imageSize = 0x1000;
  pe32Module.exports.push_back({"kernel32.dll", {pe32Target}, "gettickcount",
                                static_cast<std::uint16_t>(1), true, std::nullopt});
  pe32Runtime.modules.push_back(std::move(pe32Module));
  auto pe32Singleton = ImportDiscovery::Discover(pe32Image, {}, pe32Layout, pe32Runtime,
                                                 pe32Layout.entryPoint);
  Expect(pe32Singleton.Succeeded() && pe32Singleton.plan &&
             pe32Singleton.plan->modules.size() == 1 &&
             pe32Singleton.plan->modules[0].firstThunk.value == 0x1080 &&
             pe32Singleton.plan->modules[0].symbols.size() == 1,
         "PE32 uses four-byte zero boundaries for a single-slot runtime import");

  auto packedLayout = layout;
  packedLayout.sizeOfImage = 0x4000;
  packedLayout.sections[0].virtualSize = 0x2000;
  packedLayout.sections[0].rawSize = 0x2000;
  packedLayout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT] = {{0x1800}, 0x100};
  auto packedImage = std::vector<std::byte>(packedLayout.sizeOfImage);
  std::memcpy(packedImage.data() + 0x183c, &first, sizeof(first));
  std::memcpy(packedImage.data() + 0x1844, &second, sizeof(second));
  std::memcpy(packedImage.data() + 0x1a04, &first, sizeof(first));
  std::memcpy(packedImage.data() + 0x1a0c, &second, sizeof(second));
  packedLayout.sizeOfHeaders = 0x200;
  packedLayout.entryPoint = {0x1e00};
  packedLayout.sections[0].rawOffset = {0x200};
  packedLayout.sections[0].name.fill('\0');
  auto packedSource = std::vector<std::byte>(0x2200);
  auto const rawAt = [](std::uint32_t rva) { return 0x200u + rva - 0x1000u; };
  IMAGE_IMPORT_DESCRIPTOR loaderDescriptor{};
  loaderDescriptor.Name = 0x1874;
  loaderDescriptor.FirstThunk = 0x183c;
  std::memcpy(packedSource.data() + rawAt(0x1800), &loaderDescriptor,
              sizeof(loaderDescriptor));
  constexpr char loaderName[] = "KERNEL32.DLL";
  std::memcpy(packedSource.data() + rawAt(0x1874), loaderName, sizeof(loaderName));
  std::uint64_t lookup = 0x1890;
  std::memcpy(packedSource.data() + rawAt(0x183c), &lookup, sizeof(lookup));
  lookup = 0x18a0;
  std::memcpy(packedSource.data() + rawAt(0x1844), &lookup, sizeof(lookup));
  constexpr char firstName[] = "createfilew";
  constexpr char secondName[] = "closehandle";
  std::memcpy(packedSource.data() + rawAt(0x1892), firstName, sizeof(firstName));
  std::memcpy(packedSource.data() + rawAt(0x18a2), secondName, sizeof(secondName));
  auto packed = ImportDiscovery::Discover(packedImage, packedSource, packedLayout, runtime,
                                           {0x14e0});
  Expect(packed.Succeeded() && packed.plan && packed.plan->modules.size() == 1 &&
             packed.plan->modules[0].firstThunk.value == 0x1a04 &&
             packed.plan->modules[0].symbols.size() == 2,
         "a misaligned PE64 IAT after packed imports excludes loader thunks with renamed sections");

  auto packedPe32Layout = packedLayout;
  packedPe32Layout.format = PeFormat::Pe32;
  auto packedPe32Source = std::vector<std::byte>(packedSource.size());
  std::memcpy(packedPe32Source.data() + rawAt(0x1800), &loaderDescriptor,
              sizeof(loaderDescriptor));
  std::memcpy(packedPe32Source.data() + rawAt(0x1874), loaderName, sizeof(loaderName));
  std::uint32_t narrowLookup = 0x1890;
  std::memcpy(packedPe32Source.data() + rawAt(0x183c), &narrowLookup,
              sizeof(narrowLookup));
  std::memcpy(packedPe32Source.data() + rawAt(0x1892), firstName, sizeof(firstName));
  auto packedPe32Image = std::vector<std::byte>(packedPe32Layout.sizeOfImage);
  std::memcpy(packedPe32Image.data() + 0x183c, &pe32Target, sizeof(pe32Target));
  std::memcpy(packedPe32Image.data() + 0x1a04, &pe32Target, sizeof(pe32Target));
  auto packedPe32 = ImportDiscovery::Discover(
      packedPe32Image, packedPe32Source, packedPe32Layout, pe32Runtime, {0x14e0});
  Expect(packedPe32.Succeeded() && packedPe32.plan &&
             packedPe32.plan->modules.size() == 1 &&
             packedPe32.plan->modules[0].firstThunk.value == 0x1a04,
         "PE32 excludes source loader thunks while keeping a zero-bounded import");

  auto ordinaryLayout = packedLayout;
  ordinaryLayout.entryPoint = {0x14e0};
  auto ordinaryImage = packedImage;
  std::memset(ordinaryImage.data() + 0x1a04, 0, 2 * sizeof(first));
  auto ordinary = ImportDiscovery::Discover(
      ordinaryImage, packedSource, ordinaryLayout, runtime, ordinaryLayout.entryPoint);
  Expect(ordinary.Succeeded() && ordinary.plan &&
             ordinary.plan->modules.size() == 1 &&
             ordinary.plan->modules[0].firstThunk.value == 0x183c,
         "an unchanged entry point keeps the source import table as a candidate");

  auto malformedSource = packedSource;
  std::uint64_t invalidLookup = 0x1fffffffull;
  std::memcpy(malformedSource.data() + rawAt(0x183c), &invalidLookup,
              sizeof(invalidLookup));
  auto malformed = ImportDiscovery::Discover(
      packedImage, malformedSource, packedLayout, runtime, {0x14e0});
  Expect(!malformed.Succeeded() &&
             malformed.error == ImportDiscoveryError::ImportsAmbiguous,
         "unverified source imports cannot become a completed plan");
  auto genericOnlyImage = packedImage;
  std::memset(genericOnlyImage.data() + 0x183c, 0, 2 * sizeof(first));
  auto genericOnly = ImportDiscovery::Discover(
      genericOnlyImage, malformedSource, packedLayout, runtime, {0x14e0});
  Expect(genericOnly.Succeeded() && genericOnly.plan &&
             genericOnly.plan->modules.size() == 1 &&
             genericOnly.plan->modules[0].firstThunk.value == 0x1a04,
         "malformed packed metadata does not disable independent runtime discovery");

  auto overlapImage = std::vector<std::byte>(0x3000);
  std::uint32_t overlapWords[]{1, 2, 3, 4, 5};
  std::memcpy(overlapImage.data() + 0x1020, overlapWords, sizeof(overlapWords));
  RuntimeModuleSnapshot overlapRuntime{};
  RuntimeModule overlapModule{};
  overlapModule.moduleName = "example.dll";
  overlapModule.imageSize = 0x1000;
  for (std::size_t index = 0; index < 4; ++index) {
    auto const value = static_cast<std::uint64_t>(overlapWords[index]) |
                       (static_cast<std::uint64_t>(overlapWords[index + 1]) << 32);
    overlapModule.exports.push_back({"example.dll", {value},
                                     "symbol" + std::to_string(index),
                                     std::nullopt, true, std::nullopt});
  }
  overlapRuntime.modules.push_back(std::move(overlapModule));
  auto overlap = ImportDiscovery::Discover(overlapImage, {}, layout, overlapRuntime,
                                           layout.entryPoint);
  Expect(!overlap.Succeeded() &&
             overlap.error == ImportDiscoveryError::ImportsAmbiguous,
         "overlapping four-byte PE64 probe lanes fail closed");

  auto collisionImage = std::vector<std::byte>(0x3000);
  constexpr std::uint64_t collisionAddress = 0x180003000ull;
  std::memcpy(collisionImage.data() + 0x1080, &collisionAddress,
              sizeof(collisionAddress));
  RuntimeModuleSnapshot collisionRuntime{};
  RuntimeModule publicModule{};
  publicModule.moduleName = "kernel32.dll";
  publicModule.imageSize = 0x1000;
  publicModule.exports.push_back({"kernel32.dll", {collisionAddress}, "Shared",
                                  static_cast<std::uint16_t>(1), true,
                                  "KERNELBASE.Shared"});
  RuntimeModule implementationModule{};
  implementationModule.moduleName = "kernelbase.dll";
  implementationModule.imageSize = 0x1000;
  implementationModule.exports.push_back({"kernelbase.dll", {collisionAddress}, "Shared",
                                          static_cast<std::uint16_t>(2), true,
                                          std::nullopt});
  collisionRuntime.modules.push_back(std::move(publicModule));
  collisionRuntime.modules.push_back(std::move(implementationModule));
  auto collision = ImportDiscovery::Discover(collisionImage, {}, layout,
                                             collisionRuntime, layout.entryPoint);
  Expect(!collision.Succeeded() &&
             collision.error == ImportDiscoveryError::ImportsAmbiguous,
         "forwarding and module precedence do not identify original import ownership");

  auto hintedLayout = packedLayout;
  auto hintedSource = packedSource;
  constexpr char hintedDll[] = "kernel32.dll";
  std::memcpy(hintedSource.data() + rawAt(0x18c0), hintedDll,
              sizeof(hintedDll));
  auto hintedImage = std::vector<std::byte>(hintedLayout.sizeOfImage);
  std::memcpy(hintedImage.data() + 0x1a00, &collisionAddress,
              sizeof(collisionAddress));
  IMAGE_NT_HEADERS64 originalHeader{};
  originalHeader.Signature = IMAGE_NT_SIGNATURE;
  originalHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
  originalHeader.FileHeader.NumberOfSections = 1;
  originalHeader.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  originalHeader.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  originalHeader.OptionalHeader.AddressOfEntryPoint = 0x14e0;
  originalHeader.OptionalHeader.SizeOfImage = hintedLayout.sizeOfImage;
  originalHeader.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  originalHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x1600, 0x28};
  std::memcpy(hintedImage.data() + 0x1d00, &originalHeader,
              sizeof(originalHeader));
  IMAGE_IMPORT_DESCRIPTOR originalDescriptor{};
  originalDescriptor.Name = 0x1680;
  originalDescriptor.FirstThunk = 0x1a00;
  std::memcpy(hintedImage.data() + 0x1600, &originalDescriptor,
              sizeof(originalDescriptor));
  IMAGE_SECTION_HEADER originalSection{};
  originalSection.VirtualAddress = 0x1000;
  originalSection.Misc.VirtualSize = 0x2000;
  std::memcpy(hintedImage.data() + 0x1d00 + sizeof(originalHeader),
              &originalSection, sizeof(originalSection));
  auto metadataOffset = 0x1d00 + sizeof(originalHeader) + sizeof(originalSection);
  std::uint32_t streamOffset = 0xb00;
  std::memcpy(hintedImage.data() + metadataOffset, &streamOffset,
              sizeof(streamOffset));
  std::uint32_t dllOffset = 0xc0;
  std::uint32_t iatOffset = 0xa00;
  std::memcpy(hintedImage.data() + 0x1b00, &dllOffset, sizeof(dllOffset));
  std::memcpy(hintedImage.data() + 0x1b04, &iatOffset, sizeof(iatOffset));
  hintedImage[0x1b08] = std::byte{1};
  constexpr char hintedSymbol[] = "Shared";
  std::memcpy(hintedImage.data() + 0x1b09, hintedSymbol,
              sizeof(hintedSymbol));
  auto hinted = ImportDiscovery::Discover(hintedImage, hintedSource,
                                          hintedLayout, collisionRuntime, {0x14e0});
  Expect(hinted.Succeeded() && hinted.plan &&
             hinted.plan->modules.size() == 1 &&
             hinted.plan->modules[0].moduleName == "kernel32.dll" &&
             hinted.plan->modules[0].firstThunk.value == 0x1a00,
         "validated UPX import metadata selects the original provider of an alias");

  RuntimeModuleSnapshot forwardedRuntime{};
  RuntimeModule forwardedOwner{};
  forwardedOwner.moduleName = "kernel32.dll";
  forwardedOwner.imageSize = 0x1000;
  forwardedOwner.exports.push_back({"kernel32.dll", {}, "Shared", static_cast<std::uint16_t>(1), false,
                                    "api-ms-win-core-test-l1-1-0.Shared"});
  RuntimeModule forwardedHost{};
  forwardedHost.moduleName = "kernelbase.dll";
  forwardedHost.imageSize = 0x1000;
  forwardedHost.exports.push_back({"kernelbase.dll", {collisionAddress},
                                   "Shared", static_cast<std::uint16_t>(2), true, std::nullopt});
  forwardedRuntime.modules.push_back(std::move(forwardedOwner));
  forwardedRuntime.modules.push_back(std::move(forwardedHost));
  auto chained = ImportDiscovery::Discover(hintedImage, hintedSource,
                                            hintedLayout, forwardedRuntime, {0x14e0});
  Expect(chained.Succeeded() && chained.plan &&
             chained.plan->modules.size() == 1 &&
             chained.plan->modules[0].moduleName == "kernel32.dll",
         "an explicit hint and verified forwarder chain preserve the logical provider");

  auto overriddenImage = hintedImage;
  constexpr std::uint64_t overrideAddress = 0x180003000;
  std::memcpy(overriddenImage.data() + 0x1a00, &overrideAddress,
              sizeof(overrideAddress));
  RuntimeModuleSnapshot overriddenRuntime{};
  RuntimeModule overrideModule{};
  overrideModule.moduleName = "user32.dll";
  overrideModule.imageSize = 0x1000;
  overrideModule.exports.push_back({"user32.dll", {overrideAddress},
                                    "WindowFromDC", static_cast<std::uint16_t>(3), true, std::nullopt});
  overriddenRuntime.modules.push_back(std::move(overrideModule));
  auto overridden = ImportDiscovery::Discover(overriddenImage, hintedSource,
                                               hintedLayout, overriddenRuntime, {0x14e0});
  Expect(overridden.Succeeded() && overridden.plan &&
             overridden.plan->modules.size() == 1 &&
             overridden.plan->modules[0].moduleName == "user32.dll" &&
             overridden.plan->modules[0].symbols[0].name == "WindowFromDC" &&
             overridden.warnings.size() == 1 &&
             overridden.warnings[0] == "upx_hint_rejected:rva=6656",
         "a conflicting UPX hint is rejected while a unique runtime provider survives");

  RuntimeModule secondOverride{};
  secondOverride.moduleName = "kernelbase.dll";
  secondOverride.imageSize = 0x1000;
  secondOverride.exports.push_back({"kernelbase.dll", {overrideAddress},
                                    "WindowFromDC", static_cast<std::uint16_t>(4), true, std::nullopt});
  overriddenRuntime.modules.push_back(std::move(secondOverride));
  auto overrideAmbiguous = ImportDiscovery::Discover(
      overriddenImage, hintedSource, hintedLayout, overriddenRuntime, {0x14e0});
  Expect(!overrideAmbiguous.Succeeded() &&
             overrideAmbiguous.error == ImportDiscoveryError::ImportsAmbiguous &&
             overrideAmbiguous.warnings.size() == 1,
         "a rejected hint cannot resolve same-address runtime ambiguity");

  std::uint64_t unknown = 0x12345678;
  std::uint64_t zero{};
  std::memcpy(image.data() + 0x1020, &zero, sizeof(zero));
  std::memcpy(image.data() + 0x1028, &zero, sizeof(zero));
  std::memcpy(image.data() + 0x1030, &zero, sizeof(zero));
  std::memcpy(image.data() + 0x1050, &unknown, sizeof(unknown));
  auto negative = ImportDiscovery::Discover(image, {}, layout, runtime, layout.entryPoint);
  Expect(!negative.Succeeded(), "unmatched pointers do not produce an import plan");
  return failures;
}
