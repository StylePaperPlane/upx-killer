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
  auto result = ImportDiscovery::Discover(image, layout, runtime);
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
  auto mixed = ImportDiscovery::Discover(mixedImage, layout, runtime);
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
  auto incidental = ImportDiscovery::Discover(incidentalImage, layout, runtime);
  Expect(incidental.Succeeded() && incidental.plan &&
             incidental.plan->modules.size() == 1 &&
             incidental.plan->modules[0].symbols.size() == 3,
         "ambiguous exported addresses outside a bounded IAT run are ignored");

  auto directoryImage = std::vector<std::byte>(0x3000);
  auto directoryLayout = layout;
  directoryLayout.directories[IMAGE_DIRECTORY_ENTRY_IAT] = {{0x1000}, 0x18};
  std::memcpy(directoryImage.data() + 0x1000, &first, sizeof(first));
  std::memcpy(directoryImage.data() + 0x1008, &second, sizeof(second));
  auto directoryResult = ImportDiscovery::Discover(directoryImage, directoryLayout, runtime);
  Expect(directoryResult.Succeeded() && directoryResult.plan &&
             directoryResult.plan->modules.size() == 1 &&
             directoryResult.plan->modules[0].firstThunk.value == 0x1000 &&
             directoryResult.plan->modules[0].symbols.size() == 2,
         "declared IAT range is authoritative even when it starts at the section boundary");

  auto singletonImage = std::vector<std::byte>(0x3000);
  std::memcpy(singletonImage.data() + 0x1080, &first, sizeof(first));
  auto singleton = ImportDiscovery::Discover(singletonImage, layout, runtime);
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
  auto pe32Singleton = ImportDiscovery::Discover(pe32Image, pe32Layout, pe32Runtime);
  Expect(pe32Singleton.Succeeded() && pe32Singleton.plan &&
             pe32Singleton.plan->modules.size() == 1 &&
             pe32Singleton.plan->modules[0].firstThunk.value == 0x1080 &&
             pe32Singleton.plan->modules[0].symbols.size() == 1,
         "PE32 uses four-byte zero boundaries for a single-slot runtime import");

  std::uint64_t unknown = 0x12345678;
  std::uint64_t zero{};
  std::memcpy(image.data() + 0x1020, &zero, sizeof(zero));
  std::memcpy(image.data() + 0x1028, &zero, sizeof(zero));
  std::memcpy(image.data() + 0x1030, &zero, sizeof(zero));
  std::memcpy(image.data() + 0x1050, &unknown, sizeof(unknown));
  auto negative = ImportDiscovery::Discover(image, layout, runtime);
  Expect(!negative.Succeeded(), "unmatched pointers do not produce an import plan");
  return failures;
}
