#include "Core/PE/Imports/ImportDiscovery.h"

#include <Windows.h>

#include <cstring>
#include <iostream>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe;
    using namespace upx_killer::engine::pe::imports;

    int failures{};

    void Expect(bool value, char const* message)
    {
        if (!value) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
    }
}

int RunImportDiscoveryTests()
{
    std::vector<std::byte> image(0x3000);
    PeImageLayout layout{};
    layout.sizeOfImage = static_cast<std::uint32_t>(image.size());
    layout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT] = { { 0x2000 }, 0x20 };
    PeSection data{};
    std::memcpy(data.name.data(), ".data", 5);
    data.virtualAddress = { 0x1000 };
    data.virtualSize = 0x100;
    data.rawSize = 0x100;
    data.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    layout.sections.push_back(data);

    RuntimeModuleSnapshot runtime{};
    RuntimeModule module{};
    module.moduleName = "kernel32.dll";
    module.imageSize = 0x1000;
    module.exports.push_back({ "kernel32.dll", { 0x180001000 }, "createfilew", static_cast<std::uint16_t>(1), true, std::nullopt });
    module.exports.push_back({ "kernel32.dll", { 0x180001100 }, "closehandle", static_cast<std::uint16_t>(2), true, std::nullopt });
    runtime.modules.push_back(module);
    auto first = 0x180001000ull;
    auto second = 0x180001100ull;
    std::memcpy(image.data() + 0x1020, &first, sizeof(first));
    std::memcpy(image.data() + 0x1028, &second, sizeof(second));
    auto result = ImportDiscovery::Discover(image, layout, runtime);
    Expect(result.Succeeded(), "contiguous runtime IAT slots are discovered");
    Expect(result.plan && result.plan->modules.size() == 1 && result.plan->modules[0].symbols.size() == 2,
        "contiguous slots form one module plan");

    auto directoryImage = std::vector<std::byte>(0x3000);
    auto directoryLayout = layout;
    directoryLayout.directories[IMAGE_DIRECTORY_ENTRY_IAT] = { { 0x1000 }, 0x18 };
    std::memcpy(directoryImage.data() + 0x1000, &first, sizeof(first));
    std::memcpy(directoryImage.data() + 0x1008, &second, sizeof(second));
    auto directoryResult = ImportDiscovery::Discover(
        directoryImage, directoryLayout, runtime);
    Expect(directoryResult.Succeeded() &&
        directoryResult.plan &&
        directoryResult.plan->modules.size() == 1 &&
        directoryResult.plan->modules[0].firstThunk.value == 0x1000 &&
        directoryResult.plan->modules[0].symbols.size() == 2,
        "declared IAT range is authoritative even when it starts at the section boundary");

    std::uint64_t unknown = 0x12345678;
    std::uint64_t zero{};
    std::memcpy(image.data() + 0x1020, &zero, sizeof(zero));
    std::memcpy(image.data() + 0x1028, &zero, sizeof(zero));
    std::memcpy(image.data() + 0x1050, &unknown, sizeof(unknown));
    auto negative = ImportDiscovery::Discover(image, layout, runtime);
    Expect(!negative.Succeeded(), "unmatched pointers do not produce an import plan");
    return failures;
}
