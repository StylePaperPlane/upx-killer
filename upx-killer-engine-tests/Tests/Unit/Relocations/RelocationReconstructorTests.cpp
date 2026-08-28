#include "Core/PE/Relocations/RelocationReconstructor.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace
{
    using namespace upx_killer::engine;

    void PutPointer(std::vector<std::byte>& bytes, std::uint32_t rva, std::uint64_t value)
    {
        std::memcpy(bytes.data() + rva, &value, sizeof(value));
    }
}

int RunRelocationReconstructorTests()
{
    using namespace upx_killer::engine;
    int failures{};
    auto expect = [&](bool condition, std::string_view message)
    {
        if (!condition)
        {
            ++failures;
            std::cerr << "FAILED: " << message << '\n';
        }
    };

    constexpr std::uint32_t imageSize = 0x3000;
    std::vector<std::vector<std::byte>> images;
    std::vector<pe::relocations::LoadedImageSnapshot> snapshots;
    for (auto const base : { 0x140000000ull, 0x180000000ull, 0x1c0000000ull })
    {
        images.emplace_back(imageSize);
        PutPointer(images.back(), 0x1023, base + 0x1500);
        PutPointer(images.back(), 0x1800, base + 0x1700);
        PutPointer(images.back(), 0x1810, base + 0x1650);
    }
    images[1][0x1f00] = std::byte{ 0x55 };
    for (std::size_t index = 0; index < images.size(); ++index)
        snapshots.push_back({ { 0x140000000ull + index * 0x40000000ull }, images[index] });

    std::vector<pe::rebasing::SourceRelocationSlot> sourceSlots{
        { { 0x1800 }, RelativeVirtualAddress{ 0x1700 } },
        { { 0x1810 }, RelativeVirtualAddress{ 0x1600 } },
    };
    auto rebuilt = pe::relocations::RelocationReconstructor::Reconstruct(
        snapshots, sourceSlots, 0x200, imageSize, LoadedAddress{ 0x140000000ull });
    expect(rebuilt.Succeeded(), "three controlled-base snapshots reconstruct relocation evidence");
    if (rebuilt.plan)
    {
        expect(rebuilt.plan->slots.size() == 2, "only genuine unpacked relocation slots remain");
        expect(rebuilt.plan->slots[0].location.value == 0x1023 &&
            rebuilt.plan->slots[0].imageTarget.value == 0x1500,
            "unaligned DIR64 slot is recovered");
        expect(rebuilt.plan->slots[1].location.value == 0x1810 &&
            rebuilt.plan->slots[1].imageTarget.value == 0x1650,
            "a source slot overwritten by unpacked content remains genuine");
        expect(!rebuilt.plan->directoryBytes.empty(), "standard relocation blocks are encoded");
        auto const* first = reinterpret_cast<IMAGE_BASE_RELOCATION const*>(rebuilt.plan->directoryBytes.data());
        expect(first->VirtualAddress == 0x1000 && first->SizeOfBlock >= 12,
            "relocation entries are grouped by 4 KiB page");
    }

    snapshots.pop_back();
    auto insufficient = pe::relocations::RelocationReconstructor::Reconstruct(
        snapshots, sourceSlots, 0x200, imageSize, LoadedAddress{ 0x140000000ull });
    expect(insufficient.error == pe::relocations::RelocationRebuildError::EvidenceInsufficient,
        "two snapshots are not accepted as complete evidence");
    return failures;
}
