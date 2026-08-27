#include "Core/PE/OepDiscovery/UpxOepLocator.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace
{
    using namespace upx_killer::engine;

    int failures{};

    void Expect(bool condition, std::string_view message)
    {
        if (!condition)
        {
            ++failures;
            std::cerr << "FAIL: " << message << '\n';
        }
    }

    pe::PeSection Section(
        char const* name,
        std::uint32_t virtualAddress,
        std::uint32_t virtualSize,
        std::uint32_t rawOffset,
        std::uint32_t rawSize,
        std::uint32_t characteristics)
    {
        pe::PeSection section{};
        std::memcpy(section.name.data(), name, std::min<std::size_t>(std::strlen(name), section.name.size()));
        section.virtualAddress = { virtualAddress };
        section.virtualSize = virtualSize;
        section.rawOffset = { rawOffset };
        section.rawSize = rawSize;
        section.characteristics = characteristics;
        return section;
    }

    struct UpxLikeImage
    {
        std::vector<std::byte> bytes = std::vector<std::byte>(0x800);
        pe::PeImageLayout layout{};

        UpxLikeImage()
        {
            layout.entryPoint = { 0x2100 };
            layout.sizeOfImage = 0x4000;
            layout.sections.push_back(Section("UPX0", 0x1000, 0x1000, 0, 0, 0xE0000080));
            layout.sections.push_back(Section("UPX1", 0x2000, 0x1000, 0x200, 0x400, 0x60000020));
            std::memcpy(bytes.data() + 0x240, "UPX!", 4);
            auto const epilogueOffset = std::size_t{ 0x380 };
            std::array<std::uint8_t, 5> const prefix{ 0x5d, 0x5f, 0x5e, 0x5b, 0xe9 };
            std::memcpy(bytes.data() + epilogueOffset, prefix.data(), prefix.size());
            auto const transferRva = std::uint32_t{ 0x2184 };
            auto const targetRva = std::uint32_t{ 0x1100 };
            auto const displacement = static_cast<std::int32_t>(targetRva - (transferRva + 5));
            std::memcpy(bytes.data() + epilogueOffset + prefix.size(), &displacement, sizeof(displacement));
        }
    };

    void WriteTailTransfer(UpxLikeImage& image, std::size_t offset, std::uint32_t targetRva)
    {
        std::array<std::uint8_t, 5> const prefix{ 0x5d, 0x5f, 0x5e, 0x5b, 0xe9 };
        std::memcpy(image.bytes.data() + offset, prefix.data(), prefix.size());
        auto const transferRva = image.layout.sections[1].virtualAddress.value +
            static_cast<std::uint32_t>(offset - image.layout.sections[1].rawOffset.value) + 4;
        auto const displacement = static_cast<std::int32_t>(targetRva - (transferRva + 5));
        std::memcpy(image.bytes.data() + offset + prefix.size(), &displacement, sizeof(displacement));
    }
}

int RunOepDiscoveryTests()
{
    UpxLikeImage image;
    auto result = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(image.bytes, image.layout);
    Expect(result.Succeeded(), "UPX x64 tail transfer creates a discovery plan");
    Expect(result.plan && result.plan->candidates.size() == 1, "discovery returns one bounded candidate");
    if (result.plan && !result.plan->candidates.empty())
    {
        Expect(result.plan->candidates.front().transfer.value == 0x2184, "transfer RVA is preserved");
        Expect(result.plan->candidates.front().target.value == 0x1100, "known OEP RVA is decoded");
    }

    std::memcpy(image.layout.sections[0].name.data(), ".text", 5);
    std::memcpy(image.layout.sections[1].name.data(), ".stub", 5);
    image.layout.sections[0].virtualSize = 0x200;
    image.layout.sections[0].rawOffset = { 0x600 };
    image.layout.sections[0].rawSize = 0x200;
    std::fill(image.bytes.begin() + 0x240, image.bytes.begin() + 0x244, std::byte{});
    auto ordinary = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(image.bytes, image.layout);
    Expect(ordinary.error == upx_killer::engine::pe::oep::OepDiscoveryError::UnsupportedPacker,
        "ordinary PE is not treated as UPX");

    UpxLikeImage renamed;
    std::fill(renamed.layout.sections[0].name.begin(), renamed.layout.sections[0].name.end(), '\0');
    std::fill(renamed.layout.sections[1].name.begin(), renamed.layout.sections[1].name.end(), '\0');
    std::memcpy(renamed.layout.sections[0].name.data(), "AAAA", 4);
    std::memcpy(renamed.layout.sections[1].name.data(), "AAAA", 4);
    auto renamedResult = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(renamed.bytes, renamed.layout);
    Expect(renamedResult.Succeeded(), "renamed UPX sections retain structural discovery");

    std::fill(renamed.bytes.begin() + 0x240, renamed.bytes.begin() + 0x244, std::byte{});
    auto structuralResult = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(renamed.bytes, renamed.layout);
    Expect(structuralResult.Succeeded(), "sparse executable destination supports marker-free UPX variant");

    UpxLikeImage outsideImage;
    WriteTailTransfer(outsideImage, 0x380, 0x5000);
    auto outsideResult = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(outsideImage.bytes, outsideImage.layout);
    Expect(outsideResult.error == upx_killer::engine::pe::oep::OepDiscoveryError::OepNotFound,
        "tail transfer outside the image is rejected");

    UpxLikeImage intoStub;
    WriteTailTransfer(intoStub, 0x380, 0x2200);
    auto stubResult = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(intoStub.bytes, intoStub.layout);
    Expect(stubResult.error == upx_killer::engine::pe::oep::OepDiscoveryError::OepNotFound,
        "tail transfer back into the stub is rejected");

    UpxLikeImage nonExecutable;
    nonExecutable.layout.sections[0].characteristics = 0xC0000080;
    auto nonExecutableResult = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(
        nonExecutable.bytes, nonExecutable.layout);
    Expect(nonExecutableResult.error == upx_killer::engine::pe::oep::OepDiscoveryError::OepNotFound,
        "non-executable OEP destination is rejected");

    UpxLikeImage truncated;
    truncated.bytes.resize(0x400);
    auto truncatedResult = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(truncated.bytes, truncated.layout);
    Expect(truncatedResult.error == upx_killer::engine::pe::oep::OepDiscoveryError::OepNotFound,
        "truncated stub bytes are rejected without reading out of bounds");

    UpxLikeImage bounded;
    std::fill(bounded.bytes.begin() + 0x300, bounded.bytes.begin() + 0x600, std::byte{});
    for (std::size_t index = 0; index < 40; ++index)
        WriteTailTransfer(bounded, 0x300 + index * 9, 0x1100);
    auto boundedResult = upx_killer::engine::pe::oep::UpxOepLocator::Analyze(bounded.bytes, bounded.layout);
    Expect(boundedResult.plan && boundedResult.plan->candidates.size() ==
        upx_killer::engine::pe::oep::MaximumOepCandidates,
        "discovery never emits more than the configured candidate limit");
    return failures;
}
