#pragma once

#include "Core/Unpacking/UnpackTypes.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::engine::pe
{
    constexpr std::size_t PeDirectoryCount = 16;

    enum class PeError
    {
        None,
        Truncated,
        InvalidSignature,
        UnsupportedPe32,
        UnsupportedArchitecture,
        UnsupportedImageKind,
        InvalidAlignment,
        InvalidSectionTable,
        ImageTooLarge,
    };

    struct PeDataDirectory
    {
        RelativeVirtualAddress address;
        std::uint32_t size{};
    };

    struct PeSection
    {
        std::array<char, 8> name{};
        RelativeVirtualAddress virtualAddress;
        std::uint32_t virtualSize{};
        FileOffset rawOffset;
        std::uint32_t rawSize{};
        std::uint32_t characteristics{};
    };

    struct PeImageLayout
    {
        std::uint32_t ntHeaderOffset{};
        std::uint64_t preferredImageBase{};
        RelativeVirtualAddress entryPoint;
        std::uint32_t sizeOfImage{};
        std::uint32_t sizeOfHeaders{};
        std::uint32_t sectionAlignment{};
        std::uint32_t fileAlignment{};
        std::uint16_t characteristics{};
        std::array<PeDataDirectory, PeDirectoryCount> directories{};
        std::vector<PeSection> sections;
    };

    struct PeParseResult
    {
        std::optional<PeImageLayout> layout;
        PeError error{ PeError::None };

        [[nodiscard]] bool Succeeded() const noexcept { return layout.has_value(); }
    };

    class PeParser final
    {
    public:
        [[nodiscard]] static PeParseResult Parse(std::span<std::byte const> bytes) noexcept;
    };
}
