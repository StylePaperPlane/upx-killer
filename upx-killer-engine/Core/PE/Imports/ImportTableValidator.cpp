#include "Core/PE/Imports/ImportTableValidator.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe;

    bool ToRaw(PeImageLayout const& layout, std::uint32_t rva, std::size_t size, std::size_t& raw) noexcept
    {
        if (rva < layout.sizeOfHeaders)
        {
            raw = rva;
            return true;
        }
        for (auto const& section : layout.sections)
        {
            auto const extent = std::max(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress.value && size <= extent && rva - section.virtualAddress.value <= extent - size)
            {
                raw = static_cast<std::size_t>(section.rawOffset.value) + (rva - section.virtualAddress.value);
                return true;
            }
        }
        return false;
    }

    bool InSection(PeImageLayout const& layout, std::uint32_t rva, std::uint32_t size, PeSection const** owner = nullptr) noexcept
    {
        for (auto const& section : layout.sections)
        {
            auto const extent = std::max(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress.value && size <= extent && rva - section.virtualAddress.value <= extent - size)
            {
                if (owner) *owner = &section;
                return true;
            }
        }
        return false;
    }

    bool StringAt(std::span<std::byte const> bytes, PeImageLayout const& layout, std::uint32_t rva) noexcept
    {
        std::size_t raw{};
        if (!ToRaw(layout, rva, 1, raw) || raw >= bytes.size()) return false;
        auto const* begin = reinterpret_cast<char const*>(bytes.data() + raw);
        auto const remaining = bytes.size() - raw;
        return std::memchr(begin, '\0', remaining) != nullptr;
    }
}

namespace upx_killer::engine::pe::imports
{
    bool ImportTableValidator::Validate(std::span<std::byte const> image, PeImageLayout const& layout) noexcept
    {
        try
        {
            auto const import = layout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
            auto const iat = layout.directories[IMAGE_DIRECTORY_ENTRY_IAT];
            auto const delay = layout.directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
            auto const bound = layout.directories[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
            if ((delay.address.value != 0 || delay.size != 0) || (bound.address.value != 0 || bound.size != 0)) return false;
            if (import.address.value == 0 || import.size == 0)
                return iat.address.value == 0 && iat.size == 0;
            if (import.size < sizeof(IMAGE_IMPORT_DESCRIPTOR) || !InSection(layout, import.address.value, import.size)) return false;
            bool terminated{};
            for (std::uint32_t offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= import.size; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
            {
                IMAGE_IMPORT_DESCRIPTOR descriptor{};
                std::size_t raw{};
                if (!ToRaw(layout, import.address.value + offset, sizeof(descriptor), raw) || raw > image.size() || sizeof(descriptor) > image.size() - raw) return false;
                std::memcpy(&descriptor, image.data() + raw, sizeof(descriptor));
                if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 && descriptor.Name == 0)
                {
                    terminated = true;
                    break;
                }
                if (descriptor.Name == 0 || !InSection(layout, descriptor.Name, 1) || !StringAt(image, layout, descriptor.Name)) return false;
                if (descriptor.FirstThunk == 0 || !InSection(layout, descriptor.FirstThunk, sizeof(ULONGLONG))) return false;
                auto const intRva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
                if (!InSection(layout, intRva, sizeof(ULONGLONG))) return false;
                bool thunkTerminated{};
                for (std::uint32_t index = 0; index < 65'536; ++index)
                {
                    ULONGLONG thunk{};
                    if (index > (std::numeric_limits<std::uint32_t>::max() - intRva) / sizeof(thunk)) return false;
                    auto const thunkRva = intRva + index * static_cast<std::uint32_t>(sizeof(thunk));
                    if (!ToRaw(layout, thunkRva, sizeof(thunk), raw) || raw > image.size() || sizeof(thunk) > image.size() - raw) return false;
                    std::memcpy(&thunk, image.data() + raw, sizeof(thunk));
                    if (thunk == 0) { thunkTerminated = true; break; }
                    if ((thunk & IMAGE_ORDINAL_FLAG64) == 0)
                    {
                        auto const nameRva = static_cast<std::uint32_t>(thunk);
                        if (!InSection(layout, nameRva, sizeof(WORD) + 1) || !StringAt(image, layout, nameRva + sizeof(WORD))) return false;
                    }
                    if (index > (std::numeric_limits<std::uint32_t>::max() - descriptor.FirstThunk) / sizeof(thunk)) return false;
                    if (!InSection(layout, descriptor.FirstThunk + index * static_cast<std::uint32_t>(sizeof(thunk)), static_cast<std::uint32_t>(sizeof(thunk)))) return false;
                }
                if (!thunkTerminated) return false;
            }
            if (!terminated) return false;
            if (iat.address.value != 0 || iat.size != 0)
                if (!InSection(layout, iat.address.value, iat.size)) return false;
            return true;
        }
        catch (...) { return false; }
    }
}
