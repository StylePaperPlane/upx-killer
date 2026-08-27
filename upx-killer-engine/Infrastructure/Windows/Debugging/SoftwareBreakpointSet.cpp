#include "Infrastructure/Windows/Debugging/SoftwareBreakpointSet.h"

#include <algorithm>

namespace upx_killer::engine::debugging
{
    SoftwareBreakpointSet::~SoftwareBreakpointSet()
    {
        std::uint32_t ignored{};
        while (!breakpoints_.empty())
        {
            auto const address = breakpoints_.back().address;
            if (!Restore(address, ignored)) breakpoints_.pop_back();
        }
    }

    bool SoftwareBreakpointSet::Install(
        std::uint64_t address,
        std::uint32_t id,
        std::uint32_t& nativeError) noexcept
    {
        nativeError = ERROR_SUCCESS;
        if (Find(address)) return true;
        std::byte original{};
        SIZE_T read{};
        if (!ReadProcessMemory(process_, reinterpret_cast<void const*>(address), &original, 1, &read) || read != 1)
        {
            nativeError = GetLastError();
            return false;
        }
        std::byte const trap{ 0xcc };
        SIZE_T written{};
        if (!WriteProcessMemory(process_, reinterpret_cast<void*>(address), &trap, 1, &written) || written != 1 ||
            !FlushInstructionCache(process_, reinterpret_cast<void const*>(address), 1))
        {
            nativeError = GetLastError();
            return false;
        }
        breakpoints_.push_back({ address, id, original });
        return true;
    }

    std::optional<std::uint32_t> SoftwareBreakpointSet::Find(std::uint64_t address) const noexcept
    {
        auto const iterator = std::find_if(breakpoints_.begin(), breakpoints_.end(),
            [address](Breakpoint const& breakpoint) { return breakpoint.address == address; });
        if (iterator == breakpoints_.end()) return std::nullopt;
        return iterator->id;
    }

    bool SoftwareBreakpointSet::Restore(std::uint64_t address, std::uint32_t& nativeError) noexcept
    {
        nativeError = ERROR_SUCCESS;
        auto const iterator = std::find_if(breakpoints_.begin(), breakpoints_.end(),
            [address](Breakpoint const& breakpoint) { return breakpoint.address == address; });
        if (iterator == breakpoints_.end()) return true;
        SIZE_T written{};
        if (!WriteProcessMemory(process_, reinterpret_cast<void*>(address), &iterator->original, 1, &written) ||
            written != 1 || !FlushInstructionCache(process_, reinterpret_cast<void const*>(address), 1))
        {
            nativeError = GetLastError();
            return false;
        }
        breakpoints_.erase(iterator);
        return true;
    }
}
