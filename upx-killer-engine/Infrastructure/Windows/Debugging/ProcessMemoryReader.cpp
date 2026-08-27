#include "Infrastructure/Windows/Debugging/ProcessMemoryReader.h"

namespace
{
    bool IsReadable(DWORD protection) noexcept
    {
        if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0) return false;
        auto const access = protection & 0xffu;
        return access == PAGE_READONLY || access == PAGE_READWRITE || access == PAGE_WRITECOPY ||
            access == PAGE_EXECUTE_READ || access == PAGE_EXECUTE_READWRITE || access == PAGE_EXECUTE_WRITECOPY;
    }
}

namespace upx_killer::engine::debugging
{
    dumping::MemoryRegion ProcessMemoryReader::Query(LoadedAddress address) const
    {
        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQueryEx(process_, reinterpret_cast<void const*>(address.value), &information, sizeof(information)) == 0)
            return { address, 0, false };
        return {
            { reinterpret_cast<std::uint64_t>(information.BaseAddress) },
            static_cast<std::uint64_t>(information.RegionSize),
            information.State == MEM_COMMIT && IsReadable(information.Protect)
        };
    }

    std::size_t ProcessMemoryReader::Read(LoadedAddress address, std::span<std::byte> destination) const
    {
        SIZE_T read{};
        if (!ReadProcessMemory(
                process_, reinterpret_cast<void const*>(address.value), destination.data(), destination.size(), &read))
            return static_cast<std::size_t>(read);
        return static_cast<std::size_t>(read);
    }
}
