#include "Infrastructure/Windows/Debugging/RemoteModuleCatalog.h"

#include "Core/PE/Imports/PeExportParser.h"

#include <TlHelp32.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe::imports;

    constexpr std::size_t MaxModules = 256;
    constexpr std::uint32_t MaxImageSize = 256u * 1024u * 1024u;
    constexpr std::size_t MaxForwardDepth = 8;

    std::string Normalize(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (value.find('.') == std::string::npos) value += ".dll";
        return value;
    }

    bool EqualName(std::string const& left, std::string const& right) noexcept
    {
        if (left.size() != right.size()) return false;
        return std::equal(left.begin(), left.end(), right.begin(), [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
        });
    }

    std::string Narrow(std::wstring value)
    {
        if (value.size() > 260) value.resize(260);
        std::string result;
        result.reserve(value.size());
        for (auto c : value) result.push_back(c < 128 ? static_cast<char>(c) : '?');
        return result;
    }

    bool ReadRemote(HANDLE process, std::uint64_t address, std::span<std::byte> destination) noexcept
    {
        SIZE_T read{};
        return ReadProcessMemory(process, reinterpret_cast<void const*>(address), destination.data(), destination.size(), &read) &&
            read == destination.size();
    }

    bool ResolveExport(
        RuntimeModuleSnapshot const& snapshot,
        RuntimeExport const& input,
        RuntimeExport& resolved,
        std::size_t depth)
    {
        if (depth > MaxForwardDepth) return false;
        if (!input.forwarder)
        {
            if (!input.executable || input.address.value == 0) return false;
            resolved = input;
            return true;
        }
        auto const separator = input.forwarder->find('.');
        if (separator == std::string::npos) return false;
        auto moduleName = Normalize(input.forwarder->substr(0, separator));
        auto symbol = input.forwarder->substr(separator + 1);
        std::optional<std::uint16_t> ordinal;
        std::optional<std::string> name;
        if (!symbol.empty() && symbol[0] == '#')
        {
            try { ordinal = static_cast<std::uint16_t>(std::stoul(symbol.substr(1))); }
            catch (...) { return false; }
        }
        else if (!symbol.empty()) name = symbol;
        else return false;

        RuntimeExport const* match{};
        for (auto const& module : snapshot.modules)
        {
            if (Normalize(module.moduleName) != moduleName) continue;
            for (auto const& candidate : module.exports)
            {
                if ((name && candidate.name && EqualName(*candidate.name, *name)) || (ordinal && candidate.ordinal == ordinal))
                {
                    if (match) return false;
                    match = &candidate;
                }
            }
        }
        // API-set forwarders are often represented by a contract name that is
        // absent from the module list; resolve them against a unique provider.
        if (!match && moduleName.rfind("api-", 0) == 0)
        {
            for (auto const& module : snapshot.modules)
                for (auto const& candidate : module.exports)
                    if ((name && candidate.name && EqualName(*candidate.name, *name)) || (ordinal && candidate.ordinal == ordinal))
                    {
                        if (match) return false;
                        match = &candidate;
                    }
        }
        if (!match) return false;
        return ResolveExport(snapshot, *match, resolved, depth + 1);
    }
}

namespace upx_killer::engine::debugging
{
    RemoteModuleCatalogResult RemoteModuleCatalog::Capture(HANDLE process, DWORD processId) noexcept
    {
        RemoteModuleCatalogResult result{};
        if (!process || process == INVALID_HANDLE_VALUE || processId == 0)
        {
            result.nativeError = ERROR_INVALID_PARAMETER;
            return result;
        }
        HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            result.nativeError = GetLastError();
            return result;
        }
        MODULEENTRY32W entry{ sizeof(entry) };
        if (!Module32FirstW(snapshotHandle, &entry))
        {
            result.nativeError = GetLastError();
            CloseHandle(snapshotHandle);
            return result;
        }
        do
        {
            if (result.snapshot.modules.size() >= MaxModules)
            {
                result.nativeError = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }
            auto const imageSize = static_cast<std::uint32_t>(entry.modBaseSize);
            if (imageSize == 0 || imageSize > MaxImageSize) continue;
            std::vector<std::byte> image(imageSize);
            if (!ReadRemote(process, reinterpret_cast<std::uint64_t>(entry.modBaseAddr), image)) continue;
            auto moduleName = Normalize(Narrow(entry.szModule));
            auto parsed = pe::imports::PeExportParser::Parse(image, { reinterpret_cast<std::uint64_t>(entry.modBaseAddr) }, moduleName);
            if (!parsed.Succeeded()) continue;
            RuntimeModule module{};
            module.moduleName = moduleName;
            module.base = { reinterpret_cast<std::uint64_t>(entry.modBaseAddr) };
            module.imageSize = imageSize;
            module.exports = std::move(parsed.exports);
            result.snapshot.modules.push_back(std::move(module));
        } while (Module32NextW(snapshotHandle, &entry));
        CloseHandle(snapshotHandle);
        if (result.nativeError != ERROR_SUCCESS) return result;

        RuntimeModuleSnapshot resolved = result.snapshot;
        for (auto& module : resolved.modules)
        {
            std::vector<RuntimeExport> filtered;
            filtered.reserve(module.exports.size());
            for (auto const& exported : module.exports)
            {
                RuntimeExport value{};
                if (!ResolveExport(resolved, exported, value, 0)) continue;
                value.moduleName = value.moduleName.empty() ? module.moduleName : value.moduleName;
                filtered.push_back(std::move(value));
            }
            module.exports = std::move(filtered);
        }
        result.snapshot = std::move(resolved);
        return result;
    }
}
