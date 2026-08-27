#include "Core/PE/Imports/ImportDiscovery.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <tuple>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe;
    using namespace upx_killer::engine::pe::imports;

    constexpr std::size_t MaximumSlots = 16'384;

    std::string NormalizeModule(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (value.find('.') == std::string::npos) value += ".dll";
        return value;
    }

    bool IsWritable(PeSection const& section) noexcept
    {
        return (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    bool IsExecutable(PeSection const& section) noexcept
    {
        return (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    bool Contains(PeSection const& section, RelativeVirtualAddress address) noexcept
    {
        auto const extent = std::max(section.virtualSize, section.rawSize);
        return address.value >= section.virtualAddress.value &&
            address.value - section.virtualAddress.value < extent;
    }

    bool ReadU64(std::span<std::byte const> bytes, std::uint32_t rva, std::uint64_t& value) noexcept
    {
        if (rva > bytes.size() || sizeof(value) > bytes.size() - rva) return false;
        std::memcpy(&value, bytes.data() + rva, sizeof(value));
        return true;
    }

    bool IsZeroSlot(std::span<std::byte const> bytes, std::uint32_t rva) noexcept
    {
        std::uint64_t value{};
        return ReadU64(bytes, rva, value) && value == 0;
    }

    struct Match
    {
        std::string module;
        ImportSymbol symbol;
    };

    struct AddressEntry
    {
        std::vector<Match> matches;
    };

    bool AddMatch(std::map<std::uint64_t, AddressEntry>& index, RuntimeExport const& exported)
    {
        if (!exported.executable || exported.address.value == 0 || exported.moduleName.empty()) return true;
        if (!exported.name && !exported.ordinal) return true;
        ImportSymbol symbol{};
        symbol.name = exported.name;
        if (!symbol.name) symbol.ordinal = exported.ordinal;
        auto& entry = index[exported.address.value];
        auto const module = NormalizeModule(exported.moduleName);
        // A DLL may expose multiple aliases at one address. They are
        // equivalent for rebuilding the IAT; ambiguity only remains when
        // different provider modules claim the same runtime address.
        auto const duplicateModule = std::find_if(entry.matches.begin(), entry.matches.end(), [&](Match const& existing) {
            return existing.module == module;
        });
        if (duplicateModule == entry.matches.end()) entry.matches.push_back({ module, std::move(symbol) });
        return true;
    }

    bool AddCandidate(
        std::vector<ImportModulePlan>& modules,
        std::uint32_t firstThunk,
        std::vector<Match> const& matches)
    {
        if (matches.empty()) return false;
        if (matches.size() != 1) return false;
        auto const& match = matches.front();
        if (match.module.empty() || (!match.symbol.name && !match.symbol.ordinal)) return false;

        if (!modules.empty() && modules.back().moduleName == match.module &&
            modules.back().firstThunk.value + modules.back().symbols.size() * sizeof(ULONGLONG) == firstThunk)
        {
            modules.back().symbols.push_back(match.symbol);
            return true;
        }
        ImportModulePlan module{};
        module.moduleName = match.module;
        module.firstThunk = { firstThunk };
        module.symbols.push_back(match.symbol);
        modules.push_back(std::move(module));
        return true;
    }
}

namespace upx_killer::engine::pe::imports
{
    ImportDiscoveryResult ImportDiscovery::Discover(
        std::span<std::byte const> dumpedBytes,
        PeImageLayout const& sourceLayout,
        RuntimeModuleSnapshot const& runtime) noexcept
    {
        try
        {
            if (dumpedBytes.size() < sourceLayout.sizeOfImage || sourceLayout.sizeOfImage == 0)
                return { std::nullopt, ImportDiscoveryError::InvalidInput, {} };

            std::map<std::uint64_t, AddressEntry> addressIndex;
            for (auto const& module : runtime.modules)
            {
                if (module.moduleName.empty() || module.imageSize == 0) continue;
                for (auto const& exported : module.exports) AddMatch(addressIndex, exported);
            }

            std::vector<ImportModulePlan> plans;
            std::size_t matchedSlots{};
            for (auto const& section : sourceLayout.sections)
            {
                auto const& importDirectory = sourceLayout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
                auto const& iatDirectory = sourceLayout.directories[IMAGE_DIRECTORY_ENTRY_IAT];
                auto const importSection = Contains(section, importDirectory.address) || Contains(section, iatDirectory.address);
                // Linkers commonly place the bound IAT in read-only .rdata;
                // after loader resolution it is still authoritative data.
                // Scan every non-executable section, while retaining strict
                // run and export-address validation below.
                if ((!IsWritable(section) && !importSection && (section.characteristics & IMAGE_SCN_MEM_READ) == 0) ||
                    IsExecutable(section) || section.virtualAddress.value >= sourceLayout.sizeOfImage)
                    continue;
                auto const extent = std::min(
                    std::max(section.virtualSize, section.rawSize),
                    sourceLayout.sizeOfImage - section.virtualAddress.value);
                if (extent < sizeof(ULONGLONG)) continue;
                // PE section RVAs need not be 8-byte aligned (the target's
                // IAT may start at RVA+4), so probe every byte offset.
                auto rva = section.virtualAddress.value;
                auto const end = section.virtualAddress.value + extent - sizeof(ULONGLONG);
                while (rva <= end)
                {
                    std::uint64_t target{};
                    if (!ReadU64(dumpedBytes, rva, target) || target == 0)
                    {
                        ++rva;
                        continue;
                    }
                    auto const found = addressIndex.find(target);
                    if (found == addressIndex.end())
                    {
                        ++rva;
                        continue;
                    }

                    auto runEnd = rva;
                    std::size_t runLength{};
                    while (runEnd <= end)
                    {
                        std::uint64_t runTarget{};
                        if (!ReadU64(dumpedBytes, runEnd, runTarget) || runTarget == 0) break;
                        auto const runMatch = addressIndex.find(runTarget);
                        if (runMatch == addressIndex.end() || runMatch->second.matches.size() != 1 ||
                            runMatch->second.matches.front().module != found->second.matches.front().module)
                            break;
                        ++runLength;
                        runEnd += sizeof(ULONGLONG);
                    }

                    auto const single = runLength == 1;
                    auto const bounded = rva >= section.virtualAddress.value + sizeof(ULONGLONG) &&
                        runEnd <= end && IsZeroSlot(dumpedBytes, rva - sizeof(ULONGLONG)) && IsZeroSlot(dumpedBytes, runEnd);
                    if (runLength < 2 && !(single && bounded))
                    {
                        if (found->second.matches.size() > 1)
                            return { std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {} };
                        ++rva;
                        continue;
                    }

                    for (auto slot = rva; slot < runEnd; slot += sizeof(ULONGLONG))
                    {
                        std::uint64_t slotTarget{};
                        if (!ReadU64(dumpedBytes, slot, slotTarget))
                            return { std::nullopt, ImportDiscoveryError::InvalidInput, {} };
                        auto const slotMatch = addressIndex.find(slotTarget);
                        if (slotMatch == addressIndex.end() || slotMatch->second.matches.size() != 1 ||
                            !AddCandidate(plans, slot, slotMatch->second.matches))
                            return { std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {} };
                        ++matchedSlots;
                        if (matchedSlots > MaximumSlots)
                            return { std::nullopt, ImportDiscoveryError::InvalidInput, {} };
                    }
                    rva = runEnd;
                }
            }

            if (plans.empty())
            {
                auto const& importDirectory = sourceLayout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDirectory.address.value == 0 && importDirectory.size == 0)
                    return { ImportRebuildPlan{}, ImportDiscoveryError::None, {} };
                return { std::nullopt, ImportDiscoveryError::ImportsNotFound, {} };
            }
            ImportRebuildPlan plan{};
            plan.modules = std::move(plans);
            return { std::move(plan), ImportDiscoveryError::None, {} };
        }
        catch (...)
        {
            return { std::nullopt, ImportDiscoveryError::InvalidInput, {} };
        }
    }
}
