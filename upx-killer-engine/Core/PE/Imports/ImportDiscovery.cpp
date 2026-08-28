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
        Match const& match)
    {
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

    std::vector<std::string> CommonModules(
        std::vector<Match> const& current,
        std::vector<std::string> const& previous)
    {
        std::vector<std::string> result;
        for (auto const& match : current)
        {
            if (previous.empty() || std::find(previous.begin(), previous.end(), match.module) != previous.end())
                result.push_back(match.module);
        }
        return result;
    }

    Match const* FindModuleMatch(AddressEntry const& entry, std::string const& module)
    {
        auto const found = std::find_if(entry.matches.begin(), entry.matches.end(),
            [&](Match const& match) { return match.module == module; });
        return found == entry.matches.end() ? nullptr : &*found;
    }
    int ModulePriority(std::string const& module) noexcept
    {
        if (module.rfind("api-", 0) == 0) return 100;
        if (module == "kernel32.dll" || module == "user32.dll" || module == "advapi32.dll") return 90;
        if (module == "ucrtbase.dll" || module == "vcruntime140.dll" || module == "msvcp140.dll") return 80;
        if (module == "kernelbase.dll" || module == "ntdll.dll") return 10;
        return 50;
    }

    std::optional<std::string> SelectCommonModule(std::vector<std::string> const& modules)
    {
        if (modules.empty()) return std::nullopt;
        auto selected = modules.front();
        auto selectedPriority = ModulePriority(selected);
        bool tie{};
        for (std::size_t index = 1; index < modules.size(); ++index)
        {
            auto const priority = ModulePriority(modules[index]);
            if (priority > selectedPriority)
            {
                selected = modules[index];
                selectedPriority = priority;
                tie = false;
            }
            else if (priority == selectedPriority && modules[index] != selected)
            {
                tie = true;
            }
        }
        if (tie) return std::nullopt;
        return selected;
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
                // Packed images may keep the unpacked IAT in an executable
                // writable section.  Writability is the authority here;
                // strict run and export-address validation prevents code
                // bytes from becoming import candidates.
                if ((!IsWritable(section) && !importSection && (section.characteristics & IMAGE_SCN_MEM_READ) == 0) ||
                    section.virtualAddress.value >= sourceLayout.sizeOfImage)
                    continue;
                auto const extent = std::min(
                    std::max(section.virtualSize, section.rawSize),
                    sourceLayout.sizeOfImage - section.virtualAddress.value);
                if (extent < sizeof(ULONGLONG)) continue;
                auto const sectionStart =
                    static_cast<std::uint64_t>(section.virtualAddress.value);
                auto const sectionEnd = sectionStart + extent;
                auto scanStart = sectionStart;
                auto scanEnd = sectionEnd;
                bool declaredIatRange{};
                if (iatDirectory.address.value != 0 || iatDirectory.size != 0)
                {
                    if (iatDirectory.address.value == 0 ||
                        iatDirectory.size < sizeof(ULONGLONG))
                    {
                        return {
                            std::nullopt,
                            ImportDiscoveryError::InvalidInput,
                            {}
                        };
                    }
                    auto const iatStart =
                        static_cast<std::uint64_t>(iatDirectory.address.value);
                    auto const iatEnd = iatStart + iatDirectory.size;
                    if (iatEnd > sourceLayout.sizeOfImage)
                    {
                        return {
                            std::nullopt,
                            ImportDiscoveryError::InvalidInput,
                            {}
                        };
                    }
                    if (iatStart >= sectionEnd || iatEnd <= sectionStart)
                        continue;
                    scanStart = std::max(scanStart, iatStart);
                    scanEnd = std::min(scanEnd, iatEnd);
                    declaredIatRange = true;
                }
                if (scanEnd - scanStart < sizeof(ULONGLONG)) continue;
                // PE section RVAs need not be 8-byte aligned (the target's
                // IAT may start at RVA+4), so probe every byte offset.
                auto rva = static_cast<std::uint32_t>(scanStart);
                auto const end = static_cast<std::uint32_t>(
                    scanEnd - sizeof(ULONGLONG));
                while (rva <= end)
                {
                    // UPX keeps its packed import descriptors and stale IAT
                    // in the import section while the unpacked image writes
                    // the real IAT elsewhere.  When the source has no IAT
                    // directory, ignore that metadata tail to avoid creating
                    // overlapping plans for both tables.
                    if (iatDirectory.address.value == 0 &&
                        importDirectory.address.value != 0 &&
                        Contains(section, importDirectory.address) &&
                        rva >= importDirectory.address.value)
                    {
                        break;
                    }
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


                    auto commonModules = std::vector<std::string>{};
                    for (auto const& match : found->second.matches) commonModules.push_back(match.module);
                    auto runEnd = rva;
                    std::size_t runLength{};
                    while (runEnd <= end)
                    {
                        std::uint64_t runTarget{};
                        if (!ReadU64(dumpedBytes, runEnd, runTarget) || runTarget == 0) break;
                        auto const runMatch = addressIndex.find(runTarget);
                        if (runMatch == addressIndex.end()) break;
                        commonModules = CommonModules(runMatch->second.matches, commonModules);
                        if (commonModules.empty()) break;
                        ++runLength;
                        runEnd += sizeof(ULONGLONG);
                    }

                    auto const bounded = rva >= section.virtualAddress.value + sizeof(ULONGLONG) &&
                        runEnd <= end && IsZeroSlot(dumpedBytes, rva - sizeof(ULONGLONG)) && IsZeroSlot(dumpedBytes, runEnd);
                    // A declared IAT directory is an authoritative scan range.
                    // Broad packed-image scans still require zero boundaries
                    // to avoid mistaking code/data pointers for thunk arrays.
                    if (runLength == 0 || (!declaredIatRange && !bounded))
                    {
                        if (found->second.matches.size() > 1)
                            return { std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {} };
                        ++rva;
                        continue;
                    }
                    auto selectedModule = SelectCommonModule(commonModules);
                    if (!selectedModule)
                        return { std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {} };

                    auto const& module = *selectedModule;
                    for (auto slot = rva; slot < runEnd; slot += sizeof(ULONGLONG))
                    {
                        std::uint64_t slotTarget{};
                        if (!ReadU64(dumpedBytes, slot, slotTarget))
                            return { std::nullopt, ImportDiscoveryError::InvalidInput, {} };
                        auto const slotMatch = addressIndex.find(slotTarget);
                        if (slotMatch == addressIndex.end())
                            return { std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {} };
                        auto const* match = FindModuleMatch(slotMatch->second, module);
                        if (!match || !AddCandidate(plans, slot, *match))
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
