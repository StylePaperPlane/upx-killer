#include "Core/PE/Fixing/PeImageFixer.h"
#include "Core/PE/Sections/SectionLayoutRebuilder.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <limits>
#include <string_view>

namespace
{
    std::uint32_t Align(std::uint32_t value, std::uint32_t alignment)
    {
        auto const mask = alignment - 1;
        if (value > std::numeric_limits<std::uint32_t>::max() - mask) throw std::overflow_error("alignment");
        return (value + mask) & ~mask;
    }

    void Append(std::vector<std::byte>& bytes, void const* data, std::size_t size)
    {
        auto const* first = static_cast<std::byte const*>(data);
        bytes.insert(bytes.end(), first, first + size);
    }

    template <typename T>
    void WriteAt(std::vector<std::byte>& bytes, std::size_t offset, T const& value)
    {
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) throw std::out_of_range("write");
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
    }
}

namespace upx_killer::engine::pe
{
    FixResult PeImageFixer::Rebuild(
        PeImageLayout const& layout,
        dumping::DumpedImage const& dump,
        FixRequest const& request) noexcept
    {
        try
        {
            if (request.oep.value >= layout.sizeOfImage || dump.bytes.size() < layout.sizeOfImage || layout.sections.empty())
                return { std::nullopt, EngineError::OepOutOfRange };
            if (request.relocations.preferredImageBase.value == 0 ||
                request.relocations.slots.empty() ||
                request.relocations.directoryBytes.empty())
                return { std::nullopt, EngineError::RelocationEvidenceInsufficient };

            auto normalizedImage = dump.bytes;
            for (auto const& slot : request.relocations.slots)
            {
                if (slot.location.value >= layout.sizeOfImage ||
                    sizeof(std::uint64_t) > layout.sizeOfImage - slot.location.value ||
                    slot.imageTarget.value >= layout.sizeOfImage ||
                    request.relocations.preferredImageBase.value >
                        std::numeric_limits<std::uint64_t>::max() - slot.imageTarget.value)
                    return { std::nullopt, EngineError::RelocationValidationFailed };
                auto const value =
                    request.relocations.preferredImageBase.value + slot.imageTarget.value;
                WriteAt(normalizedImage, slot.location.value, value);
            }
            auto const sectionLayout = sections::SectionLayoutRebuilder::Build(
                layout,
                { normalizedImage, request.relocations.preferredImageBase, request.oep,
                    request.imports ? &*request.imports : nullptr });
            if (!sectionLayout.plan)
                return { std::nullopt, EngineError::RebuildFailed };

            auto const addImportSection = request.imports.has_value() && !request.imports->modules.empty();
            if (sectionLayout.plan->sections.size() + (addImportSection ? 1u : 0u) + 1u > 96)
                return { std::nullopt, EngineError::RebuildFailed };
            auto const sectionCount = static_cast<std::uint16_t>(
                sectionLayout.plan->sections.size() + (addImportSection ? 1 : 0) + 1);
            auto const sectionTableOffset = static_cast<std::uint32_t>(
                layout.ntHeaderOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64));
            auto const headerSize = Align(
                sectionTableOffset + static_cast<std::uint32_t>(sectionCount * sizeof(IMAGE_SECTION_HEADER)),
                layout.fileAlignment);

            FixedPeImage fixed{};
            fixed.bytes.resize(headerSize);
            std::copy_n(normalizedImage.begin(), std::min<std::size_t>(layout.sizeOfHeaders, fixed.bytes.size()), fixed.bytes.begin());

            std::vector<IMAGE_SECTION_HEADER> sectionHeaders;
            sectionHeaders.reserve(sectionCount);
            std::uint32_t nextRaw = headerSize;
            std::uint32_t highestVirtualEnd{};
            for (auto const& source : sectionLayout.plan->sections)
            {
                IMAGE_SECTION_HEADER section{};
                std::memcpy(section.Name, source.name.data(), source.name.size());
                section.Misc.VirtualSize = source.virtualSize;
                section.VirtualAddress = source.virtualAddress.value;
                auto const available = layout.sizeOfImage - source.virtualAddress.value;
                auto const virtualBytes = std::min<std::uint32_t>(section.Misc.VirtualSize, available);
                section.SizeOfRawData = Align(virtualBytes, layout.fileAlignment);
                section.PointerToRawData = nextRaw;
                section.Characteristics = source.characteristics;
                fixed.bytes.resize(static_cast<std::size_t>(nextRaw) + section.SizeOfRawData);
                std::copy_n(
                    normalizedImage.begin() + source.virtualAddress.value,
                    virtualBytes,
                    fixed.bytes.begin() + nextRaw);
                nextRaw += section.SizeOfRawData;
                highestVirtualEnd = std::max(highestVirtualEnd, Align(section.VirtualAddress + section.Misc.VirtualSize, layout.sectionAlignment));
                sectionHeaders.push_back(section);
            }

            IMAGE_SECTION_HEADER importSection{};
            std::vector<std::byte> importBytes;
            std::uint32_t importDirectorySize{};
            std::uint32_t iatStart = std::numeric_limits<std::uint32_t>::max();
            std::uint32_t iatEnd{};
            std::vector<std::pair<std::uint32_t, std::uint32_t>> iatRanges;
            if (addImportSection)
            {
                auto const importRva = Align(highestVirtualEnd, layout.sectionAlignment);
                auto const descriptorBytes = static_cast<std::uint32_t>((request.imports->modules.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
                importBytes.resize(descriptorBytes);
                importDirectorySize = descriptorBytes;

                for (std::size_t moduleIndex = 0; moduleIndex < request.imports->modules.size(); ++moduleIndex)
                {
                    auto const& module = request.imports->modules[moduleIndex];
                    if (module.moduleName.empty() || module.symbols.empty())
                        return { std::nullopt, EngineError::ImportPlanInvalid };
                    auto const thunkBytes = static_cast<std::uint64_t>(module.symbols.size() + 1) * sizeof(ULONGLONG);
                    if (module.firstThunk.value >= layout.sizeOfImage || thunkBytes > layout.sizeOfImage - module.firstThunk.value)
                        return { std::nullopt, EngineError::ImportPlanInvalid };
                    auto const moduleIatEnd = module.firstThunk.value + static_cast<std::uint32_t>(thunkBytes);
                    for (auto const& [begin, end] : iatRanges)
                    {
                        if (module.firstThunk.value < end && begin < moduleIatEnd)
                            return { std::nullopt, EngineError::ImportPlanInvalid };
                    }
                    iatRanges.emplace_back(module.firstThunk.value, moduleIatEnd);

                    while ((importBytes.size() % alignof(ULONGLONG)) != 0) importBytes.push_back(std::byte{});
                    auto const intOffset = static_cast<std::uint32_t>(importBytes.size());
                    importBytes.resize(importBytes.size() + static_cast<std::size_t>(thunkBytes));
                    auto const moduleNameOffset = static_cast<std::uint32_t>(importBytes.size());
                    Append(importBytes, module.moduleName.c_str(), module.moduleName.size() + 1);

                    for (std::size_t symbolIndex = 0; symbolIndex < module.symbols.size(); ++symbolIndex)
                    {
                        auto const& symbol = module.symbols[symbolIndex];
                        ULONGLONG thunk{};
                        if (symbol.ordinal.has_value() == symbol.name.has_value())
                        {
                            return { std::nullopt, EngineError::ImportPlanInvalid };
                        }
                        if (symbol.ordinal)
                        {
                            thunk = IMAGE_ORDINAL_FLAG64 | *symbol.ordinal;
                        }
                        else
                        {
                            while ((importBytes.size() % alignof(WORD)) != 0) importBytes.push_back(std::byte{});
                            auto const nameOffset = static_cast<std::uint32_t>(importBytes.size());
                            Append(importBytes, &symbol.hint, sizeof(symbol.hint));
                            Append(importBytes, symbol.name->c_str(), symbol.name->size() + 1);
                            thunk = importRva + nameOffset;
                        }
                        WriteAt(importBytes, intOffset + symbolIndex * sizeof(ULONGLONG), thunk);

                        auto patchIat = [&](std::uint32_t rva, ULONGLONG value)
                        {
                            for (auto const& section : sectionHeaders)
                            {
                                if (rva >= section.VirtualAddress && rva + sizeof(value) <= section.VirtualAddress + section.Misc.VirtualSize)
                                {
                                    auto const offset = section.PointerToRawData + rva - section.VirtualAddress;
                                    WriteAt(fixed.bytes, offset, value);
                                    return true;
                                }
                            }
                            return false;
                        };
                    if (!patchIat(module.firstThunk.value + static_cast<std::uint32_t>(symbolIndex * sizeof(ULONGLONG)), thunk))
                    {
                        return { std::nullopt, EngineError::ImportPlanInvalid };
                    }
                    }

                    IMAGE_IMPORT_DESCRIPTOR descriptor{};
                    descriptor.OriginalFirstThunk = importRva + intOffset;
                    descriptor.Name = importRva + moduleNameOffset;
                    descriptor.FirstThunk = module.firstThunk.value;
                    WriteAt(importBytes, moduleIndex * sizeof(descriptor), descriptor);
                    iatStart = std::min(iatStart, module.firstThunk.value);
                    iatEnd = std::max(iatEnd, module.firstThunk.value + static_cast<std::uint32_t>(thunkBytes));
                }

                std::array<char, 8> importName{};
                for (unsigned suffix = 0; suffix < 1000; ++suffix)
                {
                    importName.fill('\0');
                    if (suffix == 0) std::memcpy(importName.data(), ".idata", 6);
                    else std::snprintf(importName.data(), importName.size(), ".i%03u", suffix);
                    auto const duplicate = std::any_of(
                        layout.sections.begin(), layout.sections.end(),
                        [&](PeSection const& section) { return section.name == importName; });
                    if (!duplicate) break;
                    if (suffix == 999) return { std::nullopt, EngineError::RebuildFailed };
                }
                std::memcpy(importSection.Name, importName.data(), importName.size());
                importSection.Misc.VirtualSize = static_cast<DWORD>(importBytes.size());
                importSection.VirtualAddress = importRva;
                importSection.SizeOfRawData = Align(importSection.Misc.VirtualSize, layout.fileAlignment);
                importSection.PointerToRawData = nextRaw;
                importSection.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
                fixed.bytes.resize(static_cast<std::size_t>(nextRaw) + importSection.SizeOfRawData);
                std::copy(importBytes.begin(), importBytes.end(), fixed.bytes.begin() + nextRaw);
                sectionHeaders.push_back(importSection);
                highestVirtualEnd = Align(importSection.VirtualAddress + importSection.Misc.VirtualSize, layout.sectionAlignment);
                nextRaw += importSection.SizeOfRawData;
                fixed.quality = ArtifactQuality::Complete;
            }
            else if (!request.imports.has_value())
            {
                fixed.quality = ArtifactQuality::Partial;
                fixed.warnings.emplace_back("ImportsNotRebuilt");
            }
            else
            {
                fixed.quality = ArtifactQuality::Complete;
            }

            IMAGE_SECTION_HEADER relocationSection{};
            std::memcpy(relocationSection.Name, ".reloc", 6);
            relocationSection.Misc.VirtualSize =
                static_cast<DWORD>(request.relocations.directoryBytes.size());
            relocationSection.VirtualAddress = Align(highestVirtualEnd, layout.sectionAlignment);
            relocationSection.SizeOfRawData = Align(relocationSection.Misc.VirtualSize, layout.fileAlignment);
            relocationSection.PointerToRawData = nextRaw;
            relocationSection.Characteristics =
                IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;
            fixed.bytes.resize(static_cast<std::size_t>(nextRaw) + relocationSection.SizeOfRawData);
            std::copy(
                request.relocations.directoryBytes.begin(),
                request.relocations.directoryBytes.end(),
                fixed.bytes.begin() + nextRaw);
            sectionHeaders.push_back(relocationSection);
            highestVirtualEnd = Align(
                relocationSection.VirtualAddress + relocationSection.Misc.VirtualSize,
                layout.sectionAlignment);

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(fixed.bytes.data() + layout.ntHeaderOffset);
            nt->Signature = IMAGE_NT_SIGNATURE;
            nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
            nt->FileHeader.NumberOfSections = sectionCount;
            nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
            nt->FileHeader.Characteristics = static_cast<WORD>(
                layout.characteristics & ~IMAGE_FILE_RELOCS_STRIPPED);
            nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            nt->OptionalHeader.ImageBase = request.relocations.preferredImageBase.value;
            nt->OptionalHeader.AddressOfEntryPoint = request.oep.value;
            nt->OptionalHeader.SizeOfHeaders = headerSize;
            nt->OptionalHeader.SizeOfImage = highestVirtualEnd;
            nt->OptionalHeader.SizeOfCode = 0;
            nt->OptionalHeader.SizeOfInitializedData = 0;
            nt->OptionalHeader.SizeOfUninitializedData = 0;
            nt->OptionalHeader.BaseOfCode = 0;
            for (auto const& section : sectionHeaders)
            {
                if ((section.Characteristics & IMAGE_SCN_CNT_CODE) != 0)
                {
                    if (section.SizeOfRawData > std::numeric_limits<DWORD>::max() - nt->OptionalHeader.SizeOfCode)
                        return { std::nullopt, EngineError::RebuildFailed };
                    nt->OptionalHeader.SizeOfCode += section.SizeOfRawData;
                    if (nt->OptionalHeader.BaseOfCode == 0 || section.VirtualAddress < nt->OptionalHeader.BaseOfCode)
                        nt->OptionalHeader.BaseOfCode = section.VirtualAddress;
                }
                if ((section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0)
                {
                    if (section.SizeOfRawData > std::numeric_limits<DWORD>::max() - nt->OptionalHeader.SizeOfInitializedData)
                        return { std::nullopt, EngineError::RebuildFailed };
                    nt->OptionalHeader.SizeOfInitializedData += section.SizeOfRawData;
                }
                if ((section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0)
                {
                    if (section.SizeOfRawData > std::numeric_limits<DWORD>::max() - nt->OptionalHeader.SizeOfUninitializedData)
                        return { std::nullopt, EngineError::RebuildFailed };
                    nt->OptionalHeader.SizeOfUninitializedData += section.SizeOfRawData;
                }
            }
            nt->OptionalHeader.CheckSum = 0;
            nt->OptionalHeader.DllCharacteristics |= static_cast<WORD>(
                IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
            nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {};
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {};
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {};
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = {};
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
            // TLS callbacks and load-config metadata are not reconstructed by
            // the dump path. Keep stale packed directory pointers from being
            // consumed by the Windows loader before the OEP.
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {};
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = {};
            if (addImportSection)
            {
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = { importSection.VirtualAddress, importDirectorySize };
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = { iatStart, iatEnd - iatStart };
            }
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {
                relocationSection.VirtualAddress,
                relocationSection.Misc.VirtualSize
            };

            auto* outputSections = IMAGE_FIRST_SECTION(nt);
            std::copy(sectionHeaders.begin(), sectionHeaders.end(), outputSections);
            return { std::move(fixed), EngineError::None };
        }
        catch (...)
        {
            return { std::nullopt, EngineError::RebuildFailed };
        }
    }
}
