#include "Core/PE/Fixing/PeImageFixer.h"
#include "Core/PE/Exports/ExportDirectoryAnalyzer.h"
#include "Core/PE/Format/PeFormatTraits.h"
#include "Core/PE/Sections/SectionLayoutRebuilder.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <limits>
#include <string_view>

namespace {
std::uint32_t Align(std::uint32_t value, std::uint32_t alignment) {
  auto const mask = alignment - 1;
  if (value > std::numeric_limits<std::uint32_t>::max() - mask)
    throw std::overflow_error("alignment");
  return (value + mask) & ~mask;
}

void Append(std::vector<std::byte>& bytes, void const* data, std::size_t size) {
  auto const* first = static_cast<std::byte const*>(data);
  bytes.insert(bytes.end(), first, first + size);
}

template <typename T>
void WriteAt(std::vector<std::byte>& bytes, std::size_t offset, T const& value) {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) throw std::out_of_range("write");
  std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

bool WritePointer(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value,
                  std::size_t pointerSize) {
  if (pointerSize == sizeof(std::uint32_t)) {
    if (value > std::numeric_limits<std::uint32_t>::max()) return false;
    WriteAt(bytes, offset, static_cast<std::uint32_t>(value));
    return true;
  }
  if (pointerSize == sizeof(std::uint64_t)) {
    WriteAt(bytes, offset, value);
    return true;
  }
  return false;
}

template <typename Traits>
bool WriteHeaders(std::vector<std::byte>& bytes,
                  upx_killer::engine::pe::PeImageLayout const& layout,
                  std::span<IMAGE_SECTION_HEADER const> sections, std::uint16_t sectionCount,
                  std::uint32_t headerSize, std::uint32_t imageSize,
                  upx_killer::engine::RelativeVirtualAddress oep,
                  upx_killer::engine::LoadedAddress imageBase, bool addImportSection,
                  IMAGE_SECTION_HEADER const& importSection, std::uint32_t importDirectorySize,
                  std::uint32_t iatStart, std::uint32_t iatEnd,
                  bool addRelocationSection,
                  IMAGE_SECTION_HEADER const& relocationSection,
                  bool enableDynamicBase, bool enableHighEntropyVa,
                  std::optional<upx_killer::engine::pe::PeDataDirectory> const& tlsDirectory) {
  using NtHeaders = typename Traits::NtHeaders;
  using Pointer = typename Traits::Pointer;
  if (!Traits::AddressFits(imageBase.value) || layout.ntHeaderOffset > bytes.size() ||
      sizeof(NtHeaders) > bytes.size() - layout.ntHeaderOffset)
    return false;
  auto* nt = reinterpret_cast<NtHeaders*>(bytes.data() + layout.ntHeaderOffset);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = Traits::Machine;
  nt->FileHeader.NumberOfSections = sectionCount;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(typename Traits::OptionalHeader);
  nt->FileHeader.Characteristics = addRelocationSection
                                       ? static_cast<WORD>(layout.characteristics &
                                                           ~IMAGE_FILE_RELOCS_STRIPPED)
                                       : static_cast<WORD>(layout.characteristics |
                                                           IMAGE_FILE_RELOCS_STRIPPED);
  nt->OptionalHeader.Magic = Traits::OptionalHeaderMagic;
  nt->OptionalHeader.ImageBase = static_cast<Pointer>(imageBase.value);
  nt->OptionalHeader.AddressOfEntryPoint = oep.value;
  nt->OptionalHeader.SizeOfHeaders = headerSize;
  nt->OptionalHeader.SizeOfImage = imageSize;
  nt->OptionalHeader.SizeOfCode = 0;
  nt->OptionalHeader.SizeOfInitializedData = 0;
  nt->OptionalHeader.SizeOfUninitializedData = 0;
  nt->OptionalHeader.BaseOfCode = 0;
  if constexpr (Traits::Format == upx_killer::engine::pe::PeFormat::Pe32)
    nt->OptionalHeader.BaseOfData = 0;

  for (auto const& section : sections) {
    if ((section.Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
      if (section.SizeOfRawData >
          std::numeric_limits<DWORD>::max() - nt->OptionalHeader.SizeOfCode)
        return false;
      nt->OptionalHeader.SizeOfCode += section.SizeOfRawData;
      if (nt->OptionalHeader.BaseOfCode == 0 ||
          section.VirtualAddress < nt->OptionalHeader.BaseOfCode)
        nt->OptionalHeader.BaseOfCode = section.VirtualAddress;
    }
    if ((section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0) {
      if (section.SizeOfRawData >
          std::numeric_limits<DWORD>::max() - nt->OptionalHeader.SizeOfInitializedData)
        return false;
      nt->OptionalHeader.SizeOfInitializedData += section.SizeOfRawData;
      if constexpr (Traits::Format == upx_killer::engine::pe::PeFormat::Pe32)
        if (nt->OptionalHeader.BaseOfData == 0 ||
            section.VirtualAddress < nt->OptionalHeader.BaseOfData)
          nt->OptionalHeader.BaseOfData = section.VirtualAddress;
    }
    if ((section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) {
      if (section.SizeOfRawData >
          std::numeric_limits<DWORD>::max() - nt->OptionalHeader.SizeOfUninitializedData)
        return false;
      nt->OptionalHeader.SizeOfUninitializedData += section.SizeOfRawData;
    }
  }
  nt->OptionalHeader.CheckSum = 0;
  if (addRelocationSection && enableDynamicBase) {
    nt->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    if constexpr (Traits::SupportsHighEntropyVa) {
      if (enableHighEntropyVa)
        nt->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
      else
        nt->OptionalHeader.DllCharacteristics &=
            static_cast<WORD>(~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
    } else
      nt->OptionalHeader.DllCharacteristics &=
          static_cast<WORD>(~IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
  } else {
    nt->OptionalHeader.DllCharacteristics &= static_cast<WORD>(
        ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
          IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
  }
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = {};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {};
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = {};
  if (tlsDirectory) {
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {
        tlsDirectory->address.value, tlsDirectory->size};
  }
  if (addImportSection) {
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {
        importSection.VirtualAddress, importDirectorySize};
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {iatStart, iatEnd - iatStart};
  }
  if (addRelocationSection) {
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {
        relocationSection.VirtualAddress, relocationSection.Misc.VirtualSize};
  }
  auto* outputSections = IMAGE_FIRST_SECTION(nt);
  std::copy(sections.begin(), sections.end(), outputSections);
  return true;
}
}

namespace upx_killer::engine::pe {
FixResult PeImageFixer::Rebuild(PeImageLayout const& layout,
                                images::CapturedImage const& dump,
                                FixRequest const& request) noexcept {
  try {
    if (request.oep.value >= layout.sizeOfImage || dump.bytes.size() < layout.sizeOfImage ||
        layout.sections.empty())
      return {std::nullopt, PeFixError::EntryPointOutOfRange};
    auto const* relocationPlan =
        std::get_if<relocations::RelocationRebuildPlan>(&request.imagePlacement);
    auto const* fixedPlacement =
        std::get_if<fixing::FixedImagePlacement>(&request.imagePlacement);
    if ((!relocationPlan && !fixedPlacement) ||
        (relocationPlan && (relocationPlan->preferredImageBase.value == 0 ||
                            relocationPlan->slots.empty() ||
                            relocationPlan->directoryBytes.empty())) ||
        (fixedPlacement && (fixedPlacement->preferredImageBase.value == 0 ||
                            dump.loadedAddress.value != fixedPlacement->preferredImageBase.value)))
      return {std::nullopt, PeFixError::ImagePlacementInvalid};
    auto const outputImageBase = relocationPlan ? relocationPlan->preferredImageBase
                                                : fixedPlacement->preferredImageBase;
    auto const pointerSize = layout.format == PeFormat::Pe32
                                 ? format::Pe32Traits::PointerSize
                                 : format::Pe64Traits::PointerSize;
    auto const ordinalFlag = layout.format == PeFormat::Pe32
                                 ? static_cast<std::uint64_t>(format::Pe32Traits::OrdinalFlag)
                                 : format::Pe64Traits::OrdinalFlag;

    auto normalizedImage = dump.bytes;
    if (relocationPlan) {
      for (auto const& slot : relocationPlan->slots) {
        if (slot.location.value >= layout.sizeOfImage ||
            pointerSize > layout.sizeOfImage - slot.location.value ||
            slot.imageTarget.value >= layout.sizeOfImage ||
            outputImageBase.value >
                std::numeric_limits<std::uint64_t>::max() - slot.imageTarget.value)
          return {std::nullopt, PeFixError::RelocationSlotInvalid};
        auto const value = outputImageBase.value + slot.imageTarget.value;
        if (!WritePointer(normalizedImage, slot.location.value, value, pointerSize))
          return {std::nullopt, PeFixError::RelocationSlotInvalid};
      }
    }
    std::vector<RelativeVirtualAddress> exportCodeTargets;
    if (layout.imageKind == PeImageKind::DynamicLibrary) {
      auto exports = exports::ExportDirectoryAnalyzer::AnalyzeMapped(normalizedImage, layout);
      if (!exports.directory) return {std::nullopt, PeFixError::ExportDirectoryInvalid};
      exportCodeTargets = std::move(exports.directory->codeTargets);
    }
    auto const sectionLayout = sections::SectionLayoutRebuilder::Build(
        layout, {normalizedImage, outputImageBase, request.oep,
                 request.imports ? &*request.imports : nullptr, exportCodeTargets,
                 dump.regions});
    if (!sectionLayout.plan) return {std::nullopt, PeFixError::SectionLayoutInvalid};

    auto const addImportSection = request.imports.has_value() && !request.imports->modules.empty();
    auto const addRelocationSection = relocationPlan != nullptr;
    if (sectionLayout.plan->sections.size() + (addImportSection ? 1u : 0u) +
            (addRelocationSection ? 1u : 0u) >
        96)
      return {std::nullopt, PeFixError::SectionLayoutInvalid};
    auto const sectionCount = static_cast<std::uint16_t>(sectionLayout.plan->sections.size() +
                                                         (addImportSection ? 1 : 0) +
                                                         (addRelocationSection ? 1 : 0));
    auto const sectionTableOffset =
        static_cast<std::uint32_t>(layout.ntHeaderOffset + sizeof(DWORD) +
                                   sizeof(IMAGE_FILE_HEADER) +
                                   (layout.format == PeFormat::Pe32
                                        ? sizeof(IMAGE_OPTIONAL_HEADER32)
                                        : sizeof(IMAGE_OPTIONAL_HEADER64)));
    auto const headerSize =
        Align(sectionTableOffset +
                  static_cast<std::uint32_t>(sectionCount * sizeof(IMAGE_SECTION_HEADER)),
              layout.fileAlignment);

    FixedPeImage fixed{};
    fixed.bytes.resize(headerSize);
    std::copy_n(normalizedImage.begin(),
                std::min<std::size_t>(layout.sizeOfHeaders, fixed.bytes.size()),
                fixed.bytes.begin());

    std::vector<IMAGE_SECTION_HEADER> sectionHeaders;
    sectionHeaders.reserve(sectionCount);
    std::uint32_t nextRaw = headerSize;
    std::uint32_t highestVirtualEnd{};
    for (auto const& source : sectionLayout.plan->sections) {
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
      std::copy_n(normalizedImage.begin() + source.virtualAddress.value, virtualBytes,
                  fixed.bytes.begin() + nextRaw);
      nextRaw += section.SizeOfRawData;
      highestVirtualEnd = std::max(
          highestVirtualEnd,
          Align(section.VirtualAddress + section.Misc.VirtualSize, layout.sectionAlignment));
      sectionHeaders.push_back(section);
    }

    IMAGE_SECTION_HEADER importSection{};
    std::vector<std::byte> importBytes;
    std::uint32_t importDirectorySize{};
    std::uint32_t iatStart = std::numeric_limits<std::uint32_t>::max();
    std::uint32_t iatEnd{};
    std::vector<std::pair<std::uint32_t, std::uint32_t>> iatRanges;
    if (addImportSection) {
      auto const importRva = Align(highestVirtualEnd, layout.sectionAlignment);
      auto const descriptorBytes = static_cast<std::uint32_t>(
          (request.imports->modules.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
      importBytes.resize(descriptorBytes);
      importDirectorySize = descriptorBytes;

      for (std::size_t moduleIndex = 0; moduleIndex < request.imports->modules.size();
           ++moduleIndex) {
        auto const& module = request.imports->modules[moduleIndex];
        if (module.moduleName.empty() || module.symbols.empty())
          return {std::nullopt, PeFixError::ImportPlanInvalid};
        if (module.symbols.size() >
            (std::numeric_limits<std::uint32_t>::max() / pointerSize) - 1)
          return {std::nullopt, PeFixError::ImportPlanInvalid};
        auto const iatBytes =
            static_cast<std::uint64_t>(module.symbols.size()) * pointerSize;
        auto const intBytes =
            static_cast<std::uint64_t>(module.symbols.size() + 1) * pointerSize;
        if (module.firstThunk.value >= layout.sizeOfImage ||
            iatBytes > layout.sizeOfImage - module.firstThunk.value)
          return {std::nullopt, PeFixError::ImportPlanInvalid};
        auto const moduleIatEnd = module.firstThunk.value + static_cast<std::uint32_t>(iatBytes);
        for (auto const& [begin, end] : iatRanges) {
          if (module.firstThunk.value < end && begin < moduleIatEnd) {
            return {std::nullopt, PeFixError::ImportPlanInvalid};
          }
        }
        iatRanges.emplace_back(module.firstThunk.value, moduleIatEnd);

        while ((importBytes.size() % pointerSize) != 0) importBytes.push_back(std::byte{});
        auto const intOffset = static_cast<std::uint32_t>(importBytes.size());
        importBytes.resize(importBytes.size() + static_cast<std::size_t>(intBytes));
        auto const moduleNameOffset = static_cast<std::uint32_t>(importBytes.size());
        Append(importBytes, module.moduleName.c_str(), module.moduleName.size() + 1);

        for (std::size_t symbolIndex = 0; symbolIndex < module.symbols.size(); ++symbolIndex) {
          auto const& symbol = module.symbols[symbolIndex];
          std::uint64_t thunk{};
          if (symbol.ordinal.has_value() == symbol.name.has_value()) {
            return {std::nullopt, PeFixError::ImportPlanInvalid};
          }
          if (symbol.ordinal) {
            thunk = ordinalFlag | *symbol.ordinal;
          } else {
            while ((importBytes.size() % alignof(WORD)) != 0) importBytes.push_back(std::byte{});
            auto const nameOffset = static_cast<std::uint32_t>(importBytes.size());
            Append(importBytes, &symbol.hint, sizeof(symbol.hint));
            Append(importBytes, symbol.name->c_str(), symbol.name->size() + 1);
            thunk = importRva + nameOffset;
          }
          if (!WritePointer(importBytes, intOffset + symbolIndex * pointerSize, thunk,
                            pointerSize))
            return {std::nullopt, PeFixError::ImportPlanInvalid};

          auto patchIat = [&](std::uint32_t rva, std::uint64_t value) {
            for (auto const& section : sectionHeaders) {
              if (rva >= section.VirtualAddress &&
                  rva + pointerSize <= section.VirtualAddress + section.Misc.VirtualSize) {
                auto const offset = section.PointerToRawData + rva - section.VirtualAddress;
                return WritePointer(fixed.bytes, offset, value, pointerSize);
              }
            }
            return false;
          };
          if (!patchIat(module.firstThunk.value +
                            static_cast<std::uint32_t>(symbolIndex * pointerSize),
                        thunk)) {
            return {std::nullopt, PeFixError::ImportPlanInvalid};
          }
        }

        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        descriptor.OriginalFirstThunk = importRva + intOffset;
        descriptor.Name = importRva + moduleNameOffset;
        descriptor.FirstThunk = module.firstThunk.value;
        WriteAt(importBytes, moduleIndex * sizeof(descriptor), descriptor);
        iatStart = std::min(iatStart, module.firstThunk.value);
        iatEnd = std::max(iatEnd, moduleIatEnd);
      }

      std::array<char, 8> importName{};
      for (unsigned suffix = 0; suffix < 1000; ++suffix) {
        importName.fill('\0');
        if (suffix == 0)
          std::memcpy(importName.data(), ".idata", 6);
        else
          std::snprintf(importName.data(), importName.size(), ".i%03u", suffix);
        auto const duplicate =
            std::any_of(layout.sections.begin(), layout.sections.end(),
                        [&](PeSection const& section) { return section.name == importName; });
        if (!duplicate) break;
        if (suffix == 999) return {std::nullopt, PeFixError::SectionLayoutInvalid};
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
      highestVirtualEnd = Align(importSection.VirtualAddress + importSection.Misc.VirtualSize,
                                layout.sectionAlignment);
      nextRaw += importSection.SizeOfRawData;
      fixed.quality = ArtifactQuality::Complete;
    } else if (!request.imports.has_value()) {
      fixed.quality = ArtifactQuality::Partial;
      fixed.warnings.emplace_back("ImportsNotRebuilt");
    } else {
      fixed.quality = ArtifactQuality::Complete;
    }

    IMAGE_SECTION_HEADER relocationSection{};
    if (addRelocationSection) {
      std::memcpy(relocationSection.Name, ".reloc", 6);
      relocationSection.Misc.VirtualSize =
          static_cast<DWORD>(relocationPlan->directoryBytes.size());
      relocationSection.VirtualAddress = Align(highestVirtualEnd, layout.sectionAlignment);
      relocationSection.SizeOfRawData =
          Align(relocationSection.Misc.VirtualSize, layout.fileAlignment);
      relocationSection.PointerToRawData = nextRaw;
      relocationSection.Characteristics =
          IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;
      fixed.bytes.resize(static_cast<std::size_t>(nextRaw) + relocationSection.SizeOfRawData);
      std::copy(relocationPlan->directoryBytes.begin(), relocationPlan->directoryBytes.end(),
                fixed.bytes.begin() + nextRaw);
      sectionHeaders.push_back(relocationSection);
      highestVirtualEnd = Align(
          relocationSection.VirtualAddress + relocationSection.Misc.VirtualSize,
          layout.sectionAlignment);
    }

    auto const headersWritten =
        layout.format == PeFormat::Pe32
            ? WriteHeaders<format::Pe32Traits>(
                  fixed.bytes, layout, sectionHeaders, sectionCount, headerSize, highestVirtualEnd,
                  request.oep, outputImageBase, addImportSection,
                  importSection, importDirectorySize, iatStart, iatEnd, addRelocationSection,
                  relocationSection, relocationPlan && relocationPlan->enableDynamicBase,
                  relocationPlan && relocationPlan->enableHighEntropyVa,
                  sectionLayout.plan->tlsDirectory)
            : WriteHeaders<format::Pe64Traits>(
                  fixed.bytes, layout, sectionHeaders, sectionCount, headerSize, highestVirtualEnd,
                  request.oep, outputImageBase, addImportSection,
                  importSection, importDirectorySize, iatStart, iatEnd, addRelocationSection,
                  relocationSection, relocationPlan && relocationPlan->enableDynamicBase,
                  relocationPlan && relocationPlan->enableHighEntropyVa,
                  sectionLayout.plan->tlsDirectory);
    if (!headersWritten) return {std::nullopt, PeFixError::HeaderWriteFailed};
    return {std::move(fixed), PeFixError::None};
  } catch (...) {
    return {std::nullopt, PeFixError::UnexpectedFailure};
  }
}
}
