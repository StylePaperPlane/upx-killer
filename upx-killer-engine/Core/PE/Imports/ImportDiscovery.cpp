#include "Core/PE/Imports/ImportDiscovery.h"

#include "Core/PE/Format/PeFormatTraits.h"
#include "Core/PE/Imports/Internal/ImportProviderResolver.h"
#include "Core/PE/Imports/Internal/SourceImportLayout.h"
#include "Core/PE/Imports/Internal/UpxImportHint.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <set>
#include <string>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::imports;

constexpr std::size_t MaximumSlots = 16'384;

bool IsWritable(PeSection const& section) noexcept {
  return (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
}

bool Contains(PeSection const& section, RelativeVirtualAddress address) noexcept {
  auto const extent = std::max(section.virtualSize, section.rawSize);
  return address.value >= section.virtualAddress.value &&
         address.value - section.virtualAddress.value < extent;
}

bool ReadPointer(std::span<std::byte const> bytes, std::uint32_t rva, std::size_t pointerSize,
                 std::uint64_t& value) noexcept {
  if ((pointerSize != sizeof(std::uint32_t) && pointerSize != sizeof(std::uint64_t)) ||
      rva > bytes.size() || pointerSize > bytes.size() - rva)
    return false;
  value = 0;
  std::memcpy(&value, bytes.data() + rva, pointerSize);
  return true;
}

bool IsZeroPointer(std::span<std::byte const> bytes, std::uint32_t rva,
                   std::size_t pointerSize) noexcept {
  std::uint64_t value{};
  return ReadPointer(bytes, rva, pointerSize, value) && value == 0;
}

bool AddCandidate(std::vector<ImportModulePlan>& modules, std::uint32_t firstThunk,
                  internal::ResolvedImportProvider const& match, std::size_t pointerSize) {
  if (match.moduleName.empty() || (!match.symbol.name && !match.symbol.ordinal)) return false;

  if (!modules.empty() && modules.back().moduleName == match.moduleName &&
      modules.back().firstThunk.value + modules.back().symbols.size() * pointerSize ==
          firstThunk) {
    modules.back().symbols.push_back(match.symbol);
    return true;
  }
  ImportModulePlan module{};
  module.moduleName = match.moduleName;
  module.firstThunk = {firstThunk};
  module.symbols.push_back(match.symbol);
  modules.push_back(std::move(module));
  return true;
}

}

namespace upx_killer::engine::pe::imports {
ImportDiscoveryResult ImportDiscovery::Discover(std::span<std::byte const> dumpedBytes,
                                                std::span<std::byte const> sourceBytes,
                                                PeImageLayout const& sourceLayout,
                                                RuntimeModuleSnapshot const& runtime,
                                                RelativeVirtualAddress recoveredEntryPoint) noexcept {
  try {
    if (dumpedBytes.size() < sourceLayout.sizeOfImage || sourceLayout.sizeOfImage == 0)
      return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
    auto const pointerSize = sourceLayout.format == PeFormat::Pe32
                                 ? format::Pe32Traits::PointerSize
                                 : format::Pe64Traits::PointerSize;
    auto const& importDirectory = sourceLayout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto const& iatDirectory = sourceLayout.directories[IMAGE_DIRECTORY_ENTRY_IAT];
    // A source import table is loader residue only when execution has moved
    // from the packed entry point to a recovered one. In an ordinary PE it is
    // the program's own table even if the optional IAT Directory is absent.
    auto const shellImports =
        sourceLayout.entryPoint.value != recoveredEntryPoint.value &&
        iatDirectory.address.value == 0 && iatDirectory.size == 0;
    auto const sourceImports =
        importDirectory.address.value != 0 || importDirectory.size != 0
            ? internal::SourceImportLayout::Analyze(sourceBytes, sourceLayout)
            : internal::SourceImportLayoutResult{true, {}, {}};
    auto const isSourceImport = [&](std::uint32_t rva) {
      return shellImports && std::any_of(sourceImports.occupiedRanges.begin(),
                         sourceImports.occupiedRanges.end(),
                         [rva, pointerSize](auto const& range) {
                           return range.Overlaps(rva, pointerSize);
                         });
    };
    auto const unverifiedSourceDirectory = [&](std::uint32_t rva) {
      return shellImports && !sourceImports.complete && importDirectory.address.value != 0 &&
             importDirectory.size <= sourceLayout.sizeOfImage -
                                         std::min(importDirectory.address.value,
                                                  sourceLayout.sizeOfImage) &&
             rva >= importDirectory.address.value &&
             rva - importDirectory.address.value < importDirectory.size;
    };

    internal::ImportProviderResolver providers{runtime};

    struct ObservedSlot {
      std::uint32_t rva{};
      std::uint64_t address{};
    };
    std::vector<ObservedSlot> slots;
    std::set<std::uint32_t> acceptedSlots;
    std::size_t matchedSlots{};
    bool unverifiedCandidate{};
    for (auto const& section : sourceLayout.sections) {
      auto const importSection =
          Contains(section, importDirectory.address) || Contains(section, iatDirectory.address);
      // Linkers commonly place the bound IAT in read-only .rdata;
      // after loader resolution it is still authoritative data.
      // Packed images may keep the unpacked IAT in an executable
      // writable section.  Writability is the authority here;
      // strict run and export-address validation prevents code
      // bytes from becoming import candidates.
      if ((!IsWritable(section) && !importSection &&
           (section.characteristics & IMAGE_SCN_MEM_READ) == 0) ||
          section.virtualAddress.value >= sourceLayout.sizeOfImage)
        continue;
      auto const extent = std::min(std::max(section.virtualSize, section.rawSize),
                                   sourceLayout.sizeOfImage - section.virtualAddress.value);
      if (extent < pointerSize) continue;
      auto const sectionStart = static_cast<std::uint64_t>(section.virtualAddress.value);
      auto const sectionEnd = sectionStart + extent;
      auto scanStart = sectionStart;
      auto scanEnd = sectionEnd;
      bool declaredIatRange{};
      if (iatDirectory.address.value != 0 || iatDirectory.size != 0) {
        if (iatDirectory.address.value == 0 || iatDirectory.size < pointerSize) {
          return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
        }
        auto const iatStart = static_cast<std::uint64_t>(iatDirectory.address.value);
        auto const iatEnd = iatStart + iatDirectory.size;
        if (iatEnd > sourceLayout.sizeOfImage) {
          return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
        }
        if (iatStart >= sectionEnd || iatEnd <= sectionStart) continue;
        scanStart = std::max(scanStart, iatStart);
        scanEnd = std::min(scanEnd, iatEnd);
        declaredIatRange = true;
      }
      if (scanEnd - scanStart < pointerSize) continue;
      // PE64 thunk arrays may start at either four-byte alignment. Scan the
      // two independent native-width lanes so a run in one cannot hide an
      // overlapping run in the other.
      constexpr auto Alignment = static_cast<std::uint32_t>(sizeof(std::uint32_t));
      auto const scanStep = static_cast<std::uint32_t>(pointerSize);
      auto const alignedStart = static_cast<std::uint32_t>(
          scanStart + ((Alignment - scanStart % Alignment) % Alignment));
      auto const end = static_cast<std::uint32_t>(scanEnd - pointerSize);
      for (std::uint32_t lane = 0; lane < pointerSize / Alignment; ++lane) {
        auto rva = alignedStart + lane * Alignment;
        while (rva <= end) {
          if (isSourceImport(rva)) {
            rva += scanStep;
            continue;
          }
          std::uint64_t target{};
          if (!ReadPointer(dumpedBytes, rva, pointerSize, target) || target == 0) {
            rva += scanStep;
            continue;
          }
          if (!providers.Contains(target)) {
            rva += scanStep;
            continue;
          }
          if (unverifiedSourceDirectory(rva)) {
            unverifiedCandidate = true;
            rva += scanStep;
            continue;
          }
          auto runEnd = rva;
          std::size_t runLength{};
          while (runEnd <= end) {
            if (isSourceImport(runEnd) || unverifiedSourceDirectory(runEnd)) break;
            std::uint64_t runTarget{};
            if (!ReadPointer(dumpedBytes, runEnd, pointerSize, runTarget) || runTarget == 0) break;
            if (!providers.Contains(runTarget)) break;
            ++runLength;
            runEnd += static_cast<std::uint32_t>(pointerSize);
          }

          // A declared IAT directory is authoritative. Outside it, accept either
          // a dense run or a single run bounded by native-width zero sentinels.
          // Linkers routinely emit one-symbol import descriptors; dropping those
          // leaves live runtime addresses in the repaired IAT and makes the image
          // depend on the module layout of the capture process.
          auto const zeroBounded =
              rva >= section.virtualAddress.value + pointerSize && runEnd <= end &&
              IsZeroPointer(dumpedBytes, rva - static_cast<std::uint32_t>(pointerSize),
                            pointerSize) &&
              IsZeroPointer(dumpedBytes, runEnd, pointerSize);
          if (runLength == 0 || (!declaredIatRange && runLength < 2 && !zeroBounded)) {
            rva += scanStep;
            continue;
          }
          for (auto slot = rva; slot < runEnd; slot += static_cast<std::uint32_t>(pointerSize)) {
            auto const next = acceptedSlots.lower_bound(slot);
            if (next != acceptedSlots.end() && *next == slot) continue;
            if ((next != acceptedSlots.end() && *next - slot < pointerSize) ||
                (next != acceptedSlots.begin() && slot - *std::prev(next) < pointerSize))
              return {std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {}};
            acceptedSlots.insert(slot);
            std::uint64_t slotTarget{};
            if (!ReadPointer(dumpedBytes, slot, pointerSize, slotTarget))
              return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
            slots.push_back({slot, slotTarget});
            ++matchedSlots;
            if (matchedSlots > MaximumSlots)
              return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
          }

          rva = runEnd;
        }
      }
    }

    if (unverifiedCandidate)
      return {std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {}};
    std::vector<internal::ImportProviderHint> hints =
        !shellImports && sourceImports.complete
            ? sourceImports.providers
            : std::vector<internal::ImportProviderHint>{};
    auto hintAt = [&](std::uint32_t rva) -> std::optional<internal::ImportProviderHint> {
      auto const found = std::find_if(hints.begin(), hints.end(),
                                     [rva](auto const& hint) { return hint.slotRva == rva; });
      return found == hints.end() ? std::nullopt : std::optional{*found};
    };
    auto requiresHints = shellImports || slots.empty();
    if (!requiresHints)
      for (auto const& slot : slots)
        if (!providers.Resolve(slot.address, hintAt(slot.rva))) {
          requiresHints = true;
          break;
        }
    std::vector<std::string> warnings;
    auto rejectHint = [&](std::uint32_t rva) {
      warnings.push_back("upx_hint_rejected:rva=" + std::to_string(rva));
    };
    if (requiresHints && shellImports) {
      hints = internal::UpxImportHint::Analyze(
          dumpedBytes, sourceBytes, sourceLayout, recoveredEntryPoint);
      for (auto const& hint : hints) {
        if (acceptedSlots.contains(hint.slotRva)) continue;
        std::uint64_t target{};
        if (isSourceImport(hint.slotRva) ||
            !ReadPointer(dumpedBytes, hint.slotRva, pointerSize, target) || target == 0 ||
            !providers.Resolve(target, hint)) {
          rejectHint(hint.slotRva);
          continue;
        }
        auto const next = acceptedSlots.lower_bound(hint.slotRva);
        if ((next != acceptedSlots.end() && *next - hint.slotRva < pointerSize) ||
            (next != acceptedSlots.begin() && hint.slotRva - *std::prev(next) < pointerSize)) {
          rejectHint(hint.slotRva);
          continue;
        }
        if (acceptedSlots.size() >= MaximumSlots)
          return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
        acceptedSlots.insert(hint.slotRva);
        slots.push_back({hint.slotRva, target});
      }
    }
    if (slots.empty()) {
      if (importDirectory.address.value == 0 && importDirectory.size == 0)
        return {ImportRebuildPlan{}, ImportDiscoveryError::None, {}};
      return {std::nullopt, ImportDiscoveryError::ImportsNotFound, {}};
    }
    std::sort(slots.begin(), slots.end(),
              [](auto const& left, auto const& right) { return left.rva < right.rva; });
    std::vector<ImportModulePlan> plans;
    for (auto const& slot : slots) {
      auto const hint = std::find_if(hints.begin(), hints.end(), [&](auto const& item) {
        return item.slotRva == slot.rva;
      });
      auto selected = providers.Resolve(
          slot.address, hint == hints.end() ? std::nullopt
                                            : std::optional{*hint});
      if (!selected && shellImports && hint != hints.end()) {
        rejectHint(slot.rva);
        selected = providers.Resolve(slot.address, std::nullopt);
      }
      if (!selected || !AddCandidate(plans, slot.rva, *selected, pointerSize))
        return {std::nullopt, ImportDiscoveryError::ImportsAmbiguous,
                std::move(warnings)};
    }
    ImportRebuildPlan plan{};
    plan.modules = std::move(plans);
    return {std::move(plan), ImportDiscoveryError::None, std::move(warnings)};
  } catch (...) {
    return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
  }
}
}
