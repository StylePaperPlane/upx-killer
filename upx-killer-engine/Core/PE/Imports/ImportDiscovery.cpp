#include "Core/PE/Imports/ImportDiscovery.h"

#include "Core/PE/Format/PeFormatTraits.h"
#include "Core/PE/Imports/Internal/SourceImportLayout.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <string_view>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::imports;

constexpr std::size_t MaximumSlots = 16'384;

std::string NormalizeModule(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (value.find('.') == std::string::npos) value += ".dll";
  return value;
}

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

struct Match {
  std::string module;
  ImportSymbol symbol;
};

struct AddressEntry {
  std::vector<Match> matches;
};

bool AddMatch(std::map<std::uint64_t, AddressEntry>& index, RuntimeExport const& exported) {
  // PE imports may target exported data as well as executable functions.
  // The IAT run boundary and single-module checks below provide the
  // structural evidence; executable page membership is not an import invariant.
  if (exported.address.value == 0 || exported.moduleName.empty())
    return true;
  if (!exported.name && !exported.ordinal) return true;
  ImportSymbol symbol{};
  symbol.name = exported.name;
  if (!symbol.name) symbol.ordinal = exported.ordinal;
  auto& entry = index[exported.address.value];
  auto const module = NormalizeModule(exported.moduleName);
  // A DLL may expose multiple aliases at one address. They are
  // equivalent for rebuilding the IAT; ambiguity only remains when
  // different provider modules claim the same runtime address.
  auto const duplicateModule =
      std::find_if(entry.matches.begin(), entry.matches.end(),
                   [&](Match const& existing) { return existing.module == module; });
  if (duplicateModule == entry.matches.end()) entry.matches.push_back({module, std::move(symbol)});
  return true;
}

bool AddCandidate(std::vector<ImportModulePlan>& modules, std::uint32_t firstThunk,
                  Match const& match, std::size_t pointerSize) {
  if (match.module.empty() || (!match.symbol.name && !match.symbol.ordinal)) return false;

  if (!modules.empty() && modules.back().moduleName == match.module &&
      modules.back().firstThunk.value + modules.back().symbols.size() * pointerSize ==
          firstThunk) {
    modules.back().symbols.push_back(match.symbol);
    return true;
  }
  ImportModulePlan module{};
  module.moduleName = match.module;
  module.firstThunk = {firstThunk};
  module.symbols.push_back(match.symbol);
  modules.push_back(std::move(module));
  return true;
}

int ModulePriority(std::string const& module) noexcept {
  if (module.rfind("api-", 0) == 0) return 100;
  if (module == "kernel32.dll" || module == "user32.dll" || module == "advapi32.dll") return 90;
  if (module == "ucrtbase.dll" || module == "vcruntime140.dll" || module == "msvcp140.dll")
    return 80;
  if (module == "kernelbase.dll" || module == "ntdll.dll") return 10;
  return 50;
}

std::optional<Match> SelectMatch(AddressEntry const& entry,
                                 std::string_view preferredModule) {
  if (!preferredModule.empty()) {
    auto const preferred = std::find_if(
        entry.matches.begin(), entry.matches.end(), [&](Match const& match) {
          return match.module == preferredModule;
        });
    if (preferred != entry.matches.end()) return *preferred;
  }
  if (entry.matches.empty()) return std::nullopt;
  if (entry.matches.size() == 1) return entry.matches.front();

  auto selected = entry.matches.front();
  auto selectedPriority = ModulePriority(selected.module);
  bool tie{};
  for (std::size_t index = 1; index < entry.matches.size(); ++index) {
    auto const priority = ModulePriority(entry.matches[index].module);
    if (priority > selectedPriority) {
      selected = entry.matches[index];
      selectedPriority = priority;
      tie = false;
    } else if (priority == selectedPriority &&
               entry.matches[index].module != selected.module) {
      tie = true;
    }
  }
  if (tie) return std::nullopt;
  return selected;
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
    auto const sourceImports =
        sourceLayout.entryPoint.value != recoveredEntryPoint.value &&
                iatDirectory.address.value == 0 && iatDirectory.size == 0
            ? internal::SourceImportLayout::Analyze(sourceBytes, sourceLayout)
            : internal::SourceImportLayoutResult{true, {}};
    auto const isSourceImport = [&](std::uint32_t rva) {
      return std::any_of(sourceImports.occupiedRanges.begin(),
                         sourceImports.occupiedRanges.end(),
                         [rva, pointerSize](auto const& range) {
                           return range.Overlaps(rva, pointerSize);
                         });
    };
    auto const unverifiedSourceDirectory = [&](std::uint32_t rva) {
      return !sourceImports.complete && importDirectory.address.value != 0 &&
             importDirectory.size <= sourceLayout.sizeOfImage -
                                         std::min(importDirectory.address.value,
                                                  sourceLayout.sizeOfImage) &&
             rva >= importDirectory.address.value &&
             rva - importDirectory.address.value < importDirectory.size;
    };

    std::map<std::uint64_t, AddressEntry> addressIndex;
    for (auto const& module : runtime.modules) {
      if (module.moduleName.empty() || module.imageSize == 0) continue;
      for (auto const& exported : module.exports) AddMatch(addressIndex, exported);
    }

    std::vector<ImportModulePlan> plans;
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
          auto found = addressIndex.find(target);
          if (found == addressIndex.end()) {
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
            auto const runMatch = addressIndex.find(runTarget);
            if (runMatch == addressIndex.end()) break;
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
          std::string previousModule;
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
            auto const slotMatch = addressIndex.find(slotTarget);
            auto selected = slotMatch != addressIndex.end()
                                ? SelectMatch(slotMatch->second, previousModule)
                                : std::nullopt;
            if (!selected || !AddCandidate(plans, slot, *selected, pointerSize)) {
              return {std::nullopt, ImportDiscoveryError::ImportsAmbiguous, {}};
            }
            previousModule = selected->module;
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
    if (plans.empty()) {
      if (importDirectory.address.value == 0 && importDirectory.size == 0)
        return {ImportRebuildPlan{}, ImportDiscoveryError::None, {}};
      return {std::nullopt, ImportDiscoveryError::ImportsNotFound, {}};
    }
    ImportRebuildPlan plan{};
    std::sort(plans.begin(), plans.end(), [](auto const& left, auto const& right) {
      return left.firstThunk.value < right.firstThunk.value;
    });
    plan.modules = std::move(plans);
    return {std::move(plan), ImportDiscoveryError::None, {}};
  } catch (...) {
    return {std::nullopt, ImportDiscoveryError::InvalidInput, {}};
  }
}
}
