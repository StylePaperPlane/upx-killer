#include "Infrastructure/Windows/Debugging/RemoteModuleCatalog.h"
#include "Infrastructure/Windows/Debugging/Imports/AppCompatImportAliasResolver.h"

#include "Core/PE/Imports/PeExportParser.h"

#include <TlHelp32.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe::imports;

constexpr std::size_t MaxModules = 256;
constexpr std::uint32_t MaxImageSize = 256u * 1024u * 1024u;
constexpr std::size_t MaxForwardDepth = 8;

std::string Normalize(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (value.find('.') == std::string::npos) value += ".dll";
  return value;
}

bool EqualName(std::string const& left, std::string const& right) noexcept {
  if (left.size() != right.size()) return false;
  return std::equal(left.begin(), left.end(), right.begin(), [](char a, char b) {
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
  });
}

std::string Narrow(std::wstring value) {
  if (value.size() > 260) value.resize(260);
  std::string result;
  result.reserve(value.size());
  for (auto c : value) result.push_back(c < 128 ? static_cast<char>(c) : '?');
  return result;
}

bool ReadRemote(HANDLE process, std::uint64_t address, std::span<std::byte> destination) noexcept {
  SIZE_T read{};
  return ReadProcessMemory(process, reinterpret_cast<void const*>(address), destination.data(),
                           destination.size(), &read) &&
         read == destination.size();
}

bool ReadMappedImage(HANDLE process, std::uint64_t base, std::uint32_t imageSize,
                     pe::PeFormat expectedFormat, std::vector<std::byte>& image) noexcept {
  if (imageSize == 0 || imageSize > MaxImageSize) return false;
  image.assign(imageSize, std::byte{});
  auto const initial = std::min<std::uint32_t>(imageSize, 0x1000u);
  if (!ReadRemote(process, base, std::span<std::byte>{image.data(), initial})) return false;

  IMAGE_DOS_HEADER dos{};
  if (image.size() < sizeof(dos)) return false;
  std::memcpy(&dos, image.data(), sizeof(dos));
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos)) return false;
  auto const ntOffset = static_cast<std::uint64_t>(dos.e_lfanew);
  DWORD signature{};
  IMAGE_FILE_HEADER file{};
  auto const fileOffset = ntOffset + sizeof(signature);
  auto const optionalOffset = fileOffset + sizeof(file);
  if (optionalOffset + sizeof(WORD) > image.size() ||
      !ReadRemote(process, base + ntOffset,
                  std::span<std::byte>{image.data() + ntOffset, sizeof(signature)}) ||
      !ReadRemote(process, base + fileOffset,
                  std::span<std::byte>{image.data() + fileOffset, sizeof(file)}))
    return false;
  std::memcpy(&signature, image.data() + ntOffset, sizeof(signature));
  std::memcpy(&file, image.data() + fileOffset, sizeof(file));
  if (signature != IMAGE_NT_SIGNATURE || file.NumberOfSections == 0 || file.NumberOfSections > 96)
    return false;
  auto const headerEnd =
      optionalOffset + file.SizeOfOptionalHeader +
      static_cast<std::uint64_t>(file.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
  if (headerEnd > imageSize) return false;
  if (headerEnd > initial &&
      !ReadRemote(process, base + initial,
                  std::span<std::byte>{image.data() + initial,
                                       static_cast<std::size_t>(headerEnd - initial)}))
    return false;
  WORD magic{};
  std::memcpy(&magic, image.data() + optionalOffset, sizeof(magic));
  auto const expectedMagic = expectedFormat == pe::PeFormat::Pe32
                                 ? IMAGE_NT_OPTIONAL_HDR32_MAGIC
                                 : IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  if (magic != expectedMagic) return false;

  auto const sectionTable = optionalOffset + file.SizeOfOptionalHeader;
  for (WORD index = 0; index < file.NumberOfSections; ++index) {
    IMAGE_SECTION_HEADER section{};
    auto const offset = sectionTable + static_cast<std::uint64_t>(index) * sizeof(section);
    std::memcpy(&section, image.data() + offset, sizeof(section));
    // A mapped image commits VirtualSize bytes; SizeOfRawData is a
    // file-layout value and may extend into an uncommitted gap.
    auto const extent =
        section.Misc.VirtualSize != 0 ? section.Misc.VirtualSize : section.SizeOfRawData;
    if (extent == 0) continue;
    if (section.VirtualAddress >= imageSize || extent > imageSize - section.VirtualAddress)
      return false;
    auto const sectionBytes = std::span<std::byte>{image.data() + section.VirtualAddress, extent};
    if (!ReadRemote(process, base + section.VirtualAddress, sectionBytes)) return false;
  }
  return true;
}

int ProviderPriority(std::string const& module) noexcept {
  if (module == "kernelbase.dll") return 100;
  if (module == "kernel32.dll" || module == "user32.dll" || module == "advapi32.dll") return 90;
  if (module == "ucrtbase.dll" || module == "vcruntime140.dll" || module == "msvcp140.dll")
    return 80;
  if (module == "ntdll.dll") return 10;
  return 50;
}

bool ResolveExport(RuntimeModuleSnapshot const& snapshot, RuntimeExport const& input,
                   RuntimeExport& resolved, std::size_t depth) {
  if (depth > MaxForwardDepth) return false;
  if (!input.forwarder) {
    // IAT entries may resolve to exported data as well as code. Keep the
    // export's page kind as metadata, but do not discard a valid data address.
    if (input.address.value == 0) return false;
    resolved = input;
    return true;
  }
  auto const separator = input.forwarder->find('.');
  if (separator == std::string::npos) return false;
  auto moduleName = Normalize(input.forwarder->substr(0, separator));
  auto symbol = input.forwarder->substr(separator + 1);
  std::optional<std::uint16_t> ordinal;
  std::optional<std::string> name;
  if (!symbol.empty() && symbol[0] == '#') {
    try {
      ordinal = static_cast<std::uint16_t>(std::stoul(symbol.substr(1)));
    } catch (...) {
      return false;
    }
  } else if (!symbol.empty())
    name = symbol;
  else
    return false;

  RuntimeExport const* match{};
  for (auto const& module : snapshot.modules) {
    if (Normalize(module.moduleName) != moduleName) continue;
    for (auto const& candidate : module.exports) {
      if ((name && candidate.name && EqualName(*candidate.name, *name)) ||
          (ordinal && candidate.ordinal == ordinal)) {
        if (match) return false;
        match = &candidate;
      }
    }
  }
  // API-set contracts may have several implementation exports at
  // the same name. Prefer the stable user-mode provider rather than
  // discarding the logical forwarding alias as ambiguous.
  if (!match && moduleName.rfind("api-", 0) == 0) {
    int bestPriority = -1;
    bool ambiguous{};
    for (auto const& module : snapshot.modules) {
      auto const priority = ProviderPriority(Normalize(module.moduleName));
      for (auto const& candidate : module.exports)
        if ((name && candidate.name && EqualName(*candidate.name, *name)) ||
            (ordinal && candidate.ordinal == ordinal)) {
          if (priority > bestPriority) {
            bestPriority = priority;
            match = &candidate;
            ambiguous = false;
          } else if (priority == bestPriority && match != &candidate) {
            ambiguous = true;
          }
        }
    }
    if (ambiguous) match = nullptr;
  }
  if (!match) return false;
  return ResolveExport(snapshot, *match, resolved, depth + 1);
}

}

namespace upx_killer::engine::debugging {
RemoteModuleCatalogResult RemoteModuleCatalog::Capture(HANDLE process, DWORD processId,
                                                       pe::PeFormat expectedFormat,
                                                       std::optional<LoadedAddress> excludedBase) noexcept {
  RemoteModuleCatalogResult result{};
  if (!process || process == INVALID_HANDLE_VALUE || processId == 0) {
    result.nativeError = ERROR_INVALID_PARAMETER;
    return result;
  }
  HANDLE snapshotHandle =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
  if (snapshotHandle == INVALID_HANDLE_VALUE) {
    result.nativeError = GetLastError();
    return result;
  }
  MODULEENTRY32W entry{sizeof(entry)};
  if (!Module32FirstW(snapshotHandle, &entry)) {
    result.nativeError = GetLastError();
    CloseHandle(snapshotHandle);
    return result;
  }
  std::optional<LoadedAddress> appCompatBase;
  std::vector<std::byte> appCompatImage;
  do {
    auto const moduleBase = reinterpret_cast<std::uint64_t>(entry.modBaseAddr);
    if (excludedBase && moduleBase == excludedBase->value) continue;
    if (result.snapshot.modules.size() >= MaxModules) {
      result.nativeError = ERROR_NOT_ENOUGH_MEMORY;
      break;
    }
    auto const imageSize = static_cast<std::uint32_t>(entry.modBaseSize);
    if (imageSize == 0 || imageSize > MaxImageSize) continue;
    std::vector<std::byte> image;
    if (!ReadMappedImage(process, moduleBase, imageSize,
                         expectedFormat, image))
      continue;
    auto moduleName = Normalize(Narrow(entry.szModule));
    auto parsed = pe::imports::PeExportParser::Parse(
        image, {moduleBase}, moduleName);
    if (!parsed.Succeeded()) continue;
    RuntimeModule module{};
    module.moduleName = moduleName;
    module.base = {moduleBase};
    module.imageSize = imageSize;
    module.exports = std::move(parsed.exports);
    result.snapshot.modules.push_back(std::move(module));
    if (moduleName == "apphelp.dll") {
      appCompatBase = LoadedAddress{moduleBase};
      appCompatImage = std::move(image);
    }
  } while (Module32NextW(snapshotHandle, &entry));
  CloseHandle(snapshotHandle);
  if (result.nativeError != ERROR_SUCCESS) return result;

  RuntimeModuleSnapshot resolved = result.snapshot;
  for (auto& module : resolved.modules) {
    std::vector<RuntimeExport> filtered;
    filtered.reserve(module.exports.size());
    for (auto const& exported : module.exports) {
      RuntimeExport value{};
      if (!ResolveExport(resolved, exported, value, 0)) continue;
      // Keep the logical import contract that owned the forwarder;
      // the resolved address still comes from the final provider.
      value.moduleName = module.moduleName;
      value.name = exported.name;
      value.ordinal = exported.ordinal;
      value.forwarder.reset();
      filtered.push_back(std::move(value));
    }
    module.exports = std::move(filtered);
  }
  if (appCompatBase && !appCompatImage.empty()) {
    auto aliases = imports::AppCompatImportAliasResolver::Resolve(
        process, *appCompatBase, appCompatImage, resolved);
    auto const shim = std::find_if(
        resolved.modules.begin(), resolved.modules.end(), [&](auto const& module) {
          return module.base.value == appCompatBase->value;
        });
    if (shim != resolved.modules.end()) {
      shim->exports.insert(shim->exports.end(),
                           std::make_move_iterator(aliases.begin()),
                           std::make_move_iterator(aliases.end()));
    }
  }
  result.snapshot = std::move(resolved);
  return result;
}

}
