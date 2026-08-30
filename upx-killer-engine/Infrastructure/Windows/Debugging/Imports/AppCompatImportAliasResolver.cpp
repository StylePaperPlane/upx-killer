#include "Infrastructure/Windows/Debugging/Imports/AppCompatImportAliasResolver.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <tuple>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe::imports;

constexpr std::size_t MaximumAliases = 512;
constexpr std::size_t ProbeBytes = 256;
constexpr std::uint32_t MaximumStateOffset = 64u * 1024u;

bool ReadRemotePointer(HANDLE process, std::uint64_t address,
                       std::uint32_t& value) noexcept {
  SIZE_T read{};
  return address != 0 &&
         ReadProcessMemory(process, reinterpret_cast<void const*>(address), &value,
                           sizeof(value), &read) &&
         read == sizeof(value);
}

bool ReadU32(std::span<std::byte const> bytes, std::size_t offset,
             std::uint32_t& value) noexcept {
  if (offset > bytes.size() || sizeof(value) > bytes.size() - offset) return false;
  std::memcpy(&value, bytes.data() + offset, sizeof(value));
  return true;
}

std::vector<RuntimeExport> ExportsAt(RuntimeModuleSnapshot const& runtime,
                                     std::uint32_t address) {
  std::vector<RuntimeExport> matches;
  std::set<std::tuple<std::string, std::string, std::uint16_t>> unique;
  for (auto const& module : runtime.modules) {
    for (auto const& exported : module.exports) {
      if (exported.address.value != address ||
          (!exported.name && !exported.ordinal))
        continue;
      auto const key = std::tuple{
          exported.moduleName,
          exported.name.value_or(std::string{}),
          exported.ordinal.value_or(0)};
      if (unique.insert(key).second) matches.push_back(exported);
    }
  }
  return matches;
}
}

namespace upx_killer::engine::debugging::imports {
std::vector<pe::imports::RuntimeExport> AppCompatImportAliasResolver::Resolve(
    HANDLE process, LoadedAddress shimBase, std::span<std::byte const> shimImage,
    pe::imports::RuntimeModuleSnapshot const& runtime) noexcept {
  try {
    std::vector<pe::imports::RuntimeExport> aliases;
    if (!process || process == INVALID_HANDLE_VALUE || shimBase.value == 0 ||
        shimImage.size() < ProbeBytes)
      return aliases;

    std::set<std::tuple<std::uint64_t, std::string, std::string, std::uint16_t>> unique;
    for (std::size_t entry = 0; entry + ProbeBytes <= shimImage.size(); ++entry) {
      auto const* code = shimImage.data() + entry;
      if (code[0] != std::byte{0x8b} || code[1] != std::byte{0xff} ||
          code[2] != std::byte{0x55} || code[3] != std::byte{0x8b} ||
          code[4] != std::byte{0xec})
        continue;

      std::optional<std::uint32_t> currentStatePointerLocation;
      std::optional<std::uint32_t> statePointerLocation;
      std::optional<std::uint32_t> originalTargetOffset;
      bool callsOriginal{};
      for (std::size_t cursor = 5; cursor + 6 <= ProbeBytes; ++cursor) {
        if (code[cursor] == std::byte{0xa1}) {
          std::uint32_t location{};
          if (ReadU32(shimImage, entry + cursor + 1, location))
            currentStatePointerLocation = location;
        }
        if (currentStatePointerLocation && code[cursor] == std::byte{0x8b} &&
            code[cursor + 1] == std::byte{0xb0}) {
          std::uint32_t offset{};
          if (ReadU32(shimImage, entry + cursor + 2, offset) &&
              offset <= MaximumStateOffset) {
            statePointerLocation = currentStatePointerLocation;
            originalTargetOffset = offset;
          }
        }
        if (code[cursor] == std::byte{0xff} &&
            code[cursor + 1] == std::byte{0xd6} && statePointerLocation &&
            originalTargetOffset) {
          callsOriginal = true;
          break;
        }
      }
      if (!statePointerLocation || !originalTargetOffset || !callsOriginal ||
          *statePointerLocation < shimBase.value ||
          *statePointerLocation - shimBase.value >= shimImage.size())
        continue;

      std::uint32_t state{};
      std::uint32_t originalTarget{};
      if (!ReadRemotePointer(process, *statePointerLocation, state) || state == 0 ||
          !ReadRemotePointer(process,
                             static_cast<std::uint64_t>(state) + *originalTargetOffset,
                             originalTarget) ||
          originalTarget == 0)
        continue;

      auto matches = ExportsAt(runtime, originalTarget);
      auto const hookAddress = shimBase.value + entry;
      for (auto& match : matches) {
        auto const key = std::tuple{
            hookAddress,
            match.moduleName,
            match.name.value_or(std::string{}),
            match.ordinal.value_or(0)};
        if (!unique.insert(key).second) continue;
        match.address = {hookAddress};
        match.forwarder.reset();
        aliases.push_back(std::move(match));
        if (aliases.size() >= MaximumAliases) return aliases;
      }
    }
    return aliases;
  } catch (...) {
    return {};
  }
}
}
