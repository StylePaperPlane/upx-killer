#include "Core/PE/Imports/Internal/ImportProviderResolver.h"

#include <algorithm>
#include <cctype>
#include <limits>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe::imports;

std::string NormalizeModule(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (value.find('.') == std::string::npos) value += ".dll";
  return value;
}

bool SameSymbol(ImportSymbol const& left, ImportSymbol const& right) {
  if (left.name && right.name) return *left.name == *right.name;
  return !left.name && !right.name && left.ordinal && right.ordinal &&
         *left.ordinal == *right.ordinal;
}

std::optional<std::pair<std::string, ImportSymbol>> ParseForwarder(std::string const& value) {
  auto const separator = value.rfind('.');
  if (separator == std::string::npos || separator == 0 || separator + 1 == value.size())
    return std::nullopt;
  ImportSymbol symbol{};
  if (value[separator + 1] == '#') {
    try {
      auto const ordinal = std::stoul(value.substr(separator + 2));
      if (ordinal == 0 || ordinal > std::numeric_limits<std::uint16_t>::max())
        return std::nullopt;
      symbol.ordinal = static_cast<std::uint16_t>(ordinal);
    } catch (...) {
      return std::nullopt;
    }
  } else {
    symbol.name = value.substr(separator + 1);
  }
  return std::pair{NormalizeModule(value.substr(0, separator)), std::move(symbol)};
}
}

namespace upx_killer::engine::pe::imports::internal {
ImportProviderResolver::ImportProviderResolver(RuntimeModuleSnapshot const& runtime) {
  for (auto const& module : runtime.modules) {
    if (module.moduleName.empty() || module.imageSize == 0) continue;
    for (auto const& exported : module.exports) {
      if (exported.forwarder && !exported.moduleName.empty() &&
          (exported.name || exported.ordinal)) {
        if (auto target = ParseForwarder(*exported.forwarder)) {
          ImportSymbol symbol{};
          symbol.name = exported.name;
          if (!symbol.name) symbol.ordinal = exported.ordinal;
          forwarders_.push_back({NormalizeModule(exported.moduleName),
                                 std::move(symbol), exported.ordinal,
                                 std::move(target->first), std::move(target->second)});
        }
      }
      // Exported data is a valid import target; slot shape supplies the
      // structural evidence independently of page execute permissions.
      if (exported.address.value == 0 || exported.moduleName.empty() ||
          (!exported.name && !exported.ordinal))
        continue;
      ResolvedImportProvider provider{};
      provider.moduleName = NormalizeModule(exported.moduleName);
      provider.symbol.name = exported.name;
      if (!provider.symbol.name) provider.symbol.ordinal = exported.ordinal;
      auto& candidates = byAddress_[exported.address.value];
      if (std::any_of(candidates.begin(), candidates.end(), [&](auto const& candidate) {
            return candidate.provider.moduleName == provider.moduleName &&
                   SameSymbol(candidate.provider.symbol, provider.symbol);
          }))
        continue;
      candidates.push_back({std::move(provider), exported.ordinal, exported.forwarder});
    }
  }
}

bool ImportProviderResolver::Contains(std::uint64_t address) const noexcept {
  return byAddress_.find(address) != byAddress_.end();
}

std::optional<ResolvedImportProvider> ImportProviderResolver::Resolve(
    std::uint64_t address, std::optional<ImportProviderHint> const& hint) const {
  auto const found = byAddress_.find(address);
  if (found == byAddress_.end()) return std::nullopt;
  auto const& candidates = found->second;
  if (hint) {
    auto const module = NormalizeModule(hint->moduleName);
    auto selected = candidates.end();
    for (auto candidate = candidates.begin(); candidate != candidates.end(); ++candidate) {
      auto const matchesOrdinal = !hint->symbol.name && hint->symbol.ordinal &&
                                  candidate->ordinal == hint->symbol.ordinal;
      if (candidate->provider.moduleName != module ||
          (!SameSymbol(candidate->provider.symbol, hint->symbol) && !matchesOrdinal))
        continue;
      if (selected != candidates.end()) return std::nullopt;
      selected = candidate;
    }
    if (selected == candidates.end()) {
      // API-set names are loader contracts rather than physical modules. The
      // captured catalogue contains the host DLL's export at the observed
      // address, while UPX preserves the original contract and symbol.
      if (ForwarderMatches(address, module, hint->symbol, 0))
        return ResolvedImportProvider{module, hint->symbol};
      if (module.rfind("api-", 0) != 0 && module.rfind("ext-", 0) != 0)
        return std::nullopt;
      auto const host = std::find_if(candidates.begin(), candidates.end(),
                                    [&](auto const& candidate) {
                                      return SameSymbol(candidate.provider.symbol,
                                                        hint->symbol);
                                    });
      return host == candidates.end()
                 ? std::nullopt
                 : std::optional{ResolvedImportProvider{module, hint->symbol}};
    }
    return ResolvedImportProvider{module, hint->symbol};
  }
  return candidates.size() == 1 ? std::optional{candidates.front().provider}
                                : std::nullopt;
}

bool ImportProviderResolver::ForwarderMatches(
    std::uint64_t address, std::string const& module,
    ImportSymbol const& symbol, std::size_t depth) const {
  if (depth >= 8) return false;
  auto const candidates = byAddress_.find(address);
  if (candidates == byAddress_.end()) return false;
  for (auto const& candidate : candidates->second) {
    if (candidate.provider.moduleName == module &&
        (SameSymbol(candidate.provider.symbol, symbol) ||
         (!symbol.name && symbol.ordinal && candidate.ordinal == symbol.ordinal)))
      return true;
  }
  if (module.rfind("api-", 0) == 0 || module.rfind("ext-", 0) == 0) {
    return std::any_of(candidates->second.begin(), candidates->second.end(),
                       [&](auto const& candidate) {
                         return SameSymbol(candidate.provider.symbol, symbol);
                       });
  }
  for (auto const& forwarding : forwarders_) {
    if (forwarding.moduleName != module ||
        (!SameSymbol(forwarding.symbol, symbol) &&
         !(!symbol.name && symbol.ordinal && forwarding.ordinal == symbol.ordinal)))
      continue;
    if (ForwarderMatches(address, forwarding.targetModule,
                         forwarding.targetSymbol, depth + 1))
      return true;
  }
  return false;
}
}
