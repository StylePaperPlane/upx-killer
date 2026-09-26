#pragma once

#include "Core/PE/Imports/ImportTypes.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace upx_killer::engine::pe::imports::internal {
struct ImportProviderHint {
  std::uint32_t slotRva{};
  std::string moduleName;
  ImportSymbol symbol;
};

struct ResolvedImportProvider {
  std::string moduleName;
  ImportSymbol symbol;
};

// Keeps every independently loadable contract observed at a runtime address.
// Address equality and forwarding describe the implementation, not the
// original import owner. Only a unique contract or an exact slot hint resolves.
class ImportProviderResolver final {
 public:
  explicit ImportProviderResolver(RuntimeModuleSnapshot const& runtime);

  [[nodiscard]] bool Contains(std::uint64_t address) const noexcept;
  [[nodiscard]] std::optional<ResolvedImportProvider> Resolve(
      std::uint64_t address, std::optional<ImportProviderHint> const& hint) const;

 private:
  struct Candidate {
    ResolvedImportProvider provider;
    std::optional<std::uint16_t> ordinal;
    std::optional<std::string> forwarder;
  };
  struct ForwardingContract {
    std::string moduleName;
    ImportSymbol symbol;
    std::optional<std::uint16_t> ordinal;
    std::string targetModule;
    ImportSymbol targetSymbol;
  };
  [[nodiscard]] bool ForwarderMatches(std::uint64_t address,
                                      std::string const& module,
                                      ImportSymbol const& symbol,
                                      std::size_t depth) const;
  std::map<std::uint64_t, std::vector<Candidate>> byAddress_;
  std::vector<ForwardingContract> forwarders_;
};
}
