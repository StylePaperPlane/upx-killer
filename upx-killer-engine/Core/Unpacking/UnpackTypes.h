#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace upx_killer::engine {
struct RelativeVirtualAddress {
  std::uint32_t value{};
};

struct LoadedAddress {
  std::uint64_t value{};
};

struct FileOffset {
  std::uint32_t value{};
};

enum class ArtifactQuality {
  Partial,
  Complete,
};

enum class EngineStage {
  Validating,
  DiscoveringOep,
  LoadingTargetLibrary,
  Launching,
  WaitingForOep,
  Dumping,
  RebuildingImports,
  CapturingRelocations,
  RebuildingRelocations,
  Fixing,
  ValidatingOutput,
  Completed,
};

struct ImportSymbol {
  std::optional<std::string> name;
  std::optional<std::uint16_t> ordinal;
  std::uint16_t hint{};
};

struct ImportModulePlan {
  std::string moduleName;
  RelativeVirtualAddress firstThunk;
  std::vector<ImportSymbol> symbols;
};

struct ImportRebuildPlan {
  std::vector<ImportModulePlan> modules;
};

struct UnpackRequest {
  std::filesystem::path targetPath;
  std::optional<RelativeVirtualAddress> oep;
  std::optional<ImportRebuildPlan> imports;
  std::filesystem::path outputPath;
  std::uint32_t timeoutMilliseconds{60'000};
  std::uint64_t maximumImageSize{1ull << 30};
  bool retainFailedOutput{};
};

}
