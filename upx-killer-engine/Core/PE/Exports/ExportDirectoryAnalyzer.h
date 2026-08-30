#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace upx_killer::engine::pe::exports {
struct ExportedFunction {
  std::uint16_t ordinal{};
  std::optional<std::string> name;
  std::optional<RelativeVirtualAddress> target;
  std::optional<std::string> forwarder;
};

struct ExportDirectoryModel {
  std::string moduleName;
  std::vector<ExportedFunction> functions;
  std::vector<RelativeVirtualAddress> codeTargets;
};

enum class ExportDirectoryError {
  None,
  InvalidDirectory,
  Truncated,
  InvalidOrdinal,
  InvalidTarget,
};

struct ExportDirectoryResult {
  std::optional<ExportDirectoryModel> directory;
  ExportDirectoryError error{ExportDirectoryError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return directory.has_value(); }
};

class ExportDirectoryAnalyzer final {
 public:
  // mappedImage is RVA-addressable (the first byte represents RVA zero).
  [[nodiscard]] static ExportDirectoryResult AnalyzeMapped(
      std::span<std::byte const> mappedImage, PeImageLayout const& layout) noexcept;
};
}
