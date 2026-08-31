#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <span>

namespace upx_killer::engine::elf::dynamic_linking {

struct ElfDynamicSection {
  std::string name;
  std::uint32_t type{};
  std::uint64_t flags{};
  std::uint64_t address{};
  std::uint64_t fileOffset{};
  std::uint64_t size{};
  std::uint64_t alignment{1};
  std::uint64_t entrySize{};
  std::string linkSection;
};

struct ElfDynamicMetadataResult {
  bool valid{};
  bool present{};
  std::vector<ElfDynamicSection> sections;
  std::string detailCode;
};

class ElfDynamicMetadataAnalyzer final {
 public:
  [[nodiscard]] static ElfDynamicMetadataResult Analyze(
      std::span<std::byte const> image,
      ElfImageLayout const& layout) noexcept;
};

}  // namespace upx_killer::engine::elf::dynamic_linking
