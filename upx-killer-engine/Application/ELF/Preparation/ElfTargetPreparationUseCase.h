#pragma once

#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"
#include "Core/ELF/OepDiscovery/UpxElfOepLocator.h"
#include "Core/Jobs/UnpackJob.h"

#include <filesystem>
#include <optional>
#include <span>

namespace upx_killer::engine::application::elf_preparation {

struct ElfSourceReadResult {
  std::optional<std::vector<std::byte>> bytes;
  std::uint32_t nativeCode{};
};

class IElfSourceReader {
 public:
  virtual ~IElfSourceReader() = default;
  [[nodiscard]] virtual ElfSourceReadResult Read(
      std::filesystem::path const& path,
      std::uint64_t maximumSize) const noexcept = 0;
};

struct PreparedElfTarget {
  std::filesystem::path sourcePath;
  std::filesystem::path dependencyDirectory;
  std::vector<std::byte> sourceBytes;
  elf::ElfImageLayout packedLayout;
  elf::oep::ElfOepDiscoveryPlan discoveryPlan;
  std::optional<contracts::EntryPointHint> explicitEntryPoint;
};

enum class ElfPreparationError {
  None,
  SourceReadFailed,
  InvalidTarget,
  UnsupportedTarget,
  InvalidEntryPoint,
  UnsupportedPacker,
  UnexpectedFailure,
};

struct ElfPreparationResult {
  std::optional<PreparedElfTarget> target;
  ElfPreparationError error{ElfPreparationError::None};
  std::string detailCode;
  std::uint32_t nativeCode{};
};

class ElfTargetPreparationUseCase final {
 public:
  explicit ElfTargetPreparationUseCase(IElfSourceReader const& sourceReader)
      : sourceReader_(sourceReader) {}

  [[nodiscard]] ElfPreparationResult Execute(
      contracts::UnpackJobRequest const& request) const noexcept;

 private:
  IElfSourceReader const& sourceReader_;
};

}  // namespace upx_killer::engine::application::elf_preparation
