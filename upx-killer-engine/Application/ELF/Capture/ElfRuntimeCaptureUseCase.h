#pragma once

#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"

#include <stop_token>

namespace upx_killer::engine::application::elf_capture {

struct ElfCaptureRequest {
  elf_preparation::PreparedElfTarget const& target;
  std::uint32_t timeoutMilliseconds{};
  std::uint64_t maximumImageSize{};
};

struct ElfCaptureResult {
  std::optional<elf::CapturedElfImage> image;
  std::uint64_t resolvedEntryPoint{};
  contracts::JobResult failure;
};

class IElfSnapshotCapture {
 public:
  virtual ~IElfSnapshotCapture() = default;
  [[nodiscard]] virtual ElfCaptureResult Capture(
      ElfCaptureRequest const& request,
      std::stop_token stopToken) const noexcept = 0;
};

class ElfRuntimeCaptureUseCase final {
 public:
  explicit ElfRuntimeCaptureUseCase(IElfSnapshotCapture const& capture)
      : capture_(capture) {}
  [[nodiscard]] ElfCaptureResult Execute(
      ElfCaptureRequest const& request,
      std::stop_token stopToken) const noexcept;

 private:
  IElfSnapshotCapture const& capture_;
};

}  // namespace upx_killer::engine::application::elf_capture
