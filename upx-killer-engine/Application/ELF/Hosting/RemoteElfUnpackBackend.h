#pragma once

#include "Application/ELF/Hosting/IElfHostClient.h"
#include "Application/ELF/Preparation/ElfTargetProbe.h"

namespace upx_killer::engine::application {

class RemoteElfUnpackBackend final : public contracts::IUnpackBackend {
 public:
  RemoteElfUnpackBackend(
      elf_preparation::ElfTargetProbe const& probe,
      elf_hosting::IElfHostClient const& client)
      : probe_(probe), client_(client) {}

  [[nodiscard]] contracts::BackendManifest Manifest() const override;
  [[nodiscard]] contracts::BackendProbeResult Probe(
      contracts::UnpackJobRequest const& request) const noexcept override;
  [[nodiscard]] contracts::JobResult Execute(
      contracts::UnpackJobRequest const& request,
      contracts::ProgressCallback const& progress,
      std::stop_token stopToken) noexcept override;

 private:
  elf_preparation::ElfTargetProbe const& probe_;
  elf_hosting::IElfHostClient const& client_;
};

}  // namespace upx_killer::engine::application
