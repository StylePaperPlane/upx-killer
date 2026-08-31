#pragma once

#include "Application/TemporaryFiles/ITemporaryArtifactWorkspace.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"

#include <memory>

namespace upx_killer::infrastructure {
class LocalTemporaryArtifactWorkspace final
    : public application::ITemporaryArtifactWorkspace {
 public:
  explicit LocalTemporaryArtifactWorkspace(
      std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore)
      : m_settingsStore(std::move(settingsStore)) {}

  [[nodiscard]] application::TemporaryArtifactAllocationResult Allocate(
      std::filesystem::path const& targetPath,
      contracts::TargetDescriptor const& target) const noexcept override;

 private:
  std::shared_ptr<application::ITemporaryFileSettingsStore> m_settingsStore;
};
}
