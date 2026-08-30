#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace upx_killer::contracts {
enum class ArtifactQuality { Partial, Complete };

struct JobArtifact {
  std::filesystem::path path;
  ArtifactQuality quality{ArtifactQuality::Partial};
  bool loaderVerified{};
  std::vector<std::string> warnings;
};
}
