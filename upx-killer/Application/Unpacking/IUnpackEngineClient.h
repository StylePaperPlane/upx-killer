#pragma once

#include "Core/Unpacking/UnpackTypes.h"

#include <functional>

namespace upx_killer::application {
class IUnpackEngineClient {
 public:
  virtual ~IUnpackEngineClient() = default;
  using ProgressCallback = std::function<void(engine::EngineStage)>;

  [[nodiscard]] virtual engine::EngineResult Execute(
      engine::UnpackRequest const& request, ProgressCallback const& progress = {}) noexcept = 0;
};
}
