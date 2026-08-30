#pragma once

#include "Core/Jobs/UnpackJob.h"

namespace upx_killer::ui::presentation {
class UnpackStatusPresentation final {
 public:
  [[nodiscard]] static wchar_t const* ProgressResource(
      contracts::JobStage stage) noexcept;
};
}
