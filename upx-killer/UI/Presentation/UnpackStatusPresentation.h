#pragma once

#include "Core/Jobs/UnpackJob.h"

namespace upx_killer::ui::presentation {
enum class UnpackStatusTone { Succeeded, Unavailable, Error };

struct UnpackResultPresentation {
  UnpackStatusTone tone{UnpackStatusTone::Error};
  wchar_t const* resourceKey{L"StatusUnpackFailed"};
  bool exposesArtifact{};
};

class UnpackStatusPresentation final {
 public:
  [[nodiscard]] static wchar_t const* ProgressResource(
      contracts::JobStage stage) noexcept;
  [[nodiscard]] static UnpackResultPresentation Result(
      contracts::JobResult const& result) noexcept;
};
}
