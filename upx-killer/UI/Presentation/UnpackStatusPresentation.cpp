#include "pch.h"
#include "UI/Presentation/UnpackStatusPresentation.h"

namespace upx_killer::ui::presentation {
wchar_t const* UnpackStatusPresentation::ProgressResource(
    contracts::JobStage stage) noexcept {
  switch (stage) {
    case contracts::JobStage::DiscoveringEntryPoint:
      return L"StatusFindingOep";
    case contracts::JobStage::LoadingTarget:
      return L"StatusLoadingTargetLibrary";
    case contracts::JobStage::CapturingRelocations:
      return L"StatusCapturingRelocations";
    case contracts::JobStage::RebuildingImports:
      return L"StatusRebuildingImports";
    case contracts::JobStage::CapturingImage:
      return L"StatusDumping";
    case contracts::JobStage::RebuildingImage:
      return L"StatusRebuildingRelocations";
    default:
      return nullptr;
  }
}
}
