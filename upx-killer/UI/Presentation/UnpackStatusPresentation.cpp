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

UnpackResultPresentation UnpackStatusPresentation::Result(
    contracts::JobResult const& result) noexcept {
  if (result.outcome == contracts::JobOutcome::Completed && result.artifact) {
    return {UnpackStatusTone::Succeeded, L"StatusUnpackSucceeded", true};
  }
  if (result.outcome == contracts::JobOutcome::Partial && result.artifact) {
    return {UnpackStatusTone::Unavailable, L"StatusPartialImportsNotRebuilt", true};
  }
  if (result.detailCode == "pe.oep.required") {
    return {UnpackStatusTone::Unavailable, L"StatusOepRequired", false};
  }
  if (result.detailCode == "pe.packer.unsupported") {
    return {UnpackStatusTone::Error, L"StatusUnsupportedPacker", false};
  }
  if (result.detailCode == "pe.oep.not_found") {
    return {UnpackStatusTone::Error, L"StatusOepNotFound", false};
  }
  if (result.detailCode == "pe.imports.not_found" ||
      result.detailCode == "pe.imports.ambiguous") {
    return {UnpackStatusTone::Error, L"StatusImportsNotRebuilt", false};
  }
  if (result.detailCode == "pe.relocations.evidence_insufficient" ||
      result.detailCode == "pe.relocations.candidates_ambiguous") {
    return {UnpackStatusTone::Error, L"StatusRelocationEvidenceFailed", false};
  }
  if (result.detailCode == "pe.relocations.validation_failed" ||
      result.detailCode == "pe.relocations.source_invalid") {
    return {UnpackStatusTone::Error, L"StatusRelocationValidationFailed", false};
  }
  if (result.detailCode == "pe.wow64.unavailable" ||
      result.detailCode == "pe.machine.mismatch") {
    return {UnpackStatusTone::Error, L"StatusWow64Unavailable", false};
  }
  if (result.detailCode == "pe.relocations.pe32_type_unsupported") {
    return {UnpackStatusTone::Error, L"StatusUnsupportedPe32Relocation", false};
  }
  return {UnpackStatusTone::Error, L"StatusUnpackFailed", false};
}
}
