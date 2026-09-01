#include "Application/PE/Reconstruction/PeImageReconstructionUseCase.h"

#include "Core/PE/Imports/ImportDiscovery.h"
#include "Core/PE/Relocations/RelocationReconstructor.h"
#include "Core/PE/Validation/RebuiltPeImageValidator.h"

#include <array>

namespace upx_killer::engine::application::pe_reconstruction {
PeImageReconstructionResult PeImageReconstructionUseCase::Execute(
    UnpackRequest const& request,
    pe_preparation::PreparedPeTarget const& target,
    pe_capture::PeCaptureEvidence const& evidence,
    std::function<void(EngineStage)> const& progress) const noexcept {
  try {
    if (evidence.runs.empty()) return {std::nullopt, PeReconstructionError::MissingCapture};

    std::optional<ImportRebuildPlan> imports = request.imports;
    if (!imports) {
      if (progress) progress(EngineStage::RebuildingImports);
      auto discovered = pe::imports::ImportDiscovery::Discover(
          evidence.runs.front().image.bytes, target.layout,
          evidence.runs.front().runtimeImports);
      if (!discovered.plan) {
        // A valid /NOENTRY DLL can have no imports at all. The packed source
        // still contains the loader stub's import directory, so only the
        // resolved zero entry point is authoritative after capture.
        if (discovered.error == pe::imports::ImportDiscoveryError::ImportsNotFound &&
            target.layout.imageKind == pe::PeImageKind::DynamicLibrary &&
            evidence.runs.front().entryPoint.value == 0) {
          imports = ImportRebuildPlan{};
        } else {
          return {std::nullopt,
                  discovered.error == pe::imports::ImportDiscoveryError::ImportsAmbiguous
                      ? PeReconstructionError::ImportsAmbiguous
                      : PeReconstructionError::ImportsNotFound};
        }
      } else {
        imports = std::move(discovered.plan);
      }
    }

    pe::fixing::ImagePlacementPlan imagePlacement;
    std::optional<std::size_t> expectedRelocationCount;
    if (!target.hasSourceRelocations) {
      imagePlacement = pe::fixing::FixedImagePlacement{
          LoadedAddress{target.layout.preferredImageBase}};
    } else {
      if (evidence.runs.size() != 3)
        return {std::nullopt, PeReconstructionError::RelocationEvidenceInsufficient};
      if (progress) progress(EngineStage::RebuildingRelocations);
      std::array<pe::relocations::LoadedImageSnapshot, 3> snapshots{
          pe::relocations::LoadedImageSnapshot{
              LoadedAddress{evidence.runs[0].image.loadedAddress.value},
              evidence.runs[0].image.bytes},
          pe::relocations::LoadedImageSnapshot{
              LoadedAddress{evidence.runs[1].image.loadedAddress.value},
              evidence.runs[1].image.bytes},
          pe::relocations::LoadedImageSnapshot{
              LoadedAddress{evidence.runs[2].image.loadedAddress.value},
              evidence.runs[2].image.bytes},
      };
      auto relocations = pe::relocations::RelocationReconstructor::Reconstruct(
          snapshots,
          request.oep
              ? std::span<pe::rebasing::SourceRelocationSlot const>{}
              : std::span<pe::rebasing::SourceRelocationSlot const>{
                    evidence.sourceRelocationSlots},
          target.layout, target.executionPlan.outputBase);
      if (!relocations.plan) {
        auto error = PeReconstructionError::RelocationEvidenceInsufficient;
        if (relocations.error ==
            pe::relocations::RelocationRebuildError::CandidatesAmbiguous)
          error = PeReconstructionError::RelocationCandidatesAmbiguous;
        return {std::nullopt, error};
      }
      expectedRelocationCount = relocations.plan->slots.size();
      relocations.plan->enableDynamicBase = target.executionPlan.enableDynamicBase;
      relocations.plan->enableHighEntropyVa = target.executionPlan.enableHighEntropyVa;
      imagePlacement = std::move(*relocations.plan);
    }

    if (progress) progress(EngineStage::Fixing);
    auto fixed = pe::PeImageFixer::Rebuild(
        target.layout, evidence.runs.front().image,
        {evidence.runs.front().entryPoint, std::move(imports),
         std::move(imagePlacement)});
    if (!fixed.image)
      return {std::nullopt, PeReconstructionError::FixingFailed, fixed.error};
    auto validation = pe::validation::RebuiltPeImageValidator::Validate(
        {fixed.image->bytes, target.layout, target.executionPlan.outputBase,
         target.executionPlan.validationBase, target.hasSourceRelocations,
         expectedRelocationCount});
    if (!validation.layout) {
      if (validation.error ==
          pe::validation::RebuiltPeImageValidationError::InvalidRelocations)
        return {std::nullopt,
                PeReconstructionError::RelocationValidationFailed};
      return {std::nullopt, PeReconstructionError::OutputValidationFailed};
    }

    fixed.image->warnings.insert(fixed.image->warnings.end(),
                                 evidence.runs.front().image.warnings.begin(),
                                 evidence.runs.front().image.warnings.end());
    return {ReconstructedPeImage{std::move(*fixed.image),
                                 std::move(*validation.layout)},
            PeReconstructionError::None};
  } catch (...) {
    return {std::nullopt, PeReconstructionError::UnexpectedFailure};
  }
}
}
