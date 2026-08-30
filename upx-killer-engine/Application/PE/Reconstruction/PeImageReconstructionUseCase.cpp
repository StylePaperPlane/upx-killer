#include "Application/PE/Reconstruction/PeImageReconstructionUseCase.h"

#include "Core/PE/Imports/ImportDiscovery.h"
#include "Core/PE/Imports/ImportTableValidator.h"
#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"
#include "Core/PE/Relocations/RelocationReconstructor.h"

#include <Windows.h>

#include <array>

namespace upx_killer::engine::application::pe_reconstruction {
PeImageReconstructionResult PeImageReconstructionUseCase::Execute(
    UnpackRequest const& request,
    pe_preparation::PreparedPeTarget const& target,
    pe_capture::PeCaptureEvidence const& evidence,
    std::function<void(EngineStage)> const& progress) const noexcept {
  try {
    if (evidence.runs.empty()) return {std::nullopt, EngineError::DumpIncomplete};

    std::optional<ImportRebuildPlan> imports = request.imports;
    if (!imports) {
      if (progress) progress(EngineStage::RebuildingImports);
      auto discovered = pe::imports::ImportDiscovery::Discover(
          evidence.runs.front().image.bytes, target.layout,
          evidence.runs.front().runtimeImports);
      if (!discovered.plan) {
        return {std::nullopt,
                discovered.error == pe::imports::ImportDiscoveryError::ImportsAmbiguous
                    ? EngineError::ImportsAmbiguous
                    : EngineError::ImportsNotFound};
      }
      imports = std::move(discovered.plan);
    }

    pe::fixing::ImagePlacementPlan imagePlacement;
    std::optional<std::size_t> expectedRelocationCount;
    if (!target.hasSourceRelocations) {
      imagePlacement = pe::fixing::FixedImagePlacement{
          LoadedAddress{target.layout.preferredImageBase}};
    } else {
      if (evidence.runs.size() != 3)
        return {std::nullopt, EngineError::RelocationEvidenceInsufficient};
      if (progress) progress(EngineStage::RebuildingRelocations);
      std::array<pe::relocations::LoadedImageSnapshot, 3> snapshots{
          pe::relocations::LoadedImageSnapshot{evidence.runs[0].image.loadedBase,
                                               evidence.runs[0].image.bytes},
          pe::relocations::LoadedImageSnapshot{evidence.runs[1].image.loadedBase,
                                               evidence.runs[1].image.bytes},
          pe::relocations::LoadedImageSnapshot{evidence.runs[2].image.loadedBase,
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
        auto error = EngineError::RelocationEvidenceInsufficient;
        if (relocations.error ==
            pe::relocations::RelocationRebuildError::CandidatesAmbiguous)
          error = EngineError::RelocationCandidatesAmbiguous;
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
    if (!fixed.image) return {std::nullopt, fixed.error};
    auto fixedLayout = pe::PeParser::Parse(fixed.image->bytes);
    if (!fixedLayout.layout ||
        !pe::imports::ImportTableValidator::Validate(fixed.image->bytes,
                                                     *fixedLayout.layout) ||
        fixedLayout.layout->format != target.layout.format)
      return {std::nullopt, EngineError::OutputValidationFailed};

    auto const& rebuiltRelocations =
        fixedLayout.layout->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!target.hasSourceRelocations) {
      auto const fixedBaseFlags = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                  IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
      if (fixedLayout.layout->preferredImageBase != target.layout.preferredImageBase ||
          rebuiltRelocations.address.value != 0 || rebuiltRelocations.size != 0 ||
          (fixedLayout.layout->characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0 ||
          (fixedLayout.layout->dllCharacteristics & fixedBaseFlags) != 0)
        return {std::nullopt, EngineError::OutputValidationFailed};
    } else {
      if (fixedLayout.layout->preferredImageBase !=
              target.executionPlan.outputBase.value ||
          rebuiltRelocations.address.value == 0)
        return {std::nullopt,
                target.layout.format == pe::PeFormat::Pe32
                    ? EngineError::Pe32RelocationValidationFailed
                    : EngineError::RelocationValidationFailed};
      auto relocationProbe = pe::rebasing::PeFileRebaser::Rebase(
          fixed.image->bytes, *fixedLayout.layout,
          target.executionPlan.validationBase);
      if (!relocationProbe.image || !expectedRelocationCount ||
          relocationProbe.image->sourceSlots.size() != *expectedRelocationCount)
        return {std::nullopt,
                target.layout.format == pe::PeFormat::Pe32
                    ? EngineError::Pe32RelocationValidationFailed
                    : EngineError::RelocationValidationFailed};
    }

    fixed.image->warnings.insert(fixed.image->warnings.end(),
                                 evidence.runs.front().image.warnings.begin(),
                                 evidence.runs.front().image.warnings.end());
    return {ReconstructedPeImage{std::move(*fixed.image),
                                 std::move(*fixedLayout.layout)},
            EngineError::None};
  } catch (...) {
    return {std::nullopt, EngineError::RebuildFailed};
  }
}
}
