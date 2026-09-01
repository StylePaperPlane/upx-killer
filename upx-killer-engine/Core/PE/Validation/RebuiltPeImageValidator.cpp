#include "Core/PE/Validation/RebuiltPeImageValidator.h"

#include "Core/PE/Imports/ImportTableValidator.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"

#include <Windows.h>

namespace upx_killer::engine::pe::validation {
RebuiltPeImageValidationResult RebuiltPeImageValidator::Validate(
    RebuiltPeImageValidationRequest const& request) noexcept {
  auto parsed = PeParser::Parse(request.image);
  if (!parsed.layout || parsed.layout->format != request.sourceLayout.format)
    return {std::nullopt, RebuiltPeImageValidationError::InvalidImage};
  if (!imports::ImportTableValidator::Validate(request.image, *parsed.layout))
    return {std::nullopt, RebuiltPeImageValidationError::InvalidImports};

  auto const& relocations =
      parsed.layout->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (!request.hasSourceRelocations) {
    auto const forbiddenFlags = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    if (parsed.layout->preferredImageBase !=
            request.sourceLayout.preferredImageBase ||
        relocations.address.value != 0 || relocations.size != 0 ||
        (parsed.layout->characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0 ||
        (parsed.layout->dllCharacteristics & forbiddenFlags) != 0)
      return {std::nullopt,
              RebuiltPeImageValidationError::InvalidFixedPlacement};
    return {std::move(parsed.layout), RebuiltPeImageValidationError::None};
  }

  if (parsed.layout->preferredImageBase != request.outputBase.value ||
      relocations.address.value == 0 || !request.expectedRelocationCount)
    return {std::nullopt,
            RebuiltPeImageValidationError::InvalidRelocations};

  auto relocationProbe = rebasing::PeFileRebaser::Rebase(
      request.image, *parsed.layout, request.relocationValidationBase);
  if (!relocationProbe.image ||
      relocationProbe.image->sourceSlots.size() !=
          *request.expectedRelocationCount)
    return {std::nullopt,
            RebuiltPeImageValidationError::InvalidRelocations};

  return {std::move(parsed.layout), RebuiltPeImageValidationError::None};
}
}
