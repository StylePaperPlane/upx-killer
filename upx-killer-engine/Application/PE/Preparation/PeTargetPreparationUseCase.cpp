#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"

#include "Core/PE/Parsing/PeParser.h"

namespace {
using namespace upx_killer::engine;
using upx_killer::engine::application::pe_preparation::PePreparationError;
constexpr std::size_t BaseRelocationDirectoryIndex = 5;

PePreparationError MapParseError(pe::PeError error) noexcept {
  switch (error) {
    case pe::PeError::UnsupportedPe32:
      return PePreparationError::UnsupportedPe32;
    case pe::PeError::UnsupportedArchitecture:
      return PePreparationError::UnsupportedArchitecture;
    case pe::PeError::UnsupportedImageKind:
      return PePreparationError::UnsupportedImageKind;
    default:
      return PePreparationError::InvalidPe;
  }
}

}

namespace upx_killer::engine::application::pe_preparation {
PePreparationResult PeTargetPreparationUseCase::Execute(
    UnpackRequest const& request,
    std::function<void(EngineStage)> const& progress) const noexcept {
  try {
    if (progress) progress(EngineStage::Validating);
    auto source = sourceReader_.Read(request.targetPath, request.maximumImageSize);
    if (!source.source) {
      return {std::nullopt, PePreparationError::SourceReadFailed,
              source.nativeError};
    }

    auto parsed = pe::PeParser::Parse(source.source->bytes);
    if (!parsed.layout) {
      auto const error = MapParseError(parsed.error);
      return {std::nullopt, error};
    }
    if (request.oep && request.oep->value >= parsed.layout->sizeOfImage) {
      return {std::nullopt, PePreparationError::EntryPointOutOfRange};
    }
    auto executionPlan =
        PeExecutionPlanFactory::Create(*parsed.layout, capabilities_);
    if (!executionPlan) {
      return {std::nullopt, PePreparationError::UnsupportedImageKind};
    }

    std::variant<RelativeVirtualAddress, pe::oep::OepDiscoveryPlan> entryPointTarget;
    if (request.oep) {
      entryPointTarget = *request.oep;
    } else {
      if (progress) progress(EngineStage::DiscoveringOep);
      auto discovery = pe::oep::UpxOepLocator::Analyze(source.source->bytes, *parsed.layout);
      if (!discovery.plan) {
        if (discovery.error == pe::oep::OepDiscoveryError::UnsupportedPacker) {
          return {std::nullopt, PePreparationError::UnsupportedPacker};
        }
        return {std::nullopt, PePreparationError::EntryPointNotFound};
      }
      entryPointTarget = std::move(*discovery.plan);
    }

    auto const& relocationDirectory =
        parsed.layout->directories[BaseRelocationDirectoryIndex];
    auto const hasSourceRelocations =
        relocationDirectory.address.value != 0 || relocationDirectory.size != 0;
    if (!hasSourceRelocations &&
        !std::holds_alternative<pe::oep::OepDiscoveryPlan>(entryPointTarget)) {
      return {std::nullopt, PePreparationError::SourceRelocationsInvalid};
    }

    PreparedPeTarget prepared{};
    prepared.targetPath = request.targetPath;
    prepared.dependencyDirectory = std::move(source.source->dependencyDirectory);
    prepared.sourceBytes = std::move(source.source->bytes);
    prepared.layout = std::move(*parsed.layout);
    prepared.entryPointTarget = std::move(entryPointTarget);
    prepared.executionPlan = *executionPlan;
    prepared.hasSourceRelocations = hasSourceRelocations;
    return {std::move(prepared), PePreparationError::None};
  } catch (...) {
    return {std::nullopt, PePreparationError::UnexpectedFailure};
  }
}
}
