#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"

#include "Core/PE/Parsing/PeParser.h"

namespace {
using namespace upx_killer::engine;
constexpr std::size_t BaseRelocationDirectoryIndex = 5;

EngineError MapParseError(pe::PeError error) noexcept {
  switch (error) {
    case pe::PeError::UnsupportedPe32:
      return EngineError::UnsupportedPe32;
    case pe::PeError::UnsupportedArchitecture:
      return EngineError::UnsupportedArchitecture;
    case pe::PeError::UnsupportedImageKind:
      return EngineError::UnsupportedImageKind;
    default:
      return EngineError::InvalidPe;
  }
}

bool IsUnsupported(EngineError error) noexcept {
  return error == EngineError::UnsupportedPe32 ||
         error == EngineError::UnsupportedArchitecture ||
         error == EngineError::UnsupportedImageKind;
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
      return {std::nullopt, EngineOutcome::Failed, EngineError::InvalidPe,
              source.nativeError};
    }

    auto parsed = pe::PeParser::Parse(source.source->bytes);
    if (!parsed.layout) {
      auto const error = MapParseError(parsed.error);
      return {std::nullopt,
              IsUnsupported(error) ? EngineOutcome::UnsupportedTarget
                                   : EngineOutcome::Failed,
              error};
    }
    if (request.oep && request.oep->value >= parsed.layout->sizeOfImage) {
      return {std::nullopt, EngineOutcome::Failed, EngineError::OepOutOfRange};
    }
    auto executionPlan = TargetExecutionPolicy::Resolve(*parsed.layout);
    if (!executionPlan) {
      return {std::nullopt, EngineOutcome::UnsupportedTarget,
              EngineError::UnsupportedImageKind};
    }

    std::variant<RelativeVirtualAddress, pe::oep::OepDiscoveryPlan> entryPointTarget;
    if (request.oep) {
      entryPointTarget = *request.oep;
    } else {
      if (progress) progress(EngineStage::DiscoveringOep);
      auto discovery = pe::oep::UpxOepLocator::Analyze(source.source->bytes, *parsed.layout);
      if (!discovery.plan) {
        if (discovery.error == pe::oep::OepDiscoveryError::UnsupportedPacker) {
          return {std::nullopt, EngineOutcome::UnsupportedTarget,
                  EngineError::UnsupportedPacker};
        }
        return {std::nullopt, EngineOutcome::OepNotFound, EngineError::OepNotFound};
      }
      entryPointTarget = std::move(*discovery.plan);
    }

    auto const& relocationDirectory =
        parsed.layout->directories[BaseRelocationDirectoryIndex];
    auto const hasSourceRelocations =
        relocationDirectory.address.value != 0 || relocationDirectory.size != 0;
    if (!hasSourceRelocations &&
        !std::holds_alternative<pe::oep::OepDiscoveryPlan>(entryPointTarget)) {
      return {std::nullopt, EngineOutcome::Failed,
              EngineError::SourceRelocationsInvalid};
    }

    PreparedPeTarget prepared{};
    prepared.targetPath = request.targetPath;
    prepared.dependencyDirectory = std::move(source.source->dependencyDirectory);
    prepared.sourceBytes = std::move(source.source->bytes);
    prepared.layout = std::move(*parsed.layout);
    prepared.entryPointTarget = std::move(entryPointTarget);
    prepared.executionPlan = *executionPlan;
    prepared.hasSourceRelocations = hasSourceRelocations;
    return {std::move(prepared), EngineOutcome::Completed, EngineError::None};
  } catch (...) {
    return {std::nullopt, EngineOutcome::Failed, EngineError::InvalidPe};
  }
}
}
