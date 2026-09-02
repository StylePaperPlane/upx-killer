#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"

namespace upx_killer::engine::application::elf_preparation {
ElfPreparationResult ElfTargetPreparationUseCase::Execute(
    contracts::UnpackJobRequest const& request) const noexcept {
  auto fail = [](ElfPreparationError error, std::string code,
                 std::uint32_t native = 0) {
    return ElfPreparationResult{std::nullopt, error, std::move(code), native};
  };
  try {
    auto source = sourceReader_.Read(request.targetPath,
                                     request.maximumImageSize);
    if (!source.bytes)
      return fail(ElfPreparationError::SourceReadFailed,
                  "elf.target.read_failed", source.nativeCode);
    auto parsed = elf::ElfParser::Parse(*source.bytes);
    if (!parsed.layout)
      return fail(ElfPreparationError::InvalidTarget, "elf.target.invalid");
    if (!ElfBackendCapabilities::Supports(*parsed.layout))
      return fail(ElfPreparationError::UnsupportedTarget,
                  "elf.target.kind_unsupported");
    if (request.entryPoint) {
      if (parsed.layout->imageType == elf::ElfImageType::SharedObject)
        return fail(ElfPreparationError::InvalidEntryPoint,
                    "elf.shared_object.explicit_entry_unsupported");
      auto const expected =
          parsed.layout->imageType == elf::ElfImageType::Executable
              ? contracts::EntryPointAddressKind::VirtualAddress
              : contracts::EntryPointAddressKind::RelativeVirtualAddress;
      if (request.entryPoint->kind != expected || request.entryPoint->value == 0)
        return fail(ElfPreparationError::InvalidEntryPoint,
                    "elf.entry_point.kind_unsupported");
    }
    auto discovery = elf::oep::UpxElfOepLocator::Analyze(
        *source.bytes, *parsed.layout);
    if (!discovery.plan)
      return fail(ElfPreparationError::UnsupportedPacker,
                  std::move(discovery.detailCode));
    PreparedElfTarget target{};
    target.sourcePath = request.targetPath;
    target.dependencyDirectory = request.targetPath.parent_path();
    target.sourceBytes = std::move(*source.bytes);
    target.packedLayout = std::move(*parsed.layout);
    target.discoveryPlan = std::move(*discovery.plan);
    target.explicitEntryPoint = request.entryPoint;
    return {std::move(target), ElfPreparationError::None, {}, 0};
  } catch (...) {
    return fail(ElfPreparationError::UnexpectedFailure,
                "elf.preparation.unhandled_exception");
  }
}
}  // namespace upx_killer::engine::application::elf_preparation
