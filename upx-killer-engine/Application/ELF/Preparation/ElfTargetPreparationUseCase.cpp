#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"

namespace upx_killer::engine::application::elf_preparation {
ElfPreparationResult ElfTargetPreparationUseCase::Execute(
    contracts::UnpackJobRequest const& request) const noexcept {
  auto fail = [](contracts::ErrorCategory category, std::string code,
                 std::uint32_t native = 0) {
    return ElfPreparationResult{
        std::nullopt,
        {contracts::JobOutcome::Failed, category, std::move(code),
         std::nullopt, native}};
  };
  auto source = sourceReader_.Read(request.targetPath, request.maximumImageSize);
  if (!source.bytes)
    return fail(contracts::ErrorCategory::Input, "elf.target.read_failed",
                source.nativeCode);
  auto parsed = elf::ElfParser::Parse(*source.bytes);
  if (!parsed.layout)
    return fail(contracts::ErrorCategory::Input, "elf.target.invalid");
  if (!ElfBackendCapabilities::Supports(*parsed.layout)) {
    return {std::nullopt,
            {contracts::JobOutcome::UnsupportedTarget,
             contracts::ErrorCategory::UnsupportedTarget,
             "elf.target.kind_unsupported", std::nullopt, 0}};
  }
  if (request.entryPoint) {
    if (parsed.layout->imageType == elf::ElfImageType::SharedObject)
      return fail(contracts::ErrorCategory::InvalidRequest,
                  "elf.shared_object.explicit_entry_unsupported");
    auto const expected = parsed.layout->imageType == elf::ElfImageType::Executable
                              ? contracts::EntryPointAddressKind::VirtualAddress
                              : contracts::EntryPointAddressKind::RelativeVirtualAddress;
    if (request.entryPoint->kind != expected || request.entryPoint->value == 0)
      return fail(contracts::ErrorCategory::InvalidRequest,
                  "elf.entry_point.kind_unsupported");
  }
  auto discovery = elf::oep::UpxElfOepLocator::Analyze(
      *source.bytes, *parsed.layout);
  if (!discovery.plan) {
    return {std::nullopt,
            {contracts::JobOutcome::UnsupportedTarget,
             contracts::ErrorCategory::UnsupportedTarget,
             std::move(discovery.detailCode), std::nullopt, 0}};
  }
  PreparedElfTarget target{};
  target.sourcePath = request.targetPath;
  target.dependencyDirectory = request.targetPath.parent_path();
  target.sourceBytes = std::move(*source.bytes);
  target.packedLayout = std::move(*parsed.layout);
  target.discoveryPlan = std::move(*discovery.plan);
  target.explicitEntryPoint = request.entryPoint;
  return {std::move(target), {}};
}
}  // namespace upx_killer::engine::application::elf_preparation
