#include "Application/ELF/Translation/ElfJobContractTranslator.h"

#include <iostream>

namespace {
using namespace upx_killer;

void Expect(bool condition, char const* message, int& failures) {
  if (condition) return;
  std::cerr << "FAIL: " << message << '\n';
  ++failures;
}
}  // namespace

int RunElfJobContractTranslatorTests() {
  using engine::application::elf_translation::ElfJobContractTranslator;
  int failures{};

  engine::application::elf_preparation::ElfPreparationResult unsupported{
      std::nullopt,
      engine::application::elf_preparation::ElfPreparationError::UnsupportedPacker,
      "elf.packer.unsupported", 0};
  auto unsupportedJob =
      ElfJobContractTranslator::PreparationFailure(unsupported);
  Expect(unsupportedJob.outcome == contracts::JobOutcome::UnsupportedTarget &&
             unsupportedJob.category ==
                 contracts::ErrorCategory::UnsupportedTarget,
         "ELF preparation errors translate only at the backend boundary",
         failures);

  engine::application::elf_capture::ElfCaptureResult cancelled{
      std::nullopt, 0,
      engine::application::elf_capture::ElfCaptureError::Cancelled,
      "job.cancelled", 995};
  auto cancelledJob = ElfJobContractTranslator::CaptureFailure(cancelled);
  Expect(cancelledJob.outcome == contracts::JobOutcome::Cancelled &&
             cancelledJob.category == contracts::ErrorCategory::Cancelled &&
             cancelledJob.nativeCode == 995,
         "ELF cancellation preserves its contract semantics", failures);

  engine::application::artifacts::PublishedArtifact artifact{
      L"sample.repaired.so", contracts::ArtifactQuality::Complete, true, {}};
  auto published = ElfJobContractTranslator::Publication(
      {std::move(artifact),
       engine::application::artifacts::ArtifactPublicationError::None});
  Expect(published.outcome == contracts::JobOutcome::Completed &&
             published.artifact && published.artifact->loaderVerified,
         "ELF publication translates a verified artifact", failures);
  return failures;
}
