#include "Application/PE/Translation/PeJobContractTranslator.h"

#include <iostream>

namespace {
using namespace upx_killer;

void Expect(bool condition, char const* message, int& failures) {
  if (condition) return;
  std::cerr << "FAIL: " << message << '\n';
  ++failures;
}
}

int RunPeJobContractTranslatorTests() {
  using upx_killer::engine::application::pe_translation::PeJobContractTranslator;

  int failures{};
  contracts::UnpackJobRequest request{};
  request.targetPath = L"sample.exe";
  request.outputPath = L"sample.dumped.exe";
  request.entryPoint = contracts::EntryPointHint{
      contracts::EntryPointAddressKind::RelativeVirtualAddress, 0x1234};
  request.timeoutMilliseconds = 12345;
  request.maximumImageSize = 0x200000;
  request.retainFailedOutput = true;
  auto translated = PeJobContractTranslator::Request(request);
  Expect(translated.request && translated.request->oep &&
             translated.request->oep->value == 0x1234 &&
             translated.request->timeoutMilliseconds == 12345 &&
             translated.request->retainFailedOutput,
         "PE request translation preserves supported job fields", failures);

  request.entryPoint->kind = contracts::EntryPointAddressKind::VirtualAddress;
  auto rejected = PeJobContractTranslator::Request(request);
  Expect(!rejected.request &&
             rejected.failure.category ==
                 contracts::ErrorCategory::InvalidRequest &&
             rejected.failure.detailCode ==
                 "pe.entry_point.kind_unsupported",
         "PE request translation rejects non-RVA entry points", failures);

  auto progress = PeJobContractTranslator::Progress(
      engine::EngineStage::RebuildingRelocations);
  Expect(progress.stage == contracts::JobStage::CapturingRelocations,
         "PE progress translation remains centralized", failures);

  auto result = PeJobContractTranslator::ReconstructionFailure(
      {std::nullopt,
       engine::application::pe_reconstruction::PeReconstructionError::RelocationValidationFailed});
  Expect(result.outcome == contracts::JobOutcome::Failed &&
             result.category == contracts::ErrorCategory::Validation &&
             result.detailCode == "pe.relocations.validation_failed",
         "PE result translation preserves relocation validation semantics",
         failures);

  auto unsupported = PeJobContractTranslator::PreparationFailure(
      {std::nullopt,
       engine::application::pe_preparation::PePreparationError::UnsupportedPacker});
  Expect(unsupported.outcome == contracts::JobOutcome::UnsupportedTarget &&
             unsupported.category == contracts::ErrorCategory::UnsupportedTarget &&
             unsupported.detailCode == "pe.packer.unsupported",
         "preparation errors translate only at the contract boundary", failures);

  auto timedOut = PeJobContractTranslator::CaptureFailure(
      {std::nullopt,
       engine::application::pe_capture::PeCaptureError::SnapshotFailed,
       engine::application::pe_capture::PeSnapshotCaptureError::TimedOut,
       258});
  Expect(timedOut.outcome == contracts::JobOutcome::TimedOut &&
             timedOut.category == contracts::ErrorCategory::TimedOut &&
             timedOut.detailCode == "job.timed_out" && timedOut.nativeCode == 258,
         "snapshot timeout remains local until contract translation", failures);

  engine::application::artifacts::PublishedArtifact artifact{
      L"sample.dumped.exe", engine::ArtifactQuality::Complete, true, {}};
  auto published = PeJobContractTranslator::Publication(
      {std::move(artifact),
       engine::application::artifacts::ArtifactPublicationError::None});
  Expect(published.outcome == contracts::JobOutcome::Completed &&
             published.category == contracts::ErrorCategory::None &&
             published.artifact && published.artifact->loaderVerified,
         "publication owns artifact success semantics", failures);
  return failures;
}
