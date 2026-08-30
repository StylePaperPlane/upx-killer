#include "Application/Coordination/UnpackCoordinator.h"

#include <iostream>
#include <memory>
#include <utility>

namespace {
using namespace upx_killer::contracts;

int failures{};

void Expect(bool value, char const* message) {
  if (!value) {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

class FakeBackend final : public IUnpackBackend {
 public:
  FakeBackend(std::string id, BackendProbeResult probe, JobResult result)
      : id_(std::move(id)), probe_(std::move(probe)), result_(std::move(result)) {}

  BackendManifest Manifest() const override {
    return {id_, probe_.target ? std::vector<TargetDescriptor>{*probe_.target}
                              : std::vector<TargetDescriptor>{}};
  }

  BackendProbeResult Probe(UnpackJobRequest const&) const noexcept override { return probe_; }

  JobResult Execute(UnpackJobRequest const&, ProgressCallback const&,
                    std::stop_token) noexcept override {
    ++executeCount;
    return result_;
  }

  int executeCount{};

 private:
  std::string id_;
  BackendProbeResult probe_;
  JobResult result_;
};

UnpackJobRequest ValidRequest() {
  UnpackJobRequest request{};
  request.targetPath = L"input.bin";
  request.outputPath = L"output.bin";
  return request;
}
}

int RunUnpackCoordinatorTests() {
  auto const pe32 = TargetDescriptor{BinaryFamily::Pe, BinaryClass::Bits32,
                                     CpuArchitecture::X86, ImageKind::Executable};
  auto selected = std::make_shared<FakeBackend>(
      "pe", BackendProbeResult{true, true, pe32, {}},
      JobResult{JobOutcome::Completed, ErrorCategory::None, {}});
  auto ignored = std::make_shared<FakeBackend>(
      "elf", BackendProbeResult{},
      JobResult{JobOutcome::Failed, ErrorCategory::Internal, "unexpected"});
  UnpackCoordinator coordinator;
  coordinator.Register(ignored);
  coordinator.Register(selected);
  auto result = coordinator.Execute(ValidRequest());
  Expect(result.outcome == JobOutcome::Completed && selected->executeCount == 1 &&
             ignored->executeCount == 0,
         "the only recognizing backend executes the job");
  Expect(coordinator.QueryCapabilities().size() == 2,
         "capability manifests are returned without probing a target");

  UnpackCoordinator unknown;
  unknown.Register(ignored);
  result = unknown.Execute(ValidRequest());
  Expect(result.outcome == JobOutcome::UnsupportedTarget &&
             result.detailCode == "target.unrecognized",
         "an unknown binary family is reported without invoking a backend");

  auto unsupported = std::make_shared<FakeBackend>(
      "future-elf", BackendProbeResult{true, false, pe32, "elf.backend.unavailable"},
      JobResult{});
  UnpackCoordinator knownUnsupported;
  knownUnsupported.Register(unsupported);
  result = knownUnsupported.Execute(ValidRequest());
  Expect(result.outcome == JobOutcome::UnsupportedTarget &&
             result.detailCode == "elf.backend.unavailable" &&
             unsupported->executeCount == 0,
         "a recognized but unsupported target keeps the backend detail code");

  auto duplicate = std::make_shared<FakeBackend>(
      "duplicate", BackendProbeResult{true, true, pe32, {}}, JobResult{});
  coordinator.Register(duplicate);
  result = coordinator.Execute(ValidRequest());
  Expect(result.category == ErrorCategory::Configuration &&
             result.detailCode == "coordinator.backend.multiple_matches" &&
             duplicate->executeCount == 0,
         "multiple backend claims are rejected as configuration errors");

  auto invalid = ValidRequest();
  invalid.outputPath.clear();
  result = unknown.Execute(invalid);
  Expect(result.category == ErrorCategory::InvalidRequest,
         "invalid jobs are rejected before backend probing");
  return failures;
}
