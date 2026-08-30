#include "Application/Coordination/UnpackCoordinator.h"
#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Application/PE/PeUnpackBackend.h"
#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"
#include "Application/PE/Preparation/PeTargetProbe.h"
#include "Application/PE/Reconstruction/PeImageReconstructionUseCase.h"
#include "Infrastructure/Windows/Capture/WindowsPeSnapshotCapture.h"
#include "Infrastructure/Windows/Pipes/EngineHostPipeTransport.h"
#include "Infrastructure/Windows/Storage/WindowsArtifactStore.h"
#include "Infrastructure/Windows/Storage/WindowsTargetSourceReader.h"
#include "Infrastructure/Windows/Verification/WindowsPeImageValidator.h"

#include <Windows.h>

#include <memory>

int wmain() {
  using namespace upx_killer;
  engine::storage::WindowsTargetSourceReader sourceReader;
  engine::application::pe_preparation::PeTargetProbe probe{sourceReader};
  engine::application::pe_preparation::PeTargetPreparationUseCase preparation{
      sourceReader};
  engine::capture::WindowsPeSnapshotCapture snapshotCapture;
  engine::application::pe_capture::PeRuntimeCaptureUseCase capture{snapshotCapture};
  engine::application::pe_reconstruction::PeImageReconstructionUseCase reconstruction;
  engine::storage::WindowsArtifactStore artifactStore;
  engine::verification::WindowsPeImageValidator imageValidator;
  engine::application::artifacts::ArtifactPublicationUseCase publication{
      artifactStore, imageValidator};
  auto backend = std::make_shared<engine::application::PeUnpackBackend>(
      probe, preparation, capture, reconstruction, publication);
  contracts::UnpackCoordinator coordinator;
  coordinator.Register(std::move(backend));

  engine_host::EngineHostPipeTransport transport{GetStdHandle(STD_INPUT_HANDLE),
                                                 GetStdHandle(STD_OUTPUT_HANDLE)};
  auto message = transport.Read();
  if (!message) return 2;
  if (std::holds_alternative<contracts::protocol::QueryCapabilitiesMessage>(*message)) {
    return transport.Write(contracts::protocol::CapabilitiesMessage{
               coordinator.QueryCapabilities()})
               ? 0
               : 3;
  }
  auto const* execute =
      std::get_if<contracts::protocol::ExecuteJobMessage>(&*message);
  if (!execute) return 2;
  auto result = coordinator.Execute(
      execute->request,
      [&](contracts::ProgressEvent const& event) {
        (void)transport.Write(contracts::protocol::ProgressMessage{event});
      });
  return transport.Write(
             contracts::protocol::ResultMessage{std::move(result)})
             ? 0
             : 3;
}
