#include "Application/Coordination/UnpackCoordinator.h"
#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"
#include "Application/ELF/ElfUnpackBackend.h"
#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"
#include "Application/ELF/Preparation/ElfTargetProbe.h"
#include "Application/ELF/Reconstruction/ElfImageReconstructionUseCase.h"
#include "Infrastructure/Linux/Debugging/PtraceElfSnapshotCapture.h"
#include "Infrastructure/Linux/Debugging/ElfSnapshotCaptureRouter.h"
#include "Infrastructure/Linux/Debugging/SharedObjects/PtraceElfSharedObjectSnapshotCapture.h"
#include "Infrastructure/Linux/Loading/ElfSharedObjectLoaderCatalog.h"
#include "Infrastructure/Linux/Loading/IsolatedElfLoadVerifier.h"
#include "Infrastructure/Linux/Pipes/PosixPipeTransport.h"
#include "Infrastructure/Linux/Storage/LinuxArtifactPublisher.h"
#include "Infrastructure/Linux/Storage/LinuxElfSourceReader.h"
#include "Infrastructure/Linux/Verification/LinuxElfImageValidator.h"

#include <unistd.h>

#include <memory>
#include <array>
#include <filesystem>

namespace {
std::filesystem::path ExecutableDirectory() {
  std::array<char, 4096> path{};
  auto const length = readlink("/proc/self/exe", path.data(), path.size());
  if (length <= 0 || static_cast<std::size_t>(length) >= path.size())
    return std::filesystem::current_path();
  return std::filesystem::path{
      std::string_view{path.data(), static_cast<std::size_t>(length)}}
      .parent_path();
}
}

int main() {
  using namespace upx_killer;
  elf_host::storage::LinuxElfSourceReader sourceReader;
  engine::application::elf_preparation::ElfTargetProbe probe{sourceReader};
  engine::application::elf_preparation::ElfTargetPreparationUseCase preparation{
      sourceReader};
  elf_host::loading::ElfSharedObjectLoaderCatalog loaderCatalog{
      ExecutableDirectory()};
  elf_host::debugging::PtraceElfSnapshotCapture executableCapture;
  elf_host::debugging::PtraceElfSharedObjectSnapshotCapture sharedObjectCapture{
      loaderCatalog};
  elf_host::debugging::ElfSnapshotCaptureRouter snapshotCapture{
      executableCapture, sharedObjectCapture};
  engine::application::elf_capture::ElfRuntimeCaptureUseCase capture{
      snapshotCapture};
  engine::application::elf_reconstruction::ElfImageReconstructionUseCase
      reconstruction;
  elf_host::loading::IsolatedElfLoadVerifier loadVerifier{loaderCatalog};
  elf_host::verification::LinuxElfImageValidator validator{loadVerifier};
  elf_host::storage::LinuxArtifactPublisher publisher{validator};
  auto backend = std::make_shared<engine::application::ElfUnpackBackend>(
      probe, preparation, capture, reconstruction, publisher);
  contracts::UnpackCoordinator coordinator;
  coordinator.Register(std::move(backend));

  elf_host::pipes::PosixPipeTransport transport{STDIN_FILENO, STDOUT_FILENO};
  auto message = transport.Read();
  if (!message) return 2;
  if (std::holds_alternative<
          contracts::protocol::QueryCapabilitiesMessage>(*message)) {
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
