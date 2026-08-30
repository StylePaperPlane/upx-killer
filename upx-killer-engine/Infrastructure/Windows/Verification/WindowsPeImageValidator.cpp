#include "Infrastructure/Windows/Verification/WindowsPeImageValidator.h"

#include "Infrastructure/Windows/Verification/WindowsImageVerifier.h"

namespace upx_killer::engine::verification {
application::artifacts::RepairedImageValidationResult
WindowsPeImageValidator::Validate(
    application::artifacts::RepairedImageValidationRequest const& request)
    const noexcept {
  auto result = WindowsImageVerifier::Verify(
      {request.imagePath, request.imageKind, request.dependencyDirectory,
       request.timeoutMilliseconds});
  return {result.loaderMappable, result.exportsValid, result.completed,
          result.timedOut, result.exitCode, result.nativeError};
}
}
