#pragma once

#include "Application/Backends/IUnpackBackend.h"

#include <variant>

namespace upx_killer::contracts::protocol {
struct QueryCapabilitiesMessage {};
struct CapabilitiesMessage {
  std::vector<BackendManifest> manifests;
};
struct ExecuteJobMessage {
  UnpackJobRequest request;
};
struct ProgressMessage {
  ProgressEvent event;
};
struct ResultMessage {
  JobResult result;
};

using EngineHostMessage =
    std::variant<QueryCapabilitiesMessage, CapabilitiesMessage,
                 ExecuteJobMessage, ProgressMessage, ResultMessage>;
}
