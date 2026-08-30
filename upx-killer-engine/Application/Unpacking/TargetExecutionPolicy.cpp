#include "Application/Unpacking/TargetExecutionPolicy.h"

#include <algorithm>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::application;

void FillDistinctBases(TargetExecutionPlan& plan,
                       std::array<std::uint64_t, 4> candidates) noexcept {
  plan.captureBases[0] = plan.outputBase;
  plan.captureCount = 1;
  for (auto candidate : candidates) {
    if (plan.captureCount == plan.captureBases.size()) break;
    if (candidate == 0 || candidate == plan.outputBase.value) continue;
    auto const duplicate = std::any_of(
        plan.captureBases.begin(), plan.captureBases.begin() + plan.captureCount,
        [candidate](LoadedAddress value) { return value.value == candidate; });
    if (!duplicate) plan.captureBases[plan.captureCount++] = LoadedAddress{candidate};
  }
}
}

namespace upx_killer::engine::application {
std::optional<TargetExecutionPlan> TargetExecutionPolicy::Resolve(
    pe::PeImageLayout const& image) noexcept {
  if (image.imageKind == pe::PeImageKind::DynamicLibrary && image.format != pe::PeFormat::Pe32)
    return std::nullopt;

  TargetExecutionPlan plan{};
  plan.rebuildRelocations = image.sourceLoadPolicy.hasRelocations;
  plan.enableDynamicBase = plan.rebuildRelocations && image.sourceLoadPolicy.dynamicBase;
  plan.enableHighEntropyVa = plan.enableDynamicBase && image.format == pe::PeFormat::Pe64 &&
                               image.sourceLoadPolicy.highEntropyVa;
  if (!plan.rebuildRelocations) {
    plan.outputBase = LoadedAddress{image.preferredImageBase};
    plan.captureBases[0] = plan.outputBase;
    plan.captureCount = 1;
    plan.validationBase = plan.outputBase;
    return plan;
  }

  auto const canonical = image.format == pe::PeFormat::Pe32 ? 0x00400000ull : 0x140000000ull;
  plan.outputBase = LoadedAddress{plan.enableDynamicBase ? canonical : image.preferredImageBase};
  if (image.format == pe::PeFormat::Pe32) {
    if (image.imageKind == pe::PeImageKind::DynamicLibrary) {
      plan.captureBases = {LoadedAddress{0x10000000ull}, LoadedAddress{0x20000000ull},
                           LoadedAddress{0x28000000ull}};
      plan.captureCount = plan.captureBases.size();
    } else {
      FillDistinctBases(plan,
                        {0x00400000ull, 0x10000000ull, 0x20000000ull, 0x28000000ull});
    }
    plan.validationBase = LoadedAddress{0x30000000ull};
  } else {
    FillDistinctBases(plan, {0x140000000ull, 0x180000000ull, 0x1c0000000ull, 0x200000000ull});
    plan.validationBase = LoadedAddress{0x240000000ull};
  }
  return plan.captureCount == 3 ? std::optional<TargetExecutionPlan>{plan} : std::nullopt;
}
}
