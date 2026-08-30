#include "Core/PE/Relocations/RelocationReconstructor.h"

#include "Core/PE/Format/PeFormatTraits.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::relocations;

template <typename T>
T ReadPointer(std::span<std::byte const> bytes, std::uint32_t offset) noexcept {
  T value{};
  std::memcpy(&value, bytes.data() + offset, sizeof(value));
  return value;
}

template <typename T>
void Append(std::vector<std::byte>& bytes, T const& value) {
  auto const* begin = reinterpret_cast<std::byte const*>(&value);
  bytes.insert(bytes.end(), begin, begin + sizeof(value));
}

bool IsPackedResidue(std::span<rebasing::SourceRelocationSlot const> sourceSlots,
                     RelativeVirtualAddress location, RelativeVirtualAddress target) noexcept {
  auto const found = std::find_if(sourceSlots.begin(), sourceSlots.end(),
                                  [&](rebasing::SourceRelocationSlot const& source) {
                                    return source.location.value == location.value;
                                  });
  return found != sourceSlots.end() && found->imageTarget &&
         found->imageTarget->value == target.value;
}

template <typename Traits>
std::vector<std::byte> EncodeDirectory(std::span<RelocationSlot const> slots) {
  std::vector<std::byte> bytes;
  std::size_t begin{};
  while (begin < slots.size()) {
    auto const page = slots[begin].location.value & ~0xfffu;
    auto end = begin;
    while (end < slots.size() && (slots[end].location.value & ~0xfffu) == page) ++end;

    auto const entryCount = end - begin;
    auto blockSize =
        static_cast<std::uint32_t>(sizeof(IMAGE_BASE_RELOCATION) + entryCount * sizeof(WORD));
    if ((blockSize & 3u) != 0) blockSize += sizeof(WORD);
    Append(bytes, IMAGE_BASE_RELOCATION{page, blockSize});
    for (auto index = begin; index < end; ++index) {
      auto const offset = slots[index].location.value - page;
      Append(bytes, static_cast<WORD>((Traits::RelocationType << 12) | offset));
    }
    if ((entryCount & 1u) != 0) Append(bytes, WORD{});
    begin = end;
  }
  return bytes;
}

template <typename Traits>
RelocationRebuildResult ReconstructTyped(
    std::span<LoadedImageSnapshot const> snapshots,
    std::span<rebasing::SourceRelocationSlot const> sourceSlots,
    PeImageLayout const& layout, LoadedAddress preferredImageBase) noexcept {
  using Pointer = typename Traits::Pointer;
  if (!Traits::AddressFits(preferredImageBase.value))
    return {std::nullopt, RelocationRebuildError::InvalidInput};
  for (auto const& snapshot : snapshots)
    if (!Traits::AddressFits(snapshot.loadedBase.value))
      return {std::nullopt, RelocationRebuildError::InvalidInput};

  RelocationRebuildPlan plan{};
  plan.preferredImageBase = preferredImageBase;
  for (std::uint32_t rva = layout.sizeOfHeaders;
       static_cast<std::uint64_t>(rva) + sizeof(Pointer) <= layout.sizeOfImage; ++rva) {
    std::optional<std::uint64_t> target;
    bool candidate = true;
    for (auto const& snapshot : snapshots) {
      auto const value = static_cast<std::uint64_t>(ReadPointer<Pointer>(snapshot.bytes, rva));
      if (value < snapshot.loadedBase.value) {
        candidate = false;
        break;
      }
      auto const relative = value - snapshot.loadedBase.value;
      if (relative >= layout.sizeOfImage || (target && *target != relative)) {
        candidate = false;
        break;
      }
      target = relative;
    }
    if (!candidate || !target) continue;

    RelocationSlot slot{{rva}, {static_cast<std::uint32_t>(*target)}};
    if (IsPackedResidue(sourceSlots, slot.location, slot.imageTarget)) continue;
    if (!plan.slots.empty() &&
        static_cast<std::uint64_t>(plan.slots.back().location.value) + sizeof(Pointer) > rva)
      return {std::nullopt, RelocationRebuildError::CandidatesAmbiguous};
    plan.slots.push_back(slot);
  }
  if (plan.slots.empty()) return {std::nullopt, RelocationRebuildError::NoRelocations};
  plan.directoryBytes = EncodeDirectory<Traits>(plan.slots);
  if (plan.directoryBytes.empty())
    return {std::nullopt, RelocationRebuildError::InvalidInput};
  return {std::move(plan), RelocationRebuildError::None};
}
}

namespace upx_killer::engine::pe::relocations {
RelocationRebuildResult RelocationReconstructor::Reconstruct(
    std::span<LoadedImageSnapshot const> snapshots,
    std::span<rebasing::SourceRelocationSlot const> sourceSlots,
    PeImageLayout const& layout, LoadedAddress preferredImageBase) noexcept {
  try {
    if (snapshots.size() != 3 || layout.sizeOfHeaders >= layout.sizeOfImage ||
        preferredImageBase.value == 0)
      return {std::nullopt, RelocationRebuildError::EvidenceInsufficient};
    for (std::size_t index = 0; index < snapshots.size(); ++index) {
      if (snapshots[index].loadedBase.value == 0 ||
          snapshots[index].bytes.size() < layout.sizeOfImage)
        return {std::nullopt, RelocationRebuildError::InvalidInput};
      for (std::size_t previous = 0; previous < index; ++previous)
        if (snapshots[index].loadedBase.value == snapshots[previous].loadedBase.value)
          return {std::nullopt, RelocationRebuildError::EvidenceInsufficient};
    }
    return layout.format == PeFormat::Pe32
               ? ReconstructTyped<format::Pe32Traits>(snapshots, sourceSlots, layout,
                                                       preferredImageBase)
               : ReconstructTyped<format::Pe64Traits>(snapshots, sourceSlots, layout,
                                                       preferredImageBase);
  } catch (...) {
    return {std::nullopt, RelocationRebuildError::InvalidInput};
  }
}
}
