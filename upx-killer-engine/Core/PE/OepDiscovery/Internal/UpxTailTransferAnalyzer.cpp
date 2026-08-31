#include "Core/PE/OepDiscovery/Internal/UpxTailTransferAnalyzer.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::oep;

constexpr std::uint32_t ImageScnMemExecute = 0x20000000;
constexpr std::size_t MaximumTailSearch = 128;
constexpr std::array<std::byte, 1> Pe32RegisterRestore{std::byte{0x61}};
constexpr std::array<std::byte, 4> Pe64RegisterRestore{
    std::byte{0x5d}, std::byte{0x5f}, std::byte{0x5e}, std::byte{0x5b}};
constexpr std::array<std::byte, 6> Pe32DllReturn{
    std::byte{0x33}, std::byte{0xc0}, std::byte{0x40},
    std::byte{0xc2}, std::byte{0x0c}, std::byte{0x00}};
constexpr std::array<std::byte, 4> Pe64DllReturn{
    std::byte{0x6a}, std::byte{0x01}, std::byte{0x58}, std::byte{0xc3}};

std::uint64_t SectionSpan(PeSection const& section) noexcept {
  return std::max<std::uint64_t>(section.virtualSize, section.rawSize);
}

bool ContainsRva(PeSection const& section, std::uint32_t rva) noexcept {
  auto const start = static_cast<std::uint64_t>(section.virtualAddress.value);
  auto const end = start + SectionSpan(section);
  return rva >= start && rva < end;
}

PeSection const* FindSection(PeImageLayout const& layout, std::uint32_t rva) noexcept {
  auto const iterator = std::find_if(
      layout.sections.begin(), layout.sections.end(),
      [rva](PeSection const& section) { return ContainsRva(section, rva); });
  return iterator == layout.sections.end() ? nullptr : &*iterator;
}

std::optional<RelativeVirtualAddress> FindValidationTarget(
    PeImageLayout const& layout, PeSection const& stub) noexcept {
  for (auto const& section : layout.sections) {
    if (&section == &stub || section.virtualSize == 0 ||
        (section.characteristics & ImageScnMemExecute) == 0)
      continue;
    return RelativeVirtualAddress{section.virtualAddress.value};
  }
  return std::nullopt;
}

bool IsExecutableDestination(PeImageLayout const& layout, PeSection const& stub,
                             std::uint32_t target) noexcept {
  if (target >= layout.sizeOfImage) return false;
  auto const* section = FindSection(layout, target);
  return section && section != &stub &&
         (section->characteristics & ImageScnMemExecute) != 0;
}

template <std::size_t Size>
bool Matches(std::span<std::byte const> bytes, std::size_t offset,
             std::size_t end, std::array<std::byte, Size> const& pattern) noexcept {
  return offset <= end && Size <= end - offset &&
         std::equal(pattern.begin(), pattern.end(), bytes.begin() + offset);
}

void AppendDllReturn(PeImageLayout const& layout, PeSection const& stub,
                     std::size_t returnOffset,
                     std::vector<OepTransferCandidate>& candidates) {
  auto const validation = FindValidationTarget(layout, stub);
  if (!validation) return;
  auto const transferRva = static_cast<std::uint64_t>(stub.virtualAddress.value) +
                           (returnOffset - stub.rawOffset.value);
  if (transferRva > std::numeric_limits<std::uint32_t>::max()) return;
  candidates.push_back({OepTransferKind::DllReturn,
                        {static_cast<std::uint32_t>(transferRva)}, {0},
                        *validation});
}

void AppendDirectJump(std::span<std::byte const> sourceBytes,
                      PeImageLayout const& layout, PeSection const& stub,
                      std::size_t transferOffset,
                      std::vector<OepTransferCandidate>& candidates) {
  std::int32_t displacement{};
  std::memcpy(&displacement, sourceBytes.data() + transferOffset + 1,
              sizeof(displacement));
  auto const transferRva64 = static_cast<std::uint64_t>(stub.virtualAddress.value) +
                             (transferOffset - stub.rawOffset.value);
  if (transferRva64 > std::numeric_limits<std::uint32_t>::max()) return;
  auto const target64 = static_cast<std::int64_t>(transferRva64 + 5) + displacement;
  if (target64 < 0 || target64 > std::numeric_limits<std::uint32_t>::max()) return;
  auto const target = static_cast<std::uint32_t>(target64);
  if (!IsExecutableDestination(layout, stub, target)) return;

  auto const transfer = static_cast<std::uint32_t>(transferRva64);
  auto const duplicate = std::any_of(
      candidates.begin(), candidates.end(),
      [transfer](OepTransferCandidate const& candidate) {
        return candidate.transfer.value == transfer;
      });
  if (!duplicate)
    candidates.push_back(
        {OepTransferKind::DirectJump, {transfer}, {target}, {target}});
}
}

namespace upx_killer::engine::pe::oep::internal {
std::vector<OepTransferCandidate> UpxTailTransferAnalyzer::Analyze(
    std::span<std::byte const> sourceBytes, PeImageLayout const& layout,
    PeSection const& stub, std::size_t rawStart, std::size_t rawEnd) {
  std::vector<OepTransferCandidate> candidates;
  candidates.reserve(MaximumOepCandidates);
  auto const restore = layout.format == PeFormat::Pe32
                           ? std::span<std::byte const>{Pe32RegisterRestore}
                           : std::span<std::byte const>{Pe64RegisterRestore};

  for (auto offset = rawStart;
       offset <= rawEnd && restore.size() <= rawEnd - offset &&
       candidates.size() < MaximumOepCandidates;
       ++offset) {
    if (!std::equal(restore.begin(), restore.end(), sourceBytes.begin() + offset))
      continue;

    auto const searchStart = offset + restore.size();
    auto const searchEnd = std::min(rawEnd, searchStart + MaximumTailSearch);
    for (auto transferOffset = searchStart;
         transferOffset < searchEnd &&
         candidates.size() < MaximumOepCandidates;
         ++transferOffset) {
      if (layout.imageKind == PeImageKind::DynamicLibrary) {
        if (layout.format == PeFormat::Pe32 &&
            Matches(sourceBytes, transferOffset, searchEnd, Pe32DllReturn)) {
          AppendDllReturn(layout, stub, transferOffset + 3, candidates);
          continue;
        }
        if (layout.format == PeFormat::Pe64 &&
            Matches(sourceBytes, transferOffset, searchEnd, Pe64DllReturn)) {
          AppendDllReturn(layout, stub, transferOffset + 3, candidates);
          continue;
        }
      }
      if (sourceBytes[transferOffset] == std::byte{0xe9} &&
          transferOffset + 5 <= searchEnd)
        AppendDirectJump(sourceBytes, layout, stub, transferOffset, candidates);
    }
  }
  return candidates;
}
}
