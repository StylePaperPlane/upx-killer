#include "Core/BinaryInspection/Internal/UpxPackerDetector.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>

namespace {
using upx_killer::core::UpxPackerInformation;
using upx_killer::core::binary_inspection::internal::ContainerFormat;
using upx_killer::core::binary_inspection::internal::UpxDetectionEvidence;

constexpr std::array<std::byte, 4> UpxPackHeaderMagic{
    std::byte{'U'}, std::byte{'P'}, std::byte{'X'}, std::byte{'!'}};
constexpr std::string_view UpxStubBanner{"UPX executable packer"};
constexpr std::string_view CopyrightMarker{" Copyright"};

unsigned char ByteValue(std::byte value) noexcept {
  return std::to_integer<unsigned char>(value);
}

bool Matches(std::span<std::byte const> bytes,
             std::size_t offset,
             std::string_view text) noexcept {
  if (offset > bytes.size() || text.size() > bytes.size() - offset) return false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (ByteValue(bytes[offset + index]) != static_cast<unsigned char>(text[index])) return false;
  }
  return true;
}

bool Contains(std::span<std::byte const> bytes, std::string_view text) noexcept {
  if (text.empty() || text.size() > bytes.size()) return false;
  for (std::size_t offset = 0; offset <= bytes.size() - text.size(); ++offset) {
    if (Matches(bytes, offset, text)) return true;
  }
  return false;
}

std::optional<std::uint8_t> FindPackHeaderVersion(
    std::span<std::byte const> bytes) noexcept {
  if (bytes.size() < 8) return std::nullopt;
  auto iterator = std::search(bytes.begin(), bytes.end(), UpxPackHeaderMagic.begin(),
                              UpxPackHeaderMagic.end());
  while (iterator != bytes.end()) {
    auto const offset = static_cast<std::size_t>(iterator - bytes.begin());
    if (offset + 8 <= bytes.size()) {
      auto const version = ByteValue(bytes[offset + 4]);
      auto const format = ByteValue(bytes[offset + 5]);
      auto const method = ByteValue(bytes[offset + 6]);
      auto const level = ByteValue(bytes[offset + 7]);
      if (version > 0 && version < 64 && format != 0 && method != 0 && level >= 1 && level <= 10)
        return static_cast<std::uint8_t>(version);
    }
    iterator = std::search(iterator + 1, bytes.end(), UpxPackHeaderMagic.begin(),
                           UpxPackHeaderMagic.end());
  }
  return std::nullopt;
}

std::optional<std::string> FindReleaseVersion(std::span<std::byte const> bytes) {
  constexpr std::string_view prefix{"UPX "};
  if (bytes.size() < prefix.size() + CopyrightMarker.size() + 3) return std::nullopt;

  for (std::size_t offset = 0; offset + prefix.size() < bytes.size(); ++offset) {
    if (!Matches(bytes, offset, prefix)) continue;
    auto cursor = offset + prefix.size();
    auto const versionStart = cursor;
    unsigned componentCount{};
    while (componentCount < 3) {
      auto const componentStart = cursor;
      while (cursor < bytes.size() &&
             std::isdigit(static_cast<unsigned char>(ByteValue(bytes[cursor]))) != 0) {
        ++cursor;
      }
      if (cursor == componentStart) break;
      ++componentCount;
      if (componentCount == 3 || cursor >= bytes.size() || ByteValue(bytes[cursor]) != '.') break;
      ++cursor;
    }
    if (componentCount < 2 || cursor - versionStart > 16) continue;

    auto const searchEnd = std::min(bytes.size(), cursor + 24);
    for (auto marker = cursor; marker + CopyrightMarker.size() <= searchEnd; ++marker) {
      if (!Matches(bytes, marker, CopyrightMarker)) continue;
      std::string version;
      version.reserve(cursor - versionStart);
      for (auto index = versionStart; index < cursor; ++index)
        version.push_back(static_cast<char>(ByteValue(bytes[index])));
      return version;
    }
  }
  return std::nullopt;
}

template <typename T>
std::optional<T> Prefer(std::optional<T> first, std::optional<T> second) {
  return first ? std::move(first) : std::move(second);
}
}  // namespace

namespace upx_killer::core::binary_inspection::internal {
UpxPackerInformation UpxPackerDetector::Analyze(
    std::span<std::byte const> prefix,
    std::span<std::byte const> suffix,
    UpxDetectionEvidence const& evidence) noexcept {
  try {
    auto packHeaderVersion =
        Prefer(FindPackHeaderVersion(prefix), FindPackHeaderVersion(suffix));
    auto releaseVersion = Prefer(FindReleaseVersion(prefix), FindReleaseVersion(suffix));
    auto const hasOfficialBanner = Contains(prefix, UpxStubBanner) || Contains(suffix, UpxStubBanner);

    bool detected{};
    bool standard{};
    if (evidence.container == ContainerFormat::Pe) {
      detected = evidence.canonicalLayout || evidence.packedLayout || packHeaderVersion.has_value();
      standard = evidence.canonicalLayout && packHeaderVersion.has_value();
    } else {
      detected = evidence.packedLayout || packHeaderVersion.has_value() || hasOfficialBanner ||
                 releaseVersion.has_value();
      standard = evidence.packedLayout &&
                 (hasOfficialBanner || releaseVersion.has_value() || packHeaderVersion.has_value());
    }

    if (!detected) return {};
    return {standard ? UpxPackingAssessment::LikelyStandard
                     : UpxPackingAssessment::LikelyModified,
            std::move(releaseVersion), std::move(packHeaderVersion)};
  } catch (...) {
    return {};
  }
}
}  // namespace upx_killer::core::binary_inspection::internal
