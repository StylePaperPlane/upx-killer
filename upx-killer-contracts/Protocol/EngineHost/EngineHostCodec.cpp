#include "Protocol/EngineHost/EngineHostCodec.h"

#include <cstring>
#include <limits>
#include <string>
#include <type_traits>

namespace {
using namespace upx_killer::contracts;
using namespace upx_killer::contracts::protocol;

constexpr std::uint32_t QueryCapabilitiesType = 0x1001;
constexpr std::uint32_t CapabilitiesType = 0x1002;
constexpr std::uint32_t ExecuteJobType = 0x2001;
constexpr std::uint32_t ProgressType = 0x2002;
constexpr std::uint32_t ResultType = 0x2003;
constexpr std::uint32_t MaximumStringSize = 128u << 10;
constexpr std::uint32_t MaximumCollectionSize = 4096;

void PutU32(std::vector<std::byte>& bytes, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8)
    bytes.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

void PutU64(std::vector<std::byte>& bytes, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8)
    bytes.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

bool GetU32(std::span<std::byte const> bytes, std::size_t& offset,
            std::uint32_t& value) {
  if (offset > bytes.size() || 4 > bytes.size() - offset) return false;
  value = 0;
  for (unsigned shift = 0; shift < 32; shift += 8)
    value |= std::to_integer<std::uint32_t>(bytes[offset++]) << shift;
  return true;
}

bool GetU64(std::span<std::byte const> bytes, std::size_t& offset,
            std::uint64_t& value) {
  if (offset > bytes.size() || 8 > bytes.size() - offset) return false;
  value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8)
    value |= std::to_integer<std::uint64_t>(bytes[offset++]) << shift;
  return true;
}

bool PutString(std::vector<std::byte>& bytes, std::string const& value) {
  if (value.size() > MaximumStringSize) return false;
  PutU32(bytes, static_cast<std::uint32_t>(value.size()));
  auto const* first = reinterpret_cast<std::byte const*>(value.data());
  bytes.insert(bytes.end(), first, first + value.size());
  return true;
}

bool GetString(std::span<std::byte const> bytes, std::size_t& offset,
               std::string& value) {
  std::uint32_t size{};
  if (!GetU32(bytes, offset, size) || size > MaximumStringSize ||
      size > bytes.size() - offset)
    return false;
  value.assign(reinterpret_cast<char const*>(bytes.data() + offset), size);
  offset += size;
  return true;
}

std::string PathToUtf8(std::filesystem::path const& path) {
  auto value = path.u8string();
  return {reinterpret_cast<char const*>(value.data()), value.size()};
}

std::filesystem::path Utf8ToPath(std::string const& value) {
  return std::filesystem::path{
      std::u8string{reinterpret_cast<char8_t const*>(value.data()), value.size()}};
}

std::uint32_t EncodeFamily(BinaryFamily value) {
  return value == BinaryFamily::Pe ? 0x10u : 0x20u;
}
std::uint32_t EncodeClass(BinaryClass value) {
  return value == BinaryClass::Bits32 ? 0x32u : 0x64u;
}
std::uint32_t EncodeArchitecture(CpuArchitecture value) {
  return value == CpuArchitecture::X86 ? 0x86u : 0x8664u;
}
std::uint32_t EncodeKind(ImageKind value) {
  return value == ImageKind::Executable ? 0x01u : 0x02u;
}
std::uint32_t EncodeAddressing(ImageAddressing value) {
  switch (value) {
    case ImageAddressing::PlatformDefault: return 0x00u;
    case ImageAddressing::FixedAddress: return 0x11u;
    case ImageAddressing::PositionIndependent: return 0x12u;
  }
  return 0xffffffffu;
}

bool DecodeDescriptor(std::span<std::byte const> bytes, std::size_t& offset,
                      TargetDescriptor& descriptor) {
  std::uint32_t family{}, imageClass{}, architecture{}, imageKind{}, addressing{};
  if (!GetU32(bytes, offset, family) || !GetU32(bytes, offset, imageClass) ||
      !GetU32(bytes, offset, architecture) || !GetU32(bytes, offset, imageKind) ||
      !GetU32(bytes, offset, addressing))
    return false;
  if (family == 0x10) descriptor.family = BinaryFamily::Pe;
  else if (family == 0x20) descriptor.family = BinaryFamily::Elf;
  else return false;
  if (imageClass == 0x32) descriptor.imageClass = BinaryClass::Bits32;
  else if (imageClass == 0x64) descriptor.imageClass = BinaryClass::Bits64;
  else return false;
  if (architecture == 0x86) descriptor.architecture = CpuArchitecture::X86;
  else if (architecture == 0x8664) descriptor.architecture = CpuArchitecture::X64;
  else return false;
  if (imageKind == 0x01) descriptor.imageKind = ImageKind::Executable;
  else if (imageKind == 0x02) descriptor.imageKind = ImageKind::SharedLibrary;
  else return false;
  if (addressing == 0x00)
    descriptor.addressing = ImageAddressing::PlatformDefault;
  else if (addressing == 0x11)
    descriptor.addressing = ImageAddressing::FixedAddress;
  else if (addressing == 0x12)
    descriptor.addressing = ImageAddressing::PositionIndependent;
  else
    return false;
  return true;
}

void PutDescriptor(std::vector<std::byte>& bytes,
                   TargetDescriptor const& descriptor) {
  PutU32(bytes, EncodeFamily(descriptor.family));
  PutU32(bytes, EncodeClass(descriptor.imageClass));
  PutU32(bytes, EncodeArchitecture(descriptor.architecture));
  PutU32(bytes, EncodeKind(descriptor.imageKind));
  PutU32(bytes, EncodeAddressing(descriptor.addressing));
}

std::uint32_t EncodeEntryKind(EntryPointAddressKind value) {
  switch (value) {
    case EntryPointAddressKind::RelativeVirtualAddress: return 0x11;
    case EntryPointAddressKind::VirtualAddress: return 0x12;
    case EntryPointAddressKind::FileOffset: return 0x13;
  }
  return 0;
}

bool DecodeEntryKind(std::uint32_t wire, EntryPointAddressKind& value) {
  if (wire == 0x11) value = EntryPointAddressKind::RelativeVirtualAddress;
  else if (wire == 0x12) value = EntryPointAddressKind::VirtualAddress;
  else if (wire == 0x13) value = EntryPointAddressKind::FileOffset;
  else return false;
  return true;
}

std::uint32_t EncodeStage(JobStage value) {
  switch (value) {
    case JobStage::ValidatingTarget: return 0x101;
    case JobStage::DiscoveringEntryPoint: return 0x102;
    case JobStage::LoadingTarget: return 0x103;
    case JobStage::CapturingImage: return 0x104;
    case JobStage::RebuildingImports: return 0x105;
    case JobStage::CapturingRelocations: return 0x106;
    case JobStage::RebuildingImage: return 0x107;
    case JobStage::ValidatingArtifact: return 0x108;
    case JobStage::Completed: return 0x109;
  }
  return 0;
}

bool DecodeStage(std::uint32_t wire, JobStage& value) {
  switch (wire) {
    case 0x101: value = JobStage::ValidatingTarget; break;
    case 0x102: value = JobStage::DiscoveringEntryPoint; break;
    case 0x103: value = JobStage::LoadingTarget; break;
    case 0x104: value = JobStage::CapturingImage; break;
    case 0x105: value = JobStage::RebuildingImports; break;
    case 0x106: value = JobStage::CapturingRelocations; break;
    case 0x107: value = JobStage::RebuildingImage; break;
    case 0x108: value = JobStage::ValidatingArtifact; break;
    case 0x109: value = JobStage::Completed; break;
    default: return false;
  }
  return true;
}

std::uint32_t EncodeOutcome(JobOutcome value) {
  switch (value) {
    case JobOutcome::Completed: return 0x201;
    case JobOutcome::Partial: return 0x202;
    case JobOutcome::UnsupportedTarget: return 0x203;
    case JobOutcome::Cancelled: return 0x204;
    case JobOutcome::TimedOut: return 0x205;
    case JobOutcome::Failed: return 0x206;
  }
  return 0;
}

bool DecodeOutcome(std::uint32_t wire, JobOutcome& value) {
  switch (wire) {
    case 0x201: value = JobOutcome::Completed; break;
    case 0x202: value = JobOutcome::Partial; break;
    case 0x203: value = JobOutcome::UnsupportedTarget; break;
    case 0x204: value = JobOutcome::Cancelled; break;
    case 0x205: value = JobOutcome::TimedOut; break;
    case 0x206: value = JobOutcome::Failed; break;
    default: return false;
  }
  return true;
}

std::uint32_t EncodeCategory(ErrorCategory value) {
  switch (value) {
    case ErrorCategory::None: return 0x301;
    case ErrorCategory::InvalidRequest: return 0x302;
    case ErrorCategory::UnsupportedTarget: return 0x303;
    case ErrorCategory::Configuration: return 0x304;
    case ErrorCategory::Input: return 0x305;
    case ErrorCategory::Execution: return 0x306;
    case ErrorCategory::Reconstruction: return 0x307;
    case ErrorCategory::Validation: return 0x308;
    case ErrorCategory::Storage: return 0x309;
    case ErrorCategory::Protocol: return 0x30a;
    case ErrorCategory::Cancelled: return 0x30b;
    case ErrorCategory::TimedOut: return 0x30c;
    case ErrorCategory::Internal: return 0x30d;
  }
  return 0;
}

bool DecodeCategory(std::uint32_t wire, ErrorCategory& value) {
  switch (wire) {
    case 0x301: value = ErrorCategory::None; break;
    case 0x302: value = ErrorCategory::InvalidRequest; break;
    case 0x303: value = ErrorCategory::UnsupportedTarget; break;
    case 0x304: value = ErrorCategory::Configuration; break;
    case 0x305: value = ErrorCategory::Input; break;
    case 0x306: value = ErrorCategory::Execution; break;
    case 0x307: value = ErrorCategory::Reconstruction; break;
    case 0x308: value = ErrorCategory::Validation; break;
    case 0x309: value = ErrorCategory::Storage; break;
    case 0x30a: value = ErrorCategory::Protocol; break;
    case 0x30b: value = ErrorCategory::Cancelled; break;
    case 0x30c: value = ErrorCategory::TimedOut; break;
    case 0x30d: value = ErrorCategory::Internal; break;
    default: return false;
  }
  return true;
}

std::uint32_t EncodeQuality(ArtifactQuality value) {
  return value == ArtifactQuality::Complete ? 0x401u : 0x402u;
}

bool DecodeQuality(std::uint32_t wire, ArtifactQuality& value) {
  if (wire == 0x401) value = ArtifactQuality::Complete;
  else if (wire == 0x402) value = ArtifactQuality::Partial;
  else return false;
  return true;
}

bool EncodePayload(EngineHostMessage const& message, std::uint32_t& type,
                   std::vector<std::byte>& payload) {
  return std::visit(
      [&](auto const& value) -> bool {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, QueryCapabilitiesMessage>) {
          type = QueryCapabilitiesType;
          return true;
        } else if constexpr (std::is_same_v<T, CapabilitiesMessage>) {
          type = CapabilitiesType;
          if (value.manifests.size() > MaximumCollectionSize) return false;
          PutU32(payload, static_cast<std::uint32_t>(value.manifests.size()));
          for (auto const& manifest : value.manifests) {
            if (!PutString(payload, manifest.backendId) ||
                manifest.capabilities.size() > MaximumCollectionSize)
              return false;
            PutU32(payload, static_cast<std::uint32_t>(manifest.capabilities.size()));
            for (auto const& capability : manifest.capabilities)
              PutDescriptor(payload, capability);
          }
          return true;
        } else if constexpr (std::is_same_v<T, ExecuteJobMessage>) {
          type = ExecuteJobType;
          if (!PutString(payload, PathToUtf8(value.request.targetPath)) ||
              !PutString(payload, PathToUtf8(value.request.outputPath))) return false;
          PutU32(payload, value.request.entryPoint ? 1u : 0u);
          PutU32(payload, value.request.entryPoint
                              ? EncodeEntryKind(value.request.entryPoint->kind)
                              : 0u);
          PutU64(payload, value.request.entryPoint ? value.request.entryPoint->value : 0u);
          PutU32(payload, value.request.timeoutMilliseconds);
          PutU64(payload, value.request.maximumImageSize);
          PutU32(payload, value.request.retainFailedOutput ? 1u : 0u);
          return true;
        } else if constexpr (std::is_same_v<T, ProgressMessage>) {
          type = ProgressType;
          PutU32(payload, EncodeStage(value.event.stage));
          return PutString(payload, value.event.detailCode);
        } else {
          type = ResultType;
          PutU32(payload, EncodeOutcome(value.result.outcome));
          PutU32(payload, EncodeCategory(value.result.category));
          if (!PutString(payload, value.result.detailCode)) return false;
          PutU32(payload, value.result.nativeCode);
          PutU32(payload, value.result.artifact ? 1u : 0u);
          if (!value.result.artifact) return true;
          auto const& artifact = *value.result.artifact;
          if (!PutString(payload, PathToUtf8(artifact.path))) return false;
          PutU32(payload, EncodeQuality(artifact.quality));
          PutU32(payload, artifact.loaderVerified ? 1u : 0u);
          if (artifact.warnings.size() > MaximumCollectionSize) return false;
          PutU32(payload, static_cast<std::uint32_t>(artifact.warnings.size()));
          for (auto const& warning : artifact.warnings)
            if (!PutString(payload, warning)) return false;
          return true;
        }
      }, message);
}
}

namespace upx_killer::contracts::protocol {
std::optional<std::vector<std::byte>> EngineHostCodec::Encode(
    EngineHostMessage const& message) noexcept {
  try {
    std::uint32_t type{};
    std::vector<std::byte> payload;
    if (!EncodePayload(message, type, payload) || payload.size() > MaximumFrameSize)
      return std::nullopt;
    std::vector<std::byte> frame;
    frame.reserve(FrameHeaderSize + payload.size());
    PutU32(frame, ProtocolMagic);
    PutU32(frame, ProtocolVersion);
    PutU32(frame, type);
    PutU32(frame, static_cast<std::uint32_t>(payload.size()));
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<FrameHeader> EngineHostCodec::DecodeHeader(
    std::span<std::byte const> header) noexcept {
  std::size_t offset{};
  std::uint32_t magic{}, version{}, type{}, size{};
  if (header.size() != FrameHeaderSize || !GetU32(header, offset, magic) ||
      !GetU32(header, offset, version) || !GetU32(header, offset, type) ||
      !GetU32(header, offset, size) || magic != ProtocolMagic ||
      version != ProtocolVersion || size > MaximumFrameSize)
    return std::nullopt;
  return FrameHeader{type, size};
}

std::optional<EngineHostMessage> EngineHostCodec::DecodePayload(
    FrameHeader header, std::span<std::byte const> payload) noexcept {
  try {
    if (payload.size() != header.payloadSize) return std::nullopt;
    std::size_t offset{};
    if (header.messageType == QueryCapabilitiesType)
      return payload.empty() ? std::optional<EngineHostMessage>{QueryCapabilitiesMessage{}}
                             : std::nullopt;
    if (header.messageType == CapabilitiesType) {
      CapabilitiesMessage message{};
      std::uint32_t manifestCount{};
      if (!GetU32(payload, offset, manifestCount) || manifestCount > MaximumCollectionSize)
        return std::nullopt;
      for (std::uint32_t index = 0; index < manifestCount; ++index) {
        BackendManifest manifest{};
        std::uint32_t capabilityCount{};
        if (!GetString(payload, offset, manifest.backendId) ||
            !GetU32(payload, offset, capabilityCount) ||
            capabilityCount > MaximumCollectionSize) return std::nullopt;
        for (std::uint32_t capability = 0; capability < capabilityCount; ++capability) {
          TargetDescriptor descriptor{};
          if (!DecodeDescriptor(payload, offset, descriptor)) return std::nullopt;
          manifest.capabilities.push_back(descriptor);
        }
        message.manifests.push_back(std::move(manifest));
      }
      if (offset != payload.size()) return std::nullopt;
      return EngineHostMessage{std::move(message)};
    }
    if (header.messageType == ExecuteJobType) {
      ExecuteJobMessage message{};
      std::string target, output;
      std::uint32_t hasEntry{}, entryKind{}, timeout{}, retain{};
      std::uint64_t entryValue{}, maximum{};
      if (!GetString(payload, offset, target) || !GetString(payload, offset, output) ||
          !GetU32(payload, offset, hasEntry) || hasEntry > 1 ||
          !GetU32(payload, offset, entryKind) || !GetU64(payload, offset, entryValue) ||
          !GetU32(payload, offset, timeout) || !GetU64(payload, offset, maximum) ||
          !GetU32(payload, offset, retain) || retain > 1 || offset != payload.size())
        return std::nullopt;
      message.request.targetPath = Utf8ToPath(target);
      message.request.outputPath = Utf8ToPath(output);
      message.request.timeoutMilliseconds = timeout;
      message.request.maximumImageSize = maximum;
      message.request.retainFailedOutput = retain != 0;
      if (hasEntry) {
        EntryPointAddressKind kind{};
        if (!DecodeEntryKind(entryKind, kind)) return std::nullopt;
        message.request.entryPoint = EntryPointHint{kind, entryValue};
      } else if (entryKind != 0 || entryValue != 0) {
        return std::nullopt;
      }
      return EngineHostMessage{std::move(message)};
    }
    if (header.messageType == ProgressType) {
      ProgressMessage message{};
      std::uint32_t stage{};
      if (!GetU32(payload, offset, stage) || !DecodeStage(stage, message.event.stage) ||
          !GetString(payload, offset, message.event.detailCode) || offset != payload.size())
        return std::nullopt;
      return EngineHostMessage{std::move(message)};
    }
    if (header.messageType == ResultType) {
      ResultMessage message{};
      std::uint32_t outcome{}, category{}, native{}, hasArtifact{};
      if (!GetU32(payload, offset, outcome) ||
          !DecodeOutcome(outcome, message.result.outcome) ||
          !GetU32(payload, offset, category) ||
          !DecodeCategory(category, message.result.category) ||
          !GetString(payload, offset, message.result.detailCode) ||
          !GetU32(payload, offset, native) ||
          !GetU32(payload, offset, hasArtifact) || hasArtifact > 1)
        return std::nullopt;
      message.result.nativeCode = native;
      if (hasArtifact) {
        JobArtifact artifact{};
        std::string path;
        std::uint32_t quality{}, verified{}, warningCount{};
        if (!GetString(payload, offset, path) || !GetU32(payload, offset, quality) ||
            !DecodeQuality(quality, artifact.quality) ||
            !GetU32(payload, offset, verified) || verified > 1 ||
            !GetU32(payload, offset, warningCount) ||
            warningCount > MaximumCollectionSize) return std::nullopt;
        artifact.path = Utf8ToPath(path);
        artifact.loaderVerified = verified != 0;
        for (std::uint32_t warning = 0; warning < warningCount; ++warning) {
          std::string value;
          if (!GetString(payload, offset, value)) return std::nullopt;
          artifact.warnings.push_back(std::move(value));
        }
        message.result.artifact = std::move(artifact);
      }
      if (offset != payload.size()) return std::nullopt;
      return EngineHostMessage{std::move(message)};
    }
    return std::nullopt;
  } catch (...) {
    return std::nullopt;
  }
}
}
