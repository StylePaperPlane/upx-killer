#include "Core/PE/Sections/SectionLayoutRebuilder.h"

#include "Core/PE/Format/PeFormatTraits.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>
#include <type_traits>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::sections;

constexpr std::size_t MaximumSections = 95;

enum class SectionRole : std::size_t {
  Text,
  ReadOnlyData,
  WritableData,
  ExceptionData,
  ResourceData,
  ImportAddressTable,
  ExecutableWritable,
  Count,
};

struct AddressRange {
  std::uint32_t begin{};
  std::uint32_t end{};
};

bool IsPowerOfTwo(std::uint32_t value) noexcept { return value != 0 && (value & (value - 1)) == 0; }

std::uint32_t AlignDown(std::uint32_t value, std::uint32_t alignment) noexcept {
  return value & ~(alignment - 1);
}

bool AlignUp(std::uint32_t value, std::uint32_t alignment, std::uint32_t& aligned) noexcept {
  auto const mask = alignment - 1;
  if (value > std::numeric_limits<std::uint32_t>::max() - mask) return false;
  aligned = (value + mask) & ~mask;
  return true;
}

bool Overlaps(AddressRange const& left, AddressRange const& right) noexcept {
  return left.begin < right.end && right.begin < left.end;
}

bool ValidDirectory(PeDataDirectory const& directory, std::uint32_t imageSize) noexcept {
  return directory.address.value != 0 && directory.size != 0 &&
         directory.address.value < imageSize &&
         directory.size <= imageSize - directory.address.value;
}

AddressRange DirectoryRange(PeDataDirectory const& directory) noexcept {
  return {directory.address.value, directory.address.value + directory.size};
}

template <typename Pointer>
bool TlsVaToRva(Pointer value, SectionLayoutInput const& input, PeImageLayout const& source,
                std::uint32_t& rva) noexcept {
  auto const address = static_cast<std::uint64_t>(value);
  if (address < input.loadedBase.value ||
      address - input.loadedBase.value >= source.sizeOfImage)
    return false;
  rva = static_cast<std::uint32_t>(address - input.loadedBase.value);
  return true;
}

struct TlsEvidence {
  PeDataDirectory directory;
  AddressRange writableIndexPage;
  std::vector<AddressRange> callbackCodePages;
  std::uint32_t runtimeIndex{};
  bool hasRawTemplate{};
  bool hasExplicitAlignment{};
};

constexpr std::uint32_t MaximumPlausibleTlsIndex = 4096;

std::uint32_t EvidenceScore(TlsEvidence const& evidence) noexcept {
  return (evidence.runtimeIndex != 0 ? 4u : 0u) +
         (evidence.hasExplicitAlignment ? 2u : 0u) +
         (evidence.hasRawTemplate ? 1u : 0u);
}

template <typename Traits>
std::optional<PeDataDirectory> ReadRuntimeTlsDirectory(
    SectionLayoutInput const& input, PeImageLayout const& source) noexcept {
  using NtHeaders = typename Traits::NtHeaders;
  if (input.loadedImage.size() < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;
  IMAGE_DOS_HEADER dos{};
  std::memcpy(&dos, input.loadedImage.data(), sizeof(dos));
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) return std::nullopt;
  auto const ntOffset = static_cast<std::size_t>(dos.e_lfanew);
  if (ntOffset > input.loadedImage.size() ||
      sizeof(NtHeaders) > input.loadedImage.size() - ntOffset)
    return std::nullopt;
  NtHeaders nt{};
  std::memcpy(&nt, input.loadedImage.data() + ntOffset, sizeof(nt));
  if (nt.Signature != IMAGE_NT_SIGNATURE ||
      nt.OptionalHeader.Magic != Traits::OptionalHeaderMagic ||
      nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
    return std::nullopt;
  auto const& tls = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  PeDataDirectory result{RelativeVirtualAddress{tls.VirtualAddress}, tls.Size};
  return ValidDirectory(result, source.sizeOfImage)
             ? std::optional<PeDataDirectory>{result}
             : std::nullopt;
}

bool InSourceEntrySection(PeImageLayout const& source, std::uint32_t rva) noexcept {
  auto const found =
      std::find_if(source.sections.begin(), source.sections.end(), [&](PeSection const& section) {
        auto const extent = std::max(section.virtualSize, section.rawSize);
        return source.entryPoint.value >= section.virtualAddress.value &&
               source.entryPoint.value - section.virtualAddress.value < extent;
      });
  if (found == source.sections.end()) return false;
  auto const extent = std::max(found->virtualSize, found->rawSize);
  return rva >= found->virtualAddress.value && rva - found->virtualAddress.value < extent;
}

template <typename Traits>
std::optional<TlsEvidence> ValidateTlsDirectory(
    PeImageLayout const& source, SectionLayoutInput const& input,
    PeDataDirectory directory, bool requireCallbacks) {
  using TlsDirectory = std::conditional_t<Traits::Format == PeFormat::Pe32,
                                          IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY64>;
  using Pointer = typename Traits::Pointer;
  if (!ValidDirectory(directory, source.sizeOfImage) || directory.size < sizeof(TlsDirectory))
    return std::nullopt;
  TlsDirectory tls{};
  auto const offset = static_cast<std::size_t>(directory.address.value);
  if (offset > input.loadedImage.size() || sizeof(tls) > input.loadedImage.size() - offset)
    return std::nullopt;
  std::memcpy(&tls, input.loadedImage.data() + offset, sizeof(tls));
  auto const tlsAlignment = tls.Characteristics & IMAGE_SCN_ALIGN_MASK;
  if (tls.SizeOfZeroFill > source.sizeOfImage ||
      (tls.Characteristics & ~IMAGE_SCN_ALIGN_MASK) != 0 ||
      tlsAlignment == IMAGE_SCN_ALIGN_MASK)
    return std::nullopt;

  if ((tls.StartAddressOfRawData == 0) != (tls.EndAddressOfRawData == 0))
    return std::nullopt;
  bool hasRawTemplate{};
  if (tls.StartAddressOfRawData != 0) {
    std::uint32_t rawStart{};
    std::uint32_t rawEnd{};
    if (!TlsVaToRva(tls.StartAddressOfRawData, input, source, rawStart) ||
        !TlsVaToRva(tls.EndAddressOfRawData, input, source, rawEnd) ||
        rawEnd < rawStart)
      return std::nullopt;
    hasRawTemplate = rawEnd > rawStart;
  }
  std::uint32_t indexRva{};
  if (tls.AddressOfIndex == 0 ||
      !TlsVaToRva(tls.AddressOfIndex, input, source, indexRva) ||
      sizeof(DWORD) > source.sizeOfImage - indexRva)
    return std::nullopt;
  DWORD runtimeIndex{};
  std::memcpy(&runtimeIndex, input.loadedImage.data() + indexRva,
              sizeof(runtimeIndex));
  if (runtimeIndex > MaximumPlausibleTlsIndex) return std::nullopt;

  TlsEvidence evidence{};
  evidence.directory = directory;
  evidence.runtimeIndex = runtimeIndex;
  evidence.hasRawTemplate = hasRawTemplate;
  evidence.hasExplicitAlignment = tlsAlignment != 0;
  auto const indexPage = AlignDown(indexRva, source.sectionAlignment);
  evidence.writableIndexPage = {
      indexPage, std::min(indexPage + source.sectionAlignment, source.sizeOfImage)};
  if (tls.AddressOfCallBacks == 0)
    return requireCallbacks && !hasRawTemplate
               ? std::nullopt
               : std::optional<TlsEvidence>{std::move(evidence)};
  std::uint32_t callbackTable{};
  if (!TlsVaToRva(tls.AddressOfCallBacks, input, source, callbackTable))
    return std::nullopt;

  bool terminated{};
  for (std::size_t index = 0; index < 1024; ++index) {
    auto const callbackOffset = callbackTable + index * sizeof(Pointer);
    if (callbackOffset > input.loadedImage.size() ||
        sizeof(Pointer) > input.loadedImage.size() - callbackOffset)
      return std::nullopt;
    Pointer callback{};
    std::memcpy(&callback, input.loadedImage.data() + callbackOffset, sizeof(callback));
    auto const callbackAddress = static_cast<std::uint64_t>(callback);
    if (callbackAddress == 0) {
      terminated = true;
      break;
    }
    std::uint32_t rva{};
    if (!TlsVaToRva(callback, input, source, rva)) return std::nullopt;
    auto const start = AlignDown(rva, source.sectionAlignment);
    evidence.callbackCodePages.push_back(
        {start, std::min(start + source.sectionAlignment, source.sizeOfImage)});
  }
  if (!terminated ||
      (requireCallbacks && evidence.callbackCodePages.empty() && !hasRawTemplate))
    return std::nullopt;
  return evidence;
}

template <typename Traits>
std::optional<PeDataDirectory> DiscoverTlsCodeRanges(
    PeImageLayout const& source, SectionLayoutInput const& input,
    std::vector<AddressRange>& codeRanges, std::vector<AddressRange>& writableRanges) {
  using TlsDirectory = std::conditional_t<Traits::Format == PeFormat::Pe32,
                                          IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY64>;
  std::optional<TlsEvidence> evidence;
  if (input.oep.value == source.entryPoint.value) {
    evidence = ValidateTlsDirectory<Traits>(
        source, input, source.directories[IMAGE_DIRECTORY_ENTRY_TLS], false);
  } else {
    // UPX restores the original data directories in the mapped image before
    // transferring control. That runtime header is stronger evidence than a
    // broad scan, which can find multiple TLS-shaped byte sequences in x64
    // read-only data.
    if (auto runtimeDirectory = ReadRuntimeTlsDirectory<Traits>(input, source);
        runtimeDirectory &&
        !InSourceEntrySection(source, runtimeDirectory->address.value)) {
      evidence = ValidateTlsDirectory<Traits>(source, input, *runtimeDirectory, false);
    }
    if (!evidence) {
      std::uint32_t bestScore{};
      bool tied{};
      for (std::uint32_t rva = 0;
           rva <= source.sizeOfImage - sizeof(TlsDirectory);
           rva += static_cast<std::uint32_t>(Traits::PointerSize)) {
        if (InSourceEntrySection(source, rva)) continue;
        auto candidate = ValidateTlsDirectory<Traits>(
            source, input,
            PeDataDirectory{RelativeVirtualAddress{rva}, sizeof(TlsDirectory)}, true);
        if (!candidate) continue;
        auto const score = EvidenceScore(*candidate);
        if (!evidence || score > bestScore) {
          bestScore = score;
          evidence = std::move(candidate);
          tied = false;
        } else if (score == bestScore) {
          tied = true;
        }
      }
      if (tied) return std::nullopt;
    }
  }
  if (!evidence) return std::nullopt;
  codeRanges.insert(codeRanges.end(), evidence->callbackCodePages.begin(),
                    evidence->callbackCodePages.end());
  writableRanges.push_back(evidence->writableIndexPage);
  return evidence->directory;
}

std::vector<AddressRange> DiscoverCodeRanges(PeImageLayout const& source,
                                             SectionLayoutInput const& input,
                                             std::optional<PeDataDirectory>& tlsDirectory,
                                             std::vector<AddressRange>& writableRanges) {
  std::vector<AddressRange> ranges;
  auto minimum = source.sizeOfImage;
  std::uint32_t maximum{};
  bool hasRuntimeFunction{};

  if (input.oep.value != 0) {
    minimum = input.oep.value;
    maximum = input.oep.value + 1;
  }
  for (auto target : input.exportCodeTargets) {
    if (target.value >= source.sizeOfImage) return {};
    minimum = std::min(minimum, target.value);
    maximum = std::max(maximum, target.value + 1);
  }

  auto const& exception = source.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  if (ValidDirectory(exception, source.sizeOfImage)) {
    auto const count = exception.size / sizeof(RUNTIME_FUNCTION);
    for (std::size_t index = 0; index < count; ++index) {
      RUNTIME_FUNCTION function{};
      auto const offset =
          static_cast<std::size_t>(exception.address.value) + index * sizeof(function);
      if (offset > input.loadedImage.size() || sizeof(function) > input.loadedImage.size() - offset)
        break;
      std::memcpy(&function, input.loadedImage.data() + offset, sizeof(function));
      if (function.BeginAddress >= function.EndAddress || function.EndAddress > source.sizeOfImage)
        continue;
      minimum = std::min(minimum, static_cast<std::uint32_t>(function.BeginAddress));
      maximum = std::max(maximum, static_cast<std::uint32_t>(function.EndAddress));
      hasRuntimeFunction = true;
    }
  }

  if (!hasRuntimeFunction && input.oep.value != 0) {
    auto const containing =
        std::find_if(source.sections.begin(), source.sections.end(), [&](PeSection const& section) {
          auto const extent = std::max(section.virtualSize, section.rawSize);
          return input.oep.value >= section.virtualAddress.value &&
                 input.oep.value - section.virtualAddress.value < extent;
        });
    if (containing != source.sections.end()) {
      minimum = containing->virtualAddress.value;
      maximum =
          containing->virtualAddress.value + std::max(containing->virtualSize, containing->rawSize);
    }
  }

  if (maximum == 0 || minimum >= source.sizeOfImage) return {};

  std::uint32_t end{};
  if (!AlignUp(maximum, source.sectionAlignment, end)) return {};
  ranges.push_back(
      {AlignDown(minimum, source.sectionAlignment), std::min(end, source.sizeOfImage)});

  tlsDirectory =
      source.format == PeFormat::Pe32
          ? DiscoverTlsCodeRanges<format::Pe32Traits>(source, input, ranges, writableRanges)
          : DiscoverTlsCodeRanges<format::Pe64Traits>(source, input, ranges, writableRanges);
  return ranges;
}

bool DiscoverIatRanges(PeImageLayout const& source, ImportRebuildPlan const* imports,
                       std::vector<AddressRange>& ranges) noexcept {
  if (!imports) return true;
  auto const pointerSize = source.format == PeFormat::Pe32
                               ? format::Pe32Traits::PointerSize
                               : format::Pe64Traits::PointerSize;
  for (auto const& module : imports->modules) {
    if (module.symbols.empty()) return false;
    if (module.symbols.size() > std::numeric_limits<std::uint32_t>::max() / pointerSize)
      return false;
    auto const size = static_cast<std::uint32_t>(module.symbols.size() * pointerSize);
    if (module.firstThunk.value >= source.sizeOfImage ||
        size > source.sizeOfImage - module.firstThunk.value)
      return false;
    ranges.push_back({module.firstThunk.value, module.firstThunk.value + size});
  }
  return true;
}

SectionRole Classify(AddressRange const& page, PeSection const& sourceSection,
                     std::vector<AddressRange> const& code,
                     std::vector<AddressRange> const& writable,
                     std::vector<AddressRange> const& executableWritable,
                     std::vector<AddressRange> const& iat,
                     PeImageLayout const& source) noexcept {
  if (std::any_of(executableWritable.begin(), executableWritable.end(),
                  [&](AddressRange const& range) { return Overlaps(page, range); }))
    return SectionRole::ExecutableWritable;
  if (std::any_of(writable.begin(), writable.end(),
                  [&](AddressRange const& range) { return Overlaps(page, range); }))
    return SectionRole::WritableData;
  if (std::any_of(code.begin(), code.end(),
                  [&](AddressRange const& range) { return Overlaps(page, range); }))
    return SectionRole::Text;
  if (std::any_of(iat.begin(), iat.end(),
                  [&](AddressRange const& range) { return Overlaps(page, range); }))
    return SectionRole::ImportAddressTable;

  auto const& exception = source.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  if (ValidDirectory(exception, source.sizeOfImage) && Overlaps(page, DirectoryRange(exception)))
    return SectionRole::ExceptionData;

  auto const& resource = source.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if (ValidDirectory(resource, source.sizeOfImage) && Overlaps(page, DirectoryRange(resource)))
    return SectionRole::ResourceData;

  auto const& exports = source.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (ValidDirectory(exports, source.sizeOfImage) && Overlaps(page, DirectoryRange(exports)))
    return SectionRole::ReadOnlyData;

  auto const isReadOnly =
      (sourceSection.characteristics & IMAGE_SCN_MEM_READ) != 0 &&
      (sourceSection.characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) == 0;
  return isReadOnly ? SectionRole::ReadOnlyData : SectionRole::WritableData;
}

std::string_view BaseName(SectionRole role) noexcept {
  switch (role) {
    case SectionRole::Text:
      return ".text";
    case SectionRole::ReadOnlyData:
      return ".rdata";
    case SectionRole::WritableData:
      return ".data";
    case SectionRole::ExceptionData:
      return ".pdata";
    case SectionRole::ResourceData:
      return ".rsrc";
    case SectionRole::ImportAddressTable:
      return ".iat";
    case SectionRole::ExecutableWritable:
      return ".textw";
    default:
      return ".data";
  }
}

std::uint32_t Characteristics(SectionRole role) noexcept {
  switch (role) {
    case SectionRole::Text:
      return IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    case SectionRole::WritableData:
    case SectionRole::ImportAddressTable:
      return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    case SectionRole::ExecutableWritable:
      return IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
             IMAGE_SCN_MEM_WRITE;
    default:
      return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
  }
}

std::array<char, 8> MakeName(SectionRole role, std::size_t ordinal) {
  std::array<char, 8> name{};
  auto const base = BaseName(role);
  std::copy(base.begin(), base.end(), name.begin());
  if (ordinal != 0) {
    auto const digit = static_cast<char>('0' + std::min<std::size_t>(ordinal, 9));
    name[std::min<std::size_t>(base.size(), name.size() - 1)] = digit;
  }
  return name;
}
}

namespace upx_killer::engine::pe::sections {
SectionLayoutResult SectionLayoutRebuilder::Build(PeImageLayout const& source,
                                                  SectionLayoutInput const& input) noexcept {
  try {
    if (source.sections.empty() || source.sizeOfImage == 0 ||
        !IsPowerOfTwo(source.sectionAlignment) || !IsPowerOfTwo(source.fileAlignment) ||
        input.loadedImage.size() < source.sizeOfImage || input.oep.value >= source.sizeOfImage)
      return {std::nullopt, SectionLayoutError::InvalidInput};

    std::optional<PeDataDirectory> tlsDirectory;
    std::vector<AddressRange> writableRanges;
    auto codeRanges =
        DiscoverCodeRanges(source, input, tlsDirectory, writableRanges);
    if (codeRanges.empty()) return {std::nullopt, SectionLayoutError::InvalidInput};
    std::vector<AddressRange> iatRanges;
    if (!DiscoverIatRanges(source, input.imports, iatRanges))
      return {std::nullopt, SectionLayoutError::InvalidInput};
    std::vector<AddressRange> executableWritableRanges;
    for (auto const& region : input.memoryRegions) {
      if (region.offset.value >= source.sizeOfImage ||
          region.size > static_cast<std::uint64_t>(source.sizeOfImage) -
                            region.offset.value)
        return {std::nullopt, SectionLayoutError::InvalidInput};
      auto const begin = static_cast<std::uint32_t>(region.offset.value);
      auto const end = static_cast<std::uint32_t>(region.offset.value + region.size);
      AddressRange range{begin, end};
      if (region.writable && region.executable)
        executableWritableRanges.push_back(range);
      else if (region.writable)
        writableRanges.push_back(range);
      else if (region.executable)
        codeRanges.push_back(range);
    }

    struct PlannedRange {
      AddressRange range;
      SectionRole role;
    };

    std::vector<PlannedRange> ranges;
    for (auto const& original : source.sections) {
      auto const extent = std::max(original.virtualSize, original.rawSize);
      if (extent == 0 || original.virtualAddress.value >= source.sizeOfImage ||
          original.virtualAddress.value % source.sectionAlignment != 0)
        return {std::nullopt, SectionLayoutError::InvalidInput};
      auto const end = std::min<std::uint64_t>(
          static_cast<std::uint64_t>(original.virtualAddress.value) + extent, source.sizeOfImage);
      auto cursor = original.virtualAddress.value;
      while (cursor < end) {
        auto const pageEnd = static_cast<std::uint32_t>(std::min<std::uint64_t>(
            static_cast<std::uint64_t>(cursor) + source.sectionAlignment, end));
        AddressRange page{cursor, pageEnd};
        auto const role =
            Classify(page, original, codeRanges, writableRanges,
                     executableWritableRanges, iatRanges, source);
        if (!ranges.empty() && ranges.back().role == role && ranges.back().range.end == page.begin)
          ranges.back().range.end = page.end;
        else
          ranges.push_back({page, role});
        cursor = pageEnd;
      }
    }
    if (ranges.empty()) return {std::nullopt, SectionLayoutError::InvalidInput};
    if (ranges.size() > MaximumSections) return {std::nullopt, SectionLayoutError::TooManySections};

    SectionLayoutPlan plan{};
    plan.sections.reserve(ranges.size());
    plan.tlsDirectory = tlsDirectory;
    std::array<std::size_t, static_cast<std::size_t>(SectionRole::Count)> nameCounts{};
    for (auto const& range : ranges) {
      auto const roleIndex = static_cast<std::size_t>(range.role);
      RebuiltSection section{};
      section.name = MakeName(range.role, nameCounts[roleIndex]++);
      section.virtualAddress = {range.range.begin};
      section.virtualSize = range.range.end - range.range.begin;
      section.characteristics = Characteristics(range.role);
      plan.sections.push_back(section);
    }
    return {std::move(plan), SectionLayoutError::None};
  } catch (...) {
    return {std::nullopt, SectionLayoutError::InvalidInput};
  }
}
}
