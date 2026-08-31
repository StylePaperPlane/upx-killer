#include "Core/PE/Parsing/PeParser.h"
#include "Tests/Support/EngineHostTestClient.h"

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <cstring>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer;

std::vector<std::byte> ReadAll(std::filesystem::path const& path) {
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  if (!stream) return {};
  auto const length = stream.tellg();
  if (length <= 0) return {};
  std::vector<std::byte> bytes(static_cast<std::size_t>(length));
  stream.seekg(0);
  stream.read(reinterpret_cast<char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
  return stream ? std::move(bytes) : std::vector<std::byte>{};
}

std::optional<engine::pe::PeImageLayout> Parse(
    std::filesystem::path const& path) {
  auto bytes = ReadAll(path);
  return engine::pe::PeParser::Parse(bytes).layout;
}

std::filesystem::path HostPath() {
  wchar_t executablePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
  auto const testDirectory = std::filesystem::path{executablePath}.parent_path();
  auto const repository = testDirectory.parent_path().parent_path().parent_path();
  auto const configuration = testDirectory.filename();
  return repository / L"upx-killer" / L"x64" / configuration /
         L"upx-killer" / L"upx_killer_engine_host.exe";
}

bool HasOnlyDir64Relocations(std::filesystem::path const& path,
                             engine::pe::PeImageLayout const& layout) {
  auto const& directory = layout.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (directory.address.value == 0 || directory.size < sizeof(IMAGE_BASE_RELOCATION))
    return false;
  auto bytes = ReadAll(path);
  auto fileOffsetForRva = [&](std::uint32_t rva) -> std::optional<std::size_t> {
    for (auto const& section : layout.sections) {
      auto const begin = section.virtualAddress.value;
      auto const end = static_cast<std::uint64_t>(begin) + section.rawSize;
      if (rva >= begin && rva < end)
        return static_cast<std::size_t>(section.rawOffset.value) + (rva - begin);
    }
    return std::nullopt;
  };
  auto offset = fileOffsetForRva(directory.address.value);
  if (!offset || *offset > bytes.size() || directory.size > bytes.size() - *offset)
    return false;
  auto const end = *offset + directory.size;
  bool foundDir64{};
  while (*offset < end) {
    if (sizeof(IMAGE_BASE_RELOCATION) > end - *offset) return false;
    IMAGE_BASE_RELOCATION block{};
    std::memcpy(&block, bytes.data() + *offset, sizeof(block));
    if (block.SizeOfBlock < sizeof(block) || block.SizeOfBlock > end - *offset ||
        ((block.SizeOfBlock - sizeof(block)) % sizeof(std::uint16_t)) != 0)
      return false;
    auto entryOffset = *offset + sizeof(block);
    auto const entryEnd = *offset + block.SizeOfBlock;
    while (entryOffset < entryEnd) {
      std::uint16_t entry{};
      std::memcpy(&entry, bytes.data() + entryOffset, sizeof(entry));
      auto const type = entry >> 12;
      if (type != IMAGE_REL_BASED_ABSOLUTE && type != IMAGE_REL_BASED_DIR64)
        return false;
      foundDir64 = foundDir64 || type == IMAGE_REL_BASED_DIR64;
      entryOffset += sizeof(entry);
    }
    *offset += block.SizeOfBlock;
  }
  return foundDir64;
}

using UnaryExport = int(__cdecl*)(int);
using NullaryExport = int(__cdecl*)();

struct KnownBehavior {
  int primary{};
  int ordinal{};
  int forwarded{};
};

std::optional<KnownBehavior> ObserveEntryDll(
    std::filesystem::path const& path,
    std::filesystem::path const& dependencyDirectory) {
  auto cookie = AddDllDirectory(dependencyDirectory.c_str());
  if (!cookie) return std::nullopt;
  auto module = LoadLibraryExW(path.c_str(), nullptr,
                               LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                   LOAD_LIBRARY_SEARCH_USER_DIRS |
                                   LOAD_LIBRARY_SEARCH_SYSTEM32);
  RemoveDllDirectory(cookie);
  if (!module) return std::nullopt;
  auto primary = reinterpret_cast<UnaryExport>(GetProcAddress(module, "FixtureCompute"));
  auto ordinal = reinterpret_cast<NullaryExport>(
      GetProcAddress(module, MAKEINTRESOURCEA(2)));
  auto forwarded = reinterpret_cast<UnaryExport>(
      GetProcAddress(module, "ForwardedDependency"));
  std::optional<KnownBehavior> result;
  if (primary && ordinal && forwarded)
    result = KnownBehavior{primary(10), ordinal(), forwarded(10)};
  FreeLibrary(module);
  return result;
}

std::optional<int> ObserveNoEntryDll(std::filesystem::path const& path) {
  auto module = LoadLibraryExW(path.c_str(), nullptr,
                               LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                   LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!module) return std::nullopt;
  auto function = reinterpret_cast<UnaryExport>(GetProcAddress(module, "NoEntryValue"));
  std::optional<int> result;
  if (function) result = function(2);
  FreeLibrary(module);
  return result;
}
}

int ValidatePe64DllFixtures(std::filesystem::path const& root) {
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 |
                           LOAD_LIBRARY_SEARCH_USER_DIRS);
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  auto const originalEntry = root / L"original-entry.dll";
  auto const originalNoEntry = root / L"original-noentry.dll";
  auto const originalEntryLayout = Parse(originalEntry);
  auto const originalNoEntryLayout = Parse(originalNoEntry);
  auto const originalEntryBehavior = ObserveEntryDll(originalEntry, root);
  auto const originalNoEntryBehavior = ObserveNoEntryDll(originalNoEntry);
  expect(originalEntryLayout && originalEntryLayout->format == engine::pe::PeFormat::Pe64 &&
             originalEntryLayout->imageKind == engine::pe::PeImageKind::DynamicLibrary,
         "original PE64 DllMain fixture parses");
  expect(originalNoEntryLayout && originalNoEntryLayout->entryPoint.value == 0 &&
             !originalNoEntryLayout->sourceLoadPolicy.dynamicBase &&
             !originalNoEntryLayout->sourceLoadPolicy.hasRelocations,
         "original PE64 /NOENTRY fixture is fixed-base without relocations");
  expect(originalEntryBehavior.has_value() && originalNoEntryBehavior.has_value(),
         "original fixture exports execute before unpacking");
  if (!originalEntryLayout || !originalNoEntryLayout || !originalEntryBehavior ||
      !originalNoEntryBehavior)
    return 1;

  struct Case {
    wchar_t const* source;
    wchar_t const* outputStem;
    bool noEntry;
    bool explicitOep;
  };
  constexpr Case cases[]{{L"original-entry.dll", L"entry-explicit", false, true},
                         {L"entry-default.dll", L"entry-default", false, false},
                         {L"entry-lzma.dll", L"entry-lzma", false, false},
                         {L"entry-renamed.dll", L"entry-renamed", false, false},
                         {L"noentry-default.dll", L"noentry-default", true, false},
                         {L"noentry-lzma.dll", L"noentry-lzma", true, false}};
  auto const host = HostPath();
  for (auto const& item : cases) {
    auto const packed = root / item.source;
    auto const output = root / (std::wstring{item.outputStem} + L".dumped.dll");
    contracts::UnpackJobRequest request{};
    request.targetPath = packed;
    request.outputPath = output;
    request.timeoutMilliseconds = 60'000;
    if (item.explicitOep)
      request.entryPoint = contracts::EntryPointHint{
          contracts::EntryPointAddressKind::RelativeVirtualAddress,
          originalEntryLayout->entryPoint.value};
    auto const execution = tests::ExecuteThroughEngineHost(host, request);
    if (!execution.protocolSucceeded ||
        execution.result.outcome != contracts::JobOutcome::Completed) {
      std::wcerr << L"host failure for " << item.source << L": outcome="
                 << static_cast<unsigned>(execution.result.outcome)
                 << L" category=" << static_cast<unsigned>(execution.result.category)
                 << L" native=" << execution.result.nativeCode << L" detail=";
      std::cerr << execution.result.detailCode << '\n';
    }
    expect(execution.protocolSucceeded &&
               execution.result.outcome == contracts::JobOutcome::Completed &&
               execution.result.category == contracts::ErrorCategory::None &&
               execution.result.nativeCode == 0 && execution.result.artifact &&
               execution.result.artifact->loaderVerified,
           "packed PE64 DLL completes through the real Engine Host");
    auto const repaired = Parse(output);
    auto const& original = item.noEntry ? *originalNoEntryLayout : *originalEntryLayout;
    expect(repaired && repaired->format == engine::pe::PeFormat::Pe64 &&
               repaired->imageKind == engine::pe::PeImageKind::DynamicLibrary &&
               repaired->entryPoint.value == original.entryPoint.value,
           "repaired PE64 DLL preserves image kind and original entry point");
    if (repaired) {
      expect(repaired->sourceLoadPolicy.dynamicBase ==
                 original.sourceLoadPolicy.dynamicBase &&
                 repaired->sourceLoadPolicy.hasRelocations ==
                     original.sourceLoadPolicy.hasRelocations,
             "repaired PE64 DLL preserves source relocation and ASLR intent");
      expect(repaired->directories[IMAGE_DIRECTORY_ENTRY_EXPORT].address.value != 0,
             "repaired PE64 DLL preserves its export directory");
      if (!item.noEntry) {
        expect(repaired->directories[IMAGE_DIRECTORY_ENTRY_IMPORT].address.value != 0 &&
                   repaired->directories[IMAGE_DIRECTORY_ENTRY_IAT].address.value != 0,
               "repaired DllMain DLL contains Imports and IAT directories");
        expect(repaired->directories[IMAGE_DIRECTORY_ENTRY_TLS].address.value != 0,
               "repaired DllMain DLL preserves its TLS directory");
        expect(HasOnlyDir64Relocations(output, *repaired),
               "repaired DllMain DLL contains only DIR64 relocation entries");
      } else {
        expect(repaired->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].address.value == 0,
               "fixed /NOENTRY DLL does not gain a relocation directory");
      }
    }
    if (item.noEntry) {
      expect(ObserveNoEntryDll(output) == originalNoEntryBehavior,
             "repaired /NOENTRY DLL export behavior matches the original");
    } else {
      auto const behavior = ObserveEntryDll(output, root);
      if (!behavior || behavior->primary != originalEntryBehavior->primary ||
          behavior->ordinal != originalEntryBehavior->ordinal ||
          behavior->forwarded != originalEntryBehavior->forwarded) {
        std::wcerr << L"behavior mismatch for " << item.source << L": original="
                   << originalEntryBehavior->primary << L','
                   << originalEntryBehavior->ordinal << L','
                   << originalEntryBehavior->forwarded << L" repaired=";
        if (behavior)
          std::wcerr << behavior->primary << L',' << behavior->ordinal << L','
                     << behavior->forwarded;
        else
          std::wcerr << L"unavailable";
        std::wcerr << L'\n';
      }
      expect(behavior && behavior->primary == originalEntryBehavior->primary &&
                 behavior->ordinal == originalEntryBehavior->ordinal &&
                 behavior->forwarded == originalEntryBehavior->forwarded,
             "repaired DllMain DLL named, ordinal, and forwarded exports match");
    }
  }
  return failures == 0 ? 0 : 1;
}
