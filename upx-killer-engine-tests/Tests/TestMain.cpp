#include <filesystem>
#include <iostream>
#include <string_view>

int RunParserTests();
int RunDumperTests();
int RunFixerTests();
int RunHostIntegrationTests();
int RunDllLoaderCatalogTests();
int RunPe64DllOepTests();
int RunPeBackendCapabilitiesTests();
int RunPeJobContractTranslatorTests();
int RunOepDiscoveryTests();
int RunOepDiscoveryIntegrationTests();
int RunImportDiscoveryTests();
int RunUnpackCoordinatorTests();
int RunEngineHostCodecTests();
int RunLayerDependencyTests();
int RunPeUseCaseTests();
int RunSectionLayoutRebuilderTests();
int RunSemanticSectionRebuildTests();
int RunPeFileRebaserTests();
int RunNoSourceRelocationsImagePreparerTests();
int RunRelocationReconstructorTests();
int RunPe32FormatTests();
int RunPe32DllExportTests();
int RunWow64DebugSessionTests();
int RunElfCoreTests();
int RunElf32ParsingTests();
int RunElfSharedObjectTests();
int RunElfJobContractTranslatorTests();
int RunBinaryInspectionTests();
int ValidateElfTargetThroughHost(std::filesystem::path const& target,
                                 std::filesystem::path const& output);
int ValidatePe64DllFixtures(std::filesystem::path const& root);
int AnalyzeAutomaticOepTarget(std::filesystem::path const& target);
int ValidateAutomaticOepTargetThroughHost(std::filesystem::path const& target);

int wmain(int argc, wchar_t** argv) {
  if (argc == 3 && std::wstring_view{argv[1]} == L"--analyze-oep")
    return AnalyzeAutomaticOepTarget(argv[2]);
  if (argc == 3 && std::wstring_view{argv[1]} == L"--validate-host")
    return ValidateAutomaticOepTargetThroughHost(argv[2]);
  if (argc == 3 && std::wstring_view{argv[1]} == L"--validate-pe64-dll-fixtures")
    return ValidatePe64DllFixtures(argv[2]);
  if (argc == 4 && std::wstring_view{argv[1]} == L"--validate-elf-host")
    return ValidateElfTargetThroughHost(argv[2], argv[3]);

  int failures{};
  failures += RunParserTests();
  failures += RunDumperTests();
  failures += RunFixerTests();
  failures += RunHostIntegrationTests();
  failures += RunDllLoaderCatalogTests();
  failures += RunPe64DllOepTests();
  failures += RunPeBackendCapabilitiesTests();
  failures += RunPeJobContractTranslatorTests();
  failures += RunOepDiscoveryTests();
  failures += RunOepDiscoveryIntegrationTests();
  failures += RunImportDiscoveryTests();
  failures += RunUnpackCoordinatorTests();
  failures += RunEngineHostCodecTests();
  failures += RunLayerDependencyTests();
  failures += RunPeUseCaseTests();
  failures += RunSectionLayoutRebuilderTests();
  failures += RunSemanticSectionRebuildTests();
  failures += RunPeFileRebaserTests();
  failures += RunNoSourceRelocationsImagePreparerTests();
  failures += RunRelocationReconstructorTests();
  failures += RunPe32FormatTests();
  failures += RunPe32DllExportTests();
  failures += RunWow64DebugSessionTests();
  failures += RunElfCoreTests();
  failures += RunElf32ParsingTests();
  failures += RunElfSharedObjectTests();
  failures += RunElfJobContractTranslatorTests();
  failures += RunBinaryInspectionTests();
  if (failures == 0) std::cout << "All engine module tests passed.\n";
  return failures == 0 ? 0 : 1;
}
