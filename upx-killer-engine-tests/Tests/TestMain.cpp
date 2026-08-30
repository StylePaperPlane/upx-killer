#include <filesystem>
#include <iostream>
#include <string_view>

int RunParserTests();
int RunDumperTests();
int RunFixerTests();
int RunHostIntegrationTests();
int RunDllLoaderCatalogTests();
int RunPeBackendCapabilitiesTests();
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
int AnalyzeAutomaticOepTarget(std::filesystem::path const& target);
int ValidateAutomaticOepTargetThroughHost(std::filesystem::path const& target);

int wmain(int argc, wchar_t** argv) {
  if (argc == 3 && std::wstring_view{argv[1]} == L"--analyze-oep")
    return AnalyzeAutomaticOepTarget(argv[2]);
  if (argc == 3 && std::wstring_view{argv[1]} == L"--validate-host")
    return ValidateAutomaticOepTargetThroughHost(argv[2]);

  int failures{};
  failures += RunParserTests();
  failures += RunDumperTests();
  failures += RunFixerTests();
  failures += RunHostIntegrationTests();
  failures += RunDllLoaderCatalogTests();
  failures += RunPeBackendCapabilitiesTests();
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
  if (failures == 0) std::cout << "All engine module tests passed.\n";
  return failures == 0 ? 0 : 1;
}
