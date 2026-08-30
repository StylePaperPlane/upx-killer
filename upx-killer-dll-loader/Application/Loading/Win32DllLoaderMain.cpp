#include <Windows.h>

#include <filesystem>

namespace {
constexpr int InvalidArguments = 2;
constexpr int DllSearchSetupFailed = 3;
constexpr int LoadFailed = 4;
constexpr int UnloadFailed = 5;
}

int wmain(int argc, wchar_t** argv) {
  if (argc != 3) return InvalidArguments;
  std::error_code error;
  auto const library = std::filesystem::weakly_canonical(argv[1], error);
  if (error || !library.is_absolute()) return InvalidArguments;
  auto const dependencyDirectory = std::filesystem::weakly_canonical(argv[2], error);
  if (error || !dependencyDirectory.is_absolute()) return InvalidArguments;

  if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS))
    return DllSearchSetupFailed;
  auto cookie = AddDllDirectory(dependencyDirectory.c_str());
  if (!cookie) return DllSearchSetupFailed;
  auto module = LoadLibraryExW(
      library.c_str(), nullptr,
      LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_USER_DIRS |
          LOAD_LIBRARY_SEARCH_SYSTEM32);
  auto const loadError = module ? ERROR_SUCCESS : GetLastError();
  RemoveDllDirectory(cookie);
  if (!module) return loadError == ERROR_SUCCESS ? LoadFailed : static_cast<int>(loadError);
  if (!FreeLibrary(module)) return UnloadFailed;
  // A DLL can create worker threads during PROCESS_ATTACH. End the isolated
  // verifier immediately after a successful detach so no worker can execute
  // code from the now-unmapped image during C runtime shutdown.
  ExitProcess(0);
}
