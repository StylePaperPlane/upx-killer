#include "Infrastructure/Windows/Loading/DllLoaderCatalog.h"

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

int RunDllLoaderCatalogTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };
  auto const root = std::filesystem::temp_directory_path() /
                    L"upx-killer-loader-catalog-tests";
  std::error_code error;
  std::filesystem::create_directories(root, error);
  auto const x86Loader = root / L"loader-x86.exe";
  {
    std::ofstream output(x86Loader, std::ios::binary | std::ios::trunc);
    output.put('M');
  }
  loading::DllLoaderCatalog catalog{{{pe::PeFormat::Pe32, x86Loader}}};
  std::uint32_t nativeError{};
  auto x86 = catalog.Resolve(pe::PeFormat::Pe32, nativeError);
  expect(x86 && *x86 == x86Loader && nativeError == ERROR_SUCCESS,
         "loader catalog resolves its registered x86 loader");
  auto x64 = catalog.Resolve(pe::PeFormat::Pe64, nativeError);
  expect(!x64 && nativeError == ERROR_NOT_SUPPORTED,
         "loader catalog reports an unregistered x64 loader");

  loading::DllLoaderCatalog missing{{
      {pe::PeFormat::Pe32, root / L"missing.exe"},
  }};
  auto absent = missing.Resolve(pe::PeFormat::Pe32, nativeError);
  expect(!absent && nativeError != ERROR_SUCCESS,
         "loader catalog reports a missing registered loader");
  std::filesystem::remove_all(root, error);
  return failures;
}
