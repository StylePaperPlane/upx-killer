#include <Windows.h>

extern "C" __declspec(dllexport) int __cdecl DependencyValue(int value) noexcept {
  return value + 7;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
