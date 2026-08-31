#include <Windows.h>

#include <array>
#include <cstddef>

extern "C" __declspec(dllimport) int __cdecl DependencyValue(int value) noexcept;

namespace {
constexpr std::size_t PayloadSize = 128 * 1024;

constexpr std::array<unsigned char, PayloadSize> MakePayload() noexcept {
  std::array<unsigned char, PayloadSize> value{};
  for (std::size_t index = 0; index < value.size(); ++index)
    value[index] = static_cast<unsigned char>("UPX-KILLER-PE64-DLL"[index % 19]);
  return value;
}

auto const fixturePayload = MakePayload();
int fixtureState = 1;
int* volatile relocatedStatePointer = &fixtureState;
__declspec(thread) int fixtureTlsValue = 3;
}

extern "C" __declspec(dllexport) int __cdecl FixtureCompute(int value) noexcept {
  auto const index = static_cast<std::size_t>(value) % fixturePayload.size();
  volatile auto observation = fixturePayload[index];
  (void)observation;
  return DependencyValue(value) + *relocatedStatePointer + fixtureTlsValue;
}

extern "C" __declspec(dllexport) int __cdecl FixtureOrdinalValue() noexcept {
  return 64;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) fixtureState = 2;
  return TRUE;
}
