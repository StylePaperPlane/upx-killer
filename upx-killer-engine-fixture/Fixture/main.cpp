#include <Windows.h>

#include <array>
#include <cstddef>

namespace {
constexpr std::size_t PayloadSize = 128 * 1024;

constexpr std::array<unsigned char, PayloadSize> MakePayload() noexcept {
  std::array<unsigned char, PayloadSize> value{};
  for (std::size_t index = 0; index < value.size(); ++index)
    value[index] = static_cast<unsigned char>("UPX-KILLER-PE32"[index % 15]);
  return value;
}

int Increment(int value) noexcept { return value + 1; }

auto const fixturePayload = MakePayload();
int fixtureValue = 41;
int* volatile relocatedDataPointer = &fixtureValue;
int (*volatile relocatedFunctionPointer)(int) = &Increment;
thread_local int relocatedTlsValue = 1;
}

int wmain() {
  auto const debuggerObserved = IsDebuggerPresent();
  auto const index = static_cast<std::size_t>(GetCurrentProcessId()) % fixturePayload.size();
  volatile auto payloadObservation = fixturePayload[index];
  auto const result = relocatedFunctionPointer(*relocatedDataPointer);
  if (debuggerObserved == static_cast<BOOL>(-1))
    return relocatedTlsValue + payloadObservation;
  return result == 42 ? 0 : 1;
}
