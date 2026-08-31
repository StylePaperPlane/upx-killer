#include <array>
#include <cstddef>

namespace {
constexpr std::size_t PayloadSize = 64 * 1024;

constexpr std::array<unsigned char, PayloadSize> MakePayload() noexcept {
  std::array<unsigned char, PayloadSize> value{};
  for (std::size_t index = 0; index < value.size(); ++index)
    value[index] = static_cast<unsigned char>("UPX-KILLER-NOENTRY"[index % 18]);
  return value;
}

auto const fixturePayload = MakePayload();
}

extern "C" __declspec(dllexport) int __cdecl NoEntryValue(int value) noexcept {
  return value + fixturePayload[static_cast<std::size_t>(value) % fixturePayload.size()];
}
