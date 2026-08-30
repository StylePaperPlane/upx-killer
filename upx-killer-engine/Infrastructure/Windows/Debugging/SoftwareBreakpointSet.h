#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace upx_killer::engine::debugging {
class SoftwareBreakpointSet final {
 public:
  explicit SoftwareBreakpointSet(HANDLE process) noexcept : process_(process) {}

  ~SoftwareBreakpointSet();
  SoftwareBreakpointSet(SoftwareBreakpointSet const&) = delete;
  SoftwareBreakpointSet& operator=(SoftwareBreakpointSet const&) = delete;

  [[nodiscard]] bool Install(std::uint64_t address, std::uint32_t id,
                             std::uint32_t& nativeError) noexcept;
  [[nodiscard]] std::optional<std::uint32_t> Find(std::uint64_t address) const noexcept;
  [[nodiscard]] bool Restore(std::uint64_t address, std::uint32_t& nativeError) noexcept;

  [[nodiscard]] std::size_t Count() const noexcept { return breakpoints_.size(); }

 private:
  struct Breakpoint {
    std::uint64_t address{};
    std::uint32_t id{};
    std::byte original{};
  };

  HANDLE process_{};
  std::vector<Breakpoint> breakpoints_;
};
}
