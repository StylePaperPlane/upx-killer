#pragma once

#include "Core/PE/Format/PeFormat.h"
#include "Core/Unpacking/UnpackTypes.h"

#include <Windows.h>

#include <cstdint>
#include <optional>

namespace upx_killer::engine::debugging::thread_context {
enum class ThreadContextError {
  None,
  PlatformCallFailed,
  MachineMismatch,
  Wow64Unavailable,
};

struct ThreadControlContext {
  std::uint64_t instructionPointer{};
  std::uint64_t stackPointer{};
};

// Represents the platform-neutral arguments supplied to a DLL entry point.
// The controller owns the PE32 stack and PE64 register calling-convention
// details so the debug state machine does not branch on processor width.
struct DllEntryInvocation {
  std::uint64_t module{};
  std::uint32_t reason{};
  std::uint64_t reserved{};
};

class ThreadContextController final {
 public:
  ~ThreadContextController();
  ThreadContextController(ThreadContextController const&) = delete;
  ThreadContextController& operator=(ThreadContextController const&) = delete;
  ThreadContextController(ThreadContextController&& other) noexcept;
  ThreadContextController& operator=(ThreadContextController&& other) noexcept;

  [[nodiscard]] static ThreadContextError ValidateProcess(
      HANDLE process, pe::PeFormat expectedFormat,
      std::uint32_t& nativeError) noexcept;
  [[nodiscard]] static std::optional<ThreadContextController> Open(
      DWORD threadId, pe::PeFormat format, std::uint32_t& nativeError) noexcept;

  [[nodiscard]] ThreadControlContext const& Context() const noexcept;
  [[nodiscard]] std::optional<DllEntryInvocation> ReadDllEntryInvocation(
      HANDLE process, std::uint32_t& nativeError) const noexcept;
  [[nodiscard]] bool SetInstructionPointer(std::uint64_t value,
                                           std::uint32_t& nativeError) noexcept;
  [[nodiscard]] bool Commit(std::uint32_t& nativeError) noexcept;

 private:
  ThreadContextController(HANDLE thread, pe::PeFormat format) noexcept;
  void Reset() noexcept;

  HANDLE m_thread{};
  pe::PeFormat m_format{pe::PeFormat::Pe64};
  ThreadControlContext m_control{};
  CONTEXT m_native{};
  WOW64_CONTEXT m_wow64{};
};
}
