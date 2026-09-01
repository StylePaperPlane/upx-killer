#include "Infrastructure/Windows/Debugging/ThreadContext/ThreadContextController.h"

#include <array>
#include <utility>

namespace {
using IsWow64Process2Function = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
using Wow64GetThreadContextFunction = BOOL(WINAPI*)(HANDLE, PWOW64_CONTEXT);
using Wow64SetThreadContextFunction = BOOL(WINAPI*)(HANDLE, WOW64_CONTEXT const*);

struct Wow64Functions final {
  IsWow64Process2Function isWow64Process2{};
  Wow64GetThreadContextFunction getThreadContext{};
  Wow64SetThreadContextFunction setThreadContext{};
};

Wow64Functions ResolveWow64Functions() noexcept {
  auto const kernel32 = GetModuleHandleW(L"kernel32.dll");
  if (!kernel32) return {};
  return {
      reinterpret_cast<IsWow64Process2Function>(
          GetProcAddress(kernel32, "IsWow64Process2")),
      reinterpret_cast<Wow64GetThreadContextFunction>(
          GetProcAddress(kernel32, "Wow64GetThreadContext")),
      reinterpret_cast<Wow64SetThreadContextFunction>(
          GetProcAddress(kernel32, "Wow64SetThreadContext")),
  };
}

Wow64Functions const& Functions() noexcept {
  static auto const functions = ResolveWow64Functions();
  return functions;
}
}

namespace upx_killer::engine::debugging::thread_context {
ThreadContextController::ThreadContextController(HANDLE thread, pe::PeFormat format) noexcept
    : m_thread(thread), m_format(format) {}

ThreadContextController::~ThreadContextController() { Reset(); }

ThreadContextController::ThreadContextController(ThreadContextController&& other) noexcept
    : m_thread(std::exchange(other.m_thread, nullptr)),
      m_format(other.m_format),
      m_control(other.m_control),
      m_native(other.m_native),
      m_wow64(other.m_wow64) {}

ThreadContextController& ThreadContextController::operator=(
    ThreadContextController&& other) noexcept {
  if (this != &other) {
    Reset();
    m_thread = std::exchange(other.m_thread, nullptr);
    m_format = other.m_format;
    m_control = other.m_control;
    m_native = other.m_native;
    m_wow64 = other.m_wow64;
  }
  return *this;
}

ThreadContextError ThreadContextController::ValidateProcess(
    HANDLE process, pe::PeFormat expectedFormat,
    std::uint32_t& nativeError) noexcept {
  nativeError = ERROR_SUCCESS;
  auto const& functions = Functions();
  if (functions.isWow64Process2) {
    USHORT processMachine{};
    USHORT nativeMachine{};
    if (!functions.isWow64Process2(process, &processMachine, &nativeMachine)) {
      nativeError = GetLastError();
      return ThreadContextError::PlatformCallFailed;
    }
    auto const isPe32 = processMachine == IMAGE_FILE_MACHINE_I386;
    auto const isPe64 =
        processMachine == IMAGE_FILE_MACHINE_UNKNOWN && nativeMachine == IMAGE_FILE_MACHINE_AMD64;
    if ((expectedFormat == pe::PeFormat::Pe32 && !isPe32) ||
        (expectedFormat == pe::PeFormat::Pe64 && !isPe64)) {
      nativeError = ERROR_BAD_EXE_FORMAT;
      return ThreadContextError::MachineMismatch;
    }
  } else {
    BOOL isWow64{};
    if (!IsWow64Process(process, &isWow64)) {
      nativeError = GetLastError();
      return ThreadContextError::PlatformCallFailed;
    }
    if ((expectedFormat == pe::PeFormat::Pe32) != (isWow64 != FALSE)) {
      nativeError = ERROR_BAD_EXE_FORMAT;
      return ThreadContextError::MachineMismatch;
    }
  }

  if (expectedFormat == pe::PeFormat::Pe32 &&
      (!functions.getThreadContext || !functions.setThreadContext)) {
    nativeError = ERROR_CALL_NOT_IMPLEMENTED;
    return ThreadContextError::Wow64Unavailable;
  }
  return ThreadContextError::None;
}

std::optional<ThreadContextController> ThreadContextController::Open(
    DWORD threadId, pe::PeFormat format, std::uint32_t& nativeError) noexcept {
  auto const thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
  if (!thread) {
    nativeError = GetLastError();
    return std::nullopt;
  }
  ThreadContextController controller{thread, format};
  if (format == pe::PeFormat::Pe32) {
    auto const& functions = Functions();
    if (!functions.getThreadContext) {
      nativeError = ERROR_CALL_NOT_IMPLEMENTED;
      return std::nullopt;
    }
    controller.m_wow64.ContextFlags = WOW64_CONTEXT_CONTROL;
    if (!functions.getThreadContext(thread, &controller.m_wow64)) {
      nativeError = GetLastError();
      return std::nullopt;
    }
    controller.m_control = {controller.m_wow64.Eip, controller.m_wow64.Esp};
  } else {
    controller.m_native.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(thread, &controller.m_native)) {
      nativeError = GetLastError();
      return std::nullopt;
    }
    controller.m_control = {controller.m_native.Rip, controller.m_native.Rsp};
  }
  return controller;
}

ThreadControlContext const& ThreadContextController::Context() const noexcept { return m_control; }

std::optional<DllEntryInvocation> ThreadContextController::ReadDllEntryInvocation(
    HANDLE process, std::uint32_t& nativeError) const noexcept {
  nativeError = ERROR_SUCCESS;
  if (!process) {
    nativeError = ERROR_INVALID_HANDLE;
    return std::nullopt;
  }

  if (m_format == pe::PeFormat::Pe64) {
    return DllEntryInvocation{m_native.Rcx, static_cast<std::uint32_t>(m_native.Rdx),
                              m_native.R8};
  }

  // stdcall PE32 DLL entry arguments follow the return address on the stack.
  std::array<std::uint32_t, 3> arguments{};
  SIZE_T read{};
  auto const address = static_cast<std::uint64_t>(m_wow64.Esp) + sizeof(std::uint32_t);
  if (!ReadProcessMemory(process, reinterpret_cast<void const*>(address), arguments.data(),
                         sizeof(arguments), &read) ||
      read != sizeof(arguments)) {
    nativeError = GetLastError();
    if (nativeError == ERROR_SUCCESS) nativeError = ERROR_PARTIAL_COPY;
    return std::nullopt;
  }
  return DllEntryInvocation{arguments[0], arguments[1], arguments[2]};
}

bool ThreadContextController::SetInstructionPointer(std::uint64_t value,
                                                    std::uint32_t& nativeError) noexcept {
  if (m_format == pe::PeFormat::Pe32) {
    if (value > UINT32_MAX) {
      nativeError = ERROR_INVALID_ADDRESS;
      return false;
    }
    m_wow64.Eip = static_cast<DWORD>(value);
  } else {
    m_native.Rip = value;
  }
  m_control.instructionPointer = value;
  return true;
}

bool ThreadContextController::Commit(std::uint32_t& nativeError) noexcept {
  auto const succeeded =
      m_format == pe::PeFormat::Pe32
          ? Functions().setThreadContext &&
                Functions().setThreadContext(m_thread, &m_wow64) != FALSE
          : SetThreadContext(m_thread, &m_native) != FALSE;
  if (!succeeded) nativeError = GetLastError();
  return succeeded;
}

void ThreadContextController::Reset() noexcept {
  if (m_thread) CloseHandle(m_thread);
  m_thread = nullptr;
}
}
