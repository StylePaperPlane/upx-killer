#include "Infrastructure/Windows/WSL/Storage/WindowsElfSourceReader.h"

#include <Windows.h>

#include <fstream>
#include <limits>

namespace upx_killer::engine_host::wsl {
engine::application::elf_preparation::ElfSourceReadResult
WindowsElfSourceReader::Read(std::filesystem::path const& path,
                             std::uint64_t maximumSize) const noexcept {
  try {
    std::error_code error;
    auto const size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > maximumSize ||
        size > std::numeric_limits<std::size_t>::max())
      return {std::nullopt, error ? static_cast<std::uint32_t>(error.value())
                                 : ERROR_FILE_TOO_LARGE};
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return {std::nullopt, GetLastError()};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    if (!stream) return {std::nullopt, ERROR_READ_FAULT};
    return {std::move(bytes), 0};
  } catch (std::filesystem::filesystem_error const& error) {
    return {std::nullopt, static_cast<std::uint32_t>(error.code().value())};
  } catch (...) {
    return {std::nullopt, ERROR_UNHANDLED_EXCEPTION};
  }
}
}  // namespace upx_killer::engine_host::wsl
