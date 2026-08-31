#include "Infrastructure/Linux/Storage/LinuxElfSourceReader.h"

#include <cerrno>
#include <fstream>
#include <limits>

namespace upx_killer::elf_host::storage {
engine::application::elf_preparation::ElfSourceReadResult
LinuxElfSourceReader::Read(std::filesystem::path const& path,
                           std::uint64_t maximumSize) const noexcept {
  try {
    std::error_code error;
    auto const size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > maximumSize ||
        size > std::numeric_limits<std::size_t>::max())
      return {std::nullopt, static_cast<std::uint32_t>(error.value())};
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return {std::nullopt, static_cast<std::uint32_t>(errno)};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    if (!stream) return {std::nullopt, static_cast<std::uint32_t>(errno)};
    return {std::move(bytes), 0};
  } catch (std::filesystem::filesystem_error const& error) {
    return {std::nullopt, static_cast<std::uint32_t>(error.code().value())};
  } catch (...) {
    return {std::nullopt, static_cast<std::uint32_t>(EIO)};
  }
}
}  // namespace upx_killer::elf_host::storage
