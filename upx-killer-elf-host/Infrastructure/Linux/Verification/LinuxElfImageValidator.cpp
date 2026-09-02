#include "Infrastructure/Linux/Verification/LinuxElfImageValidator.h"

#include "Core/ELF/Parsing/ElfParser.h"
#include "Core/ELF/Validation/ElfImageValidator.h"

#include <cerrno>
#include <fstream>
#include <vector>

namespace upx_killer::elf_host::verification {
engine::application::artifacts::ArtifactValidationResult
LinuxElfImageValidator::Validate(
    engine::application::artifacts::ArtifactValidationRequest const& request)
    const noexcept {
  try {
    std::error_code error;
    auto const size = std::filesystem::file_size(request.imagePath, error);
    if (error || size == 0)
      return {false, false, false, false, 0,
              static_cast<std::uint32_t>(error.value())};
    std::ifstream stream(request.imagePath, std::ios::binary);
    if (!stream)
      return {false, false, false, false, 0,
              static_cast<std::uint32_t>(errno)};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    if (!stream)
      return {false, false, false, false, 0,
              static_cast<std::uint32_t>(errno)};
    auto parsed = engine::elf::ElfParser::Parse(bytes);
    auto validation = engine::elf::ElfImageValidator::Validate(bytes);
    if (!parsed.layout || !validation.valid)
      return {false, false, false, false, 0,
              static_cast<std::uint32_t>(ENOEXEC)};

    auto loaded = loaderVerifier_.Verify(
        request.imagePath, *parsed.layout, request.dependencyDirectory,
        request.timeoutMilliseconds);
    return {true, true, loaded.accepted, false, 0, loaded.nativeCode};
  } catch (...) {
    return {false, false, false, false, 0,
            static_cast<std::uint32_t>(EIO)};
  }
}
}  // namespace upx_killer::elf_host::verification
