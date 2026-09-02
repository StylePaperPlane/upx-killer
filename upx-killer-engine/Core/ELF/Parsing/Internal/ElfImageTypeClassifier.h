#pragma once

#include "Core/ELF/Format/ElfImage.h"
#include "Core/ELF/Parsing/ElfParser.h"

#include <optional>
#include <span>

namespace upx_killer::engine::elf::parsing::internal {

[[nodiscard]] std::optional<ElfImageType> ClassifyDynamicImage(
    std::span<std::byte const> bytes, ElfImageLayout const& layout,
    bool entryIsExecutable, ElfParseExtent extent) noexcept;

}  // namespace upx_killer::engine::elf::parsing::internal
