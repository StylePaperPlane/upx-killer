#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::engine::pe::rebasing
{
    struct NoSourceRelocationsImage
    {
        std::vector<std::byte> bytes;
        LoadedAddress requiredBase;
    };

    enum class NoSourceRelocationsPreparationError
    {
        None,
        InvalidInput,
        SourceRelocationsPresent,
    };

    struct NoSourceRelocationsPreparationResult
    {
        std::optional<NoSourceRelocationsImage> image;
        NoSourceRelocationsPreparationError error{
            NoSourceRelocationsPreparationError::None };

        [[nodiscard]] bool Succeeded() const noexcept
        {
            return image.has_value();
        }
    };

    class NoSourceRelocationsImagePreparer final
    {
    public:
        // This path deliberately does not synthesize or apply relocation slots.
        // It changes only loader-placement metadata (ImageBase and the two ASLR
        // flags) in a transient copy. The caller must prove the target is a
        // supported position-independent unpacking stub and must verify the
        // actual base and resolved OEP at runtime.
        [[nodiscard]] static NoSourceRelocationsPreparationResult Prepare(
            std::span<std::byte const> source,
            PeImageLayout const& layout,
            LoadedAddress requiredBase) noexcept;
    };
}
