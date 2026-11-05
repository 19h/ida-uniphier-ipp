// Validating parser from ELF file bytes to ImageMetadata.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ipp/elf.hpp"

namespace ipp
{

/// Parse BYTES into OUT. All offsets and counts are treated as untrusted.
/// \return false with a reason in ERROR for a file this reader rejects; OUT is
///         then partially filled and must be discarded.
[[nodiscard]] bool parse_elf(const std::vector<uint8_t> &bytes, ImageMetadata *out,
                             std::string *error);

/// \return true if SIZE bytes starting at OFFSET lie within a buffer of BUFFER_SIZE.
[[nodiscard]] constexpr bool extent_fits(size_t buffer_size, size_t offset, size_t size)
{
    return size <= buffer_size && offset <= buffer_size - size;
}

} // namespace ipp
