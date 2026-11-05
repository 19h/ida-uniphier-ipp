// Big-endian readers shared by the decoder and the ELF parser.

#pragma once

#include <cstdint>

namespace ipp
{

[[nodiscard]] constexpr uint16_t read_be16(const uint8_t *bytes)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

[[nodiscard]] constexpr uint32_t read_be32(const uint8_t *bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 24)
        | (static_cast<uint32_t>(bytes[1]) << 16)
        | (static_cast<uint32_t>(bytes[2]) << 8)
        | static_cast<uint32_t>(bytes[3]);
}

} // namespace ipp
