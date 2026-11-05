// Small, allocation-friendly number formatting for the hot decode path.

#pragma once

#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>

namespace ipp
{

/// Append VALUE to OUT in decimal.
template<class T>
void append_decimal(std::string *out, T value)
{
    char digits[24];
    const std::to_chars_result result = std::to_chars(digits, digits + sizeof(digits), value);
    out->append(digits, result.ptr);
}

/// Append the low DIGITS nibbles of VALUE to OUT in lowercase hex.
inline void append_hex(std::string *out, uint32_t value, int digits)
{
    constexpr std::string_view HEX_DIGITS = "0123456789abcdef";
    for ( int shift = (digits - 1) * 4; shift >= 0; shift -= 4 )
        out->push_back(HEX_DIGITS[(value >> shift) & 0xf]);
}

} // namespace ipp
