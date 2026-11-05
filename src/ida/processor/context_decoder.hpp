// Decoding from the database: the core decoder plus what the database knows.

#pragma once

#include <optional>

#include <ida.hpp>

#include "ipp/decoder.hpp"

namespace ipp::processor
{

/// Decode the instruction at EA from its bytes alone. Odd or unreadable addresses
/// and anything but a valid instruction give no result.
[[nodiscard]] std::optional<ipp::Decoded> decode_bytes_at(ea_t ea);

/// Decode the instruction at EA, resolving far and absolute call sequences that end
/// there. Recognizes them even during cold analysis. Explicit data, an established
/// instruction tail, or a known entry inside a sequence prevents the fold.
[[nodiscard]] std::optional<ipp::Decoded> decode_at(ea_t ea);

} // namespace ipp::processor
