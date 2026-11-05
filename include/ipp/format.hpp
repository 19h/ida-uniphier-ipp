// Text rendering of decoded instructions.

#pragma once

#include <cstdint>
#include <string>

#include "ipp/instruction.hpp"

namespace ipp
{

/// \return a lowercase name for the classification of a record.
[[nodiscard]] const char *flow_name(Kind kind, Flow flow);

/// Render one disassembly line. RAW supplies the instruction's bytes for the
/// hex column; it may be nullptr, which leaves that column empty.
[[nodiscard]] std::string format_insn(const Decoded &insn, const uint8_t *raw);

} // namespace ipp
