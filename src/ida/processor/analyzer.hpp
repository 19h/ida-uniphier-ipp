// ev_ana_insn: fill IDA's instruction record from the decoder.

#pragma once

#include <ida.hpp>

#include <ua.hpp>

namespace ipp::processor
{

/// \return the instruction length, or 0 if there is no valid instruction at INSN->ea.
[[nodiscard]] ssize_t analyze_instruction(insn_t *insn);

} // namespace ipp::processor
