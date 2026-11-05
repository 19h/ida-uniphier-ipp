// ev_out_insn and ev_out_operand: render instructions in the disassembly listing.

#pragma once

#include <ida.hpp>

#include <ua.hpp>

namespace ipp::processor
{

/// \return false for an operand type this processor does not produce.
bool output_operand(outctx_t *ctx, const op_t &operand);

void output_instruction(outctx_t *ctx);

} // namespace ipp::processor
