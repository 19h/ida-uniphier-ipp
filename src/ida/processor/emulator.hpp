// ev_emu_insn: create cross-references, stack points and code flow.

#pragma once

#include <ida.hpp>

#include <ua.hpp>

namespace ipp::processor
{

/// \return 1 if the instruction was emulated, -1 otherwise.
[[nodiscard]] ssize_t emulate_instruction(const insn_t *insn);

} // namespace ipp::processor
