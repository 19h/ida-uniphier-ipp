// How decoder facts are stored in IDA's insn_t and op_t between processor events.

#pragma once

#include <cstdint>

namespace ipp::processor
{

// op_t::specflag1 holds ipp::OperandFlags in its low bits, plus these.
inline constexpr uint8_t OPERAND_IS_RANGE = 0x80;     // op_t::specval holds the last register
inline constexpr uint8_t OPERAND_IS_PREDICATE = 0x40; // the appended predicate register

// insn_t::auxpref, with no generation-specific interpretation.
inline constexpr uint32_t AUXPREF_RAW_E = 1;

} // namespace ipp::processor
