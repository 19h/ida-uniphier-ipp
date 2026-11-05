// Per-instruction effects: register dependencies and stack pointer changes.
//
// These are a supported subset, not a claim that every instruction's flags and
// system state have been modeled.

#pragma once

#include <cstdint>
#include <vector>

#include "ipp/instruction.hpp"
#include "ipp/registers.hpp"

namespace ipp
{

/// RegisterAccess::operand of an effect that no explicit operand describes.
inline constexpr uint8_t IMPLICIT_OPERAND = 0xff;

/// One range of register storage that an instruction reads or writes.
struct RegisterAccess
{
    RegisterSlice storage;
    uint8_t access;
    uint8_t operand; // operand index, or IMPLICIT_OPERAND
    bool conservative;
};

/// Mutable state dependencies of INSN. Fixed C7 bits are excluded, including
/// when covered by an aggregate CFR view; use register_known_bits() for their
/// value.
[[nodiscard]] std::vector<RegisterAccess> register_accesses(const Decoded &insn);

/// Exact supported per-instruction SP change in bytes.
///
/// A true zero also covers instructions without a modeled SP write.
/// \return false for an unknown replacement, a conditional update, or
///         overlapping load/writeback effects.
[[nodiscard]] bool stack_pointer_delta(const Decoded &insn, int64_t *delta);

} // namespace ipp
