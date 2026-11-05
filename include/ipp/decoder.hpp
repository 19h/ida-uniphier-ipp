// UniPhier IPP decoder. Bytes in, instruction records out.
//
// Length follows the platinum V8 disassembler. A big-endian 16-bit parcel is
// one 32-bit instruction when bits 14:13 are both set, i.e. the top nibble is
// 6, 7, E, or F. Bit 15 is retained as the raw E bit. Every accepted mask
// leaves that bit clear, so matching the raw parcel equals clearing E first.
// E polarity is generation dependent / unverified for the supplied Pro5
// corpus. It must not be silently converted to a parallel-execution claim.
// US8250340's fixed 32-bit VLIW layout is not this length rule.
//
// The table is 758 InstructionDecode rules (evidence v8-<va>) followed by 26
// GCC supplemental encodings the V8 JIT does not emit (evidence gcc-supplement,
// ids gcc-758..gcc-785 without 760 and 761). V8 wins when both match. The
// halfword 0000 is gcc-758, [c6] br to itself. Direct br and brl targets are
// address plus that instruction's displacement. The context-free decoder leaves
// brl LR unresolved; resolve_far_call supplies the adjacent sethi-LR context,
// using the formula checked across the supplied corpus.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ipp/instruction.hpp"

namespace ipp
{

/// Decode the instruction at the start of BYTES.
///
/// Odd addresses produce unresolved records, preserving parcel byte accounting
/// and raw E. A recognized instruction is not returned at a forbidden address.
/// \return a record with length 0 if BYTES is null or SIZE is 0.
[[nodiscard]] Decoded decode_one(const uint8_t *bytes, size_t size, uint32_t address);

/// Check that INSN is a recognized instruction with consistent typed operands.
[[nodiscard]] bool valid_instruction(const Decoded &insn);

/// Decode a whole extent, then fold the adjacent far and absolute call sequences
/// that no known entry can interrupt. ENTRIES lists addresses known to be
/// reached by other means; destinations found in the extent are added to them.
[[nodiscard]] std::vector<Decoded> decode_linear(const uint8_t *bytes, size_t size,
                                                 uint32_t address,
                                                 const std::vector<uint32_t> &entries = {});

/// Syntactic adjacent E=0 sethi-LR/brl-LR fold, updating CALL on success and leaving
/// it unchanged otherwise, so callers may ignore the result.
///
/// The caller must exclude execution entries after the first parcel of the
/// definition through the call, including entries implied by this candidate's
/// computed destination.
bool resolve_far_call(const Decoded &previous, Decoded *call);

/// Three adjacent unconditional E=0 definitions: mov Ra,I16; sethi Ra,I16;
/// mov LR,Ra. Resolve a following E=0 jmpl LR without replacing its LR operand,
/// updating CALL on success and leaving it unchanged otherwise.
///
/// Callers must exclude entries at every interior parcel through the call,
/// including entries implied by this candidate's computed destination.
bool resolve_absolute_call(const Decoded &low, const Decoded &high, const Decoded &copy,
                           Decoded *call);

} // namespace ipp
