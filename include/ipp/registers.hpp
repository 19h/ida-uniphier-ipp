// UniPhier IPP register file: numbering, names, widths and storage aliases.

#pragma once

#include <cstdint>

namespace ipp
{

// Register numbers are stored in IDA databases created by this module, so
// existing values must not change. Append new registers before RegisterCount.
enum Register : uint16_t
{
    // General purpose. R30 and R31 are also spelled GP and SP.
    R0 = 0,
    GP = 30,
    SP = 31,

    // Control flow.
    LR = 32,
    SVR,
    TAR,
    PC,

    // Condition flags and the CFR views that contain them.
    C0,
    C7 = C0 + 7,
    CFR,
    CFR0,
    CFR1,
    CFR2,
    CFR3,

    // Accumulators and their halves.
    M0,
    M1,
    MH0,
    MH1,
    ML0,
    ML1,

    // Floating point. Index slots preserve the disassembler's spellings.
    // register_slice() supplies inferred FS/FD/XD aliases over indices 0..31.
    // The extra FD/XD slots are reserved capacity, not claimed physical
    // registers.
    FS0,
    FS31 = FS0 + 31,
    FD0,
    FD63 = FD0 + 63,
    XD0,
    XD63 = XD0 + 63,

    // System state.
    FPCR,
    PSR,
    IPSR,
    IPC,
    SAR,
    CS,
    DS,

    // Named CFR fields. Their canonical storage is CFR.
    VC0,
    VC1,
    VC2,
    VC3,
    OVS,
    CAS,
    BPO,
    ALN,

    // Exception return state.
    EPC,
    EPSR,

    RegisterCount,
    NoRegister = 0xffff,
};

/// The bits of a storage register that a named register occupies.
struct RegisterSlice
{
    uint16_t reg;
    uint8_t bit_offset;
    uint8_t bit_count;
};

/// Bits of a register whose value does not depend on mutable machine state.
struct RegisterKnownBits
{
    uint64_t mask;  // bits known independently of mutable machine state
    uint64_t value; // value & mask, in the queried register's own bit numbering
};

/// \return the canonical name of REG, or nullptr if it is out of range.
[[nodiscard]] const char *register_name(uint16_t reg);

/// Case-insensitive lookup, also accepting the SP and GP aliases.
/// \return the register number for NAME, or -1 if there is none.
[[nodiscard]] int register_id(const char *name);

/// \return the width of REG in bytes, or 0 if it is out of range.
[[nodiscard]] unsigned register_width(uint16_t reg);

/// Resolve REG to its canonical storage. CFR fields and accumulator halves are
/// documented; the FS/FD/XD aliases over indices 0..31 are inferred.
[[nodiscard]] RegisterSlice register_slice(uint16_t reg);

/// Constant bits of REG. C7 always reads one, including through aggregate CFR
/// views; register_accesses() excludes that bit from mutable state.
[[nodiscard]] RegisterKnownBits register_known_bits(uint16_t reg);

} // namespace ipp
