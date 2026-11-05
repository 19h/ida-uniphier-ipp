// Register names, widths and storage aliases.

#include "ipp/registers.hpp"

#include <array>
#include <cctype>
#include <string>

namespace ipp
{

namespace
{
using register_names_t = std::array<std::string, RegisterCount>;
} // namespace

//--------------------------------------------------------------------
static void name_bank(register_names_t *names, unsigned base, unsigned count, const char *prefix)
{
    for ( unsigned i = 0; i < count; ++i )
        (*names)[base + i] = prefix + std::to_string(i);
}

//--------------------------------------------------------------------
static register_names_t build_register_names()
{
    register_names_t names;

    name_bank(&names, R0, 32, "R");
    name_bank(&names, C0, 8, "C");
    name_bank(&names, CFR0, 4, "CFR");
    name_bank(&names, M0, 2, "M");
    name_bank(&names, MH0, 2, "MH");
    name_bank(&names, ML0, 2, "ML");
    name_bank(&names, FS0, 32, "FS");
    name_bank(&names, FD0, 64, "FD");
    name_bank(&names, XD0, 64, "XD");
    name_bank(&names, VC0, 4, "VC");

    names[LR] = "LR";
    names[SVR] = "SVR";
    names[TAR] = "TAR";
    names[PC] = "PC";
    names[CFR] = "CFR";
    names[FPCR] = "FPCR";
    names[PSR] = "PSR";
    names[IPSR] = "IPSR";
    names[IPC] = "IPC";
    names[SAR] = "SAR";
    names[CS] = "CS";
    names[DS] = "DS";
    names[OVS] = "OVS";
    names[CAS] = "CAS";
    names[BPO] = "BPO";
    names[ALN] = "ALN";
    names[EPC] = "EPC";
    names[EPSR] = "EPSR";
    return names;
}

//--------------------------------------------------------------------
static const register_names_t &register_names()
{
    static const register_names_t names = build_register_names();
    return names;
}

//--------------------------------------------------------------------
const char *register_name(uint16_t reg)
{
    return reg < RegisterCount ? register_names()[reg].c_str() : nullptr;
}

//--------------------------------------------------------------------
int register_id(const char *name)
{
    if ( name == nullptr )
        return -1;

    std::string key = name;
    for ( char &c : key )
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    if ( key == "SP" )
        return SP;
    if ( key == "GP" )
        return GP;

    const register_names_t &names = register_names();
    for ( unsigned i = 0; i < RegisterCount; ++i )
    {
        if ( names[i] == key )
            return static_cast<int>(i);
    }
    return -1;
}

//--------------------------------------------------------------------
unsigned register_width(uint16_t reg)
{
    if ( reg >= RegisterCount )
        return 0;
    if ( (reg >= C0 && reg <= C7) || (reg >= CFR0 && reg <= CFR3) || (reg >= VC0 && reg <= ALN) )
        return 1;
    if ( reg == SVR )
        return 2;
    if ( (reg >= M0 && reg <= M1) || (reg >= FD0 && reg <= XD63) )
        return 8;
    return 4;
}

//--------------------------------------------------------------------
RegisterSlice register_slice(uint16_t reg)
{
    // CFR fields: US20040078549A1 Fig.12, 386-389, 411-414.
    if ( reg >= C0 && reg <= C7 )
        return {CFR, static_cast<uint8_t>(reg - C0), 1};
    if ( reg >= CFR0 && reg <= CFR3 )
        return {CFR, static_cast<uint8_t>((CFR3 - reg) * 8), 8};
    if ( reg >= VC0 && reg <= VC3 )
        return {CFR, static_cast<uint8_t>(16 + reg - VC0), 1};
    if ( reg == CAS )
        return {CFR, 8, 1};
    if ( reg == OVS )
        return {CFR, 9, 1};
    if ( reg == BPO )
        return {CFR, 24, 5};
    if ( reg == ALN )
        return {CFR, 30, 2};

    // Accumulator layout: Fig.13.
    if ( reg >= MH0 && reg <= MH1 )
        return {static_cast<uint16_t>(M0 + reg - MH0), 32, 32};
    if ( reg >= ML0 && reg <= ML1 )
        return {static_cast<uint16_t>(M0 + reg - ML0), 0, 32};

    // FP aliases are inferred from supplied libm fmax/fmin and source-aligned
    // atan/pzero dataflow, plus corpus transfers. FD's low index bit selects
    // XD's upper bank: FD1 <-> XD16, FD3 <-> XD17, etc. Uniform five-bit
    // permutation is an explicit inference, not a vendor physical register map.
    // Reserved FD/XD indices >=32 stay independent.
    if ( reg >= FS0 && reg <= FS31 )
    {
        const unsigned index = reg - FS0;
        const uint8_t bit_offset = (index & 1) != 0 ? 0 : 32;
        return {static_cast<uint16_t>(XD0 + index / 2), bit_offset, 32};
    }
    if ( reg >= FD0 && reg < FD0 + 32 )
    {
        const unsigned index = reg - FD0;
        return {static_cast<uint16_t>(XD0 + (index >> 1) + ((index & 1) << 4)), 0, 64};
    }

    return {reg, 0, static_cast<uint8_t>(register_width(reg) * 8)};
}

//--------------------------------------------------------------------
RegisterKnownBits register_known_bits(uint16_t reg)
{
    // US20040078549A1 paragraph 0823: C7 always reads one. Preserve the existing
    // public register spelling and CFR alias while exposing its constant value
    // rather than a fictitious mutable-state dependency.
    constexpr unsigned C7_BIT = 7;
    const RegisterSlice slice = register_slice(reg);
    const bool covers_c7 = slice.reg == CFR
        && slice.bit_offset <= C7_BIT
        && static_cast<unsigned>(slice.bit_offset) + slice.bit_count > C7_BIT;
    if ( !covers_c7 )
        return {0, 0};

    const uint64_t bit = uint64_t(1) << (C7_BIT - slice.bit_offset);
    return {bit, bit};
}

} // namespace ipp
