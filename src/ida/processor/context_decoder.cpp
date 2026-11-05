#include "processor/context_decoder.hpp"

#include <cstddef>
#include <cstdint>

#include <ida.hpp>

#include <bytes.hpp>
#include <funcs.hpp>
#include <netnode.hpp>
#include <xref.hpp>

#include "database_nodes.hpp"

namespace ipp::processor
{

namespace
{

constexpr ea_t LAST_32BIT_ADDRESS = 0xffffffffu;
constexpr unsigned SETHI_LENGTH = 4;

/// Where the three definitions of a candidate absolute call would have to lie.
struct absolute_call_layout_t
{
    ea_t low_ea;
    unsigned low_length;
    ea_t high_ea;
    ea_t copy_ea;
    unsigned copy_length;
};

} // namespace

//--------------------------------------------------------------------
std::optional<ipp::Decoded> decode_bytes_at(ea_t ea)
{
    if ( ea > LAST_32BIT_ADDRESS || (ea & 1) != 0 )
        return std::nullopt;

    uint8 raw[4];
    if ( get_bytes(raw, 2, ea) != 2 )
        return std::nullopt;
    const size_t length = (raw[0] & 0x60) == 0x60 ? 4 : 2;
    if ( length == 4 && get_bytes(raw + 2, 2, ea + 2) != 2 )
        return std::nullopt;

    const ipp::Decoded insn = ipp::decode_one(raw, length, static_cast<uint32_t>(ea));
    if ( !ipp::valid_instruction(insn) )
        return std::nullopt;
    return insn;
}

//--------------------------------------------------------------------
/// True if execution is known to reach EA other than by falling through to it.
static bool is_known_entry(ea_t ea)
{
    netnode symbols(FUNCTION_SYMBOLS_NODE);
    if ( (symbols != BADNODE && symbols.altval_ea(ea) != 0) || get_func_start(ea) == ea )
        return true;

    xrefblk_t xref;
    for ( bool ok = xref.first_to(ea, XREF_FAR); ok; ok = xref.next_to() )
    {
        if ( xref.iscode )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------
/// True if a known entry lies at any parcel after FIRST through LAST, including
/// instruction tails. FIRST itself may be an entry.
static bool has_interior_entry(ea_t first, ea_t last)
{
    for ( uint64 parcel = uint64(first) + 2; parcel <= uint64(last); parcel += 2 )
    {
        if ( is_known_entry(ea_t(parcel)) )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------
/// True if the fold would jump into its own sequence, establishing an interior entry.
static bool targets_own_interior(const ipp::Decoded &resolved, ea_t first, ea_t last)
{
    return resolved.target > first && resolved.target <= last;
}

//--------------------------------------------------------------------
static void fold_far_call(ipp::Decoded *insn, ea_t ea)
{
    if ( ea < SETHI_LENGTH
         || insn->flow != ipp::Flow::Call
         || !insn->has_mnemonic("brl")
         || insn->operand_count != 2
         || !insn->ops[0].is_register(ipp::LR) )
    {
        return;
    }

    const ea_t sethi_ea = ea - SETHI_LENGTH;
    const flags64_t sethi_flags = get_flags(sethi_ea);
    if ( is_tail(sethi_flags) || is_data(sethi_flags) || has_interior_entry(sethi_ea, ea) )
        return;

    const std::optional<ipp::Decoded> previous = decode_bytes_at(sethi_ea);
    if ( !previous )
        return;

    ipp::Decoded resolved = *insn;
    if ( ipp::resolve_far_call(*previous, &resolved)
         && !targets_own_interior(resolved, previous->address, ea) )
    {
        *insn = resolved;
    }
}

//--------------------------------------------------------------------
/// True if an instruction of LENGTH could start at EA, given what the database says.
static bool can_hold_definition(ea_t ea, unsigned length)
{
    const flags64_t flags = get_flags(ea);
    if ( is_data(flags) || is_tail(flags) )
        return false;
    return !is_code(flags) || get_item_size(ea) == length;
}

//--------------------------------------------------------------------
/// Try one placement of the definitions before the jmpl LR at EA.
static std::optional<ipp::Decoded> resolve_absolute_layout(const ipp::Decoded &call, ea_t ea,
                                                           const absolute_call_layout_t &layout)
{
    if ( !can_hold_definition(layout.low_ea, layout.low_length)
         || !can_hold_definition(layout.high_ea, SETHI_LENGTH)
         || !can_hold_definition(layout.copy_ea, layout.copy_length) )
    {
        return std::nullopt;
    }

    const std::optional<ipp::Decoded> low = decode_bytes_at(layout.low_ea);
    const std::optional<ipp::Decoded> high = decode_bytes_at(layout.high_ea);
    const std::optional<ipp::Decoded> copy = decode_bytes_at(layout.copy_ea);
    if ( !low || !high || !copy )
        return std::nullopt;

    ipp::Decoded resolved = call;
    if ( !ipp::resolve_absolute_call(*low, *high, *copy, &resolved) )
        return std::nullopt;
    if ( has_interior_entry(layout.low_ea, ea)
         || targets_own_interior(resolved, layout.low_ea, ea) )
    {
        return std::nullopt;
    }
    return resolved;
}

//--------------------------------------------------------------------
/// Definitions can be compact or wide, so several placements are possible. Two that
/// both resolve are overlapping valid interpretations: ambiguous, so neither is used.
static void fold_absolute_call(ipp::Decoded *insn, ea_t ea)
{
    if ( insn->flow != ipp::Flow::Call
         || !insn->has_mnemonic("jmpl")
         || insn->operand_count != 1
         || !insn->ops[0].is_register(ipp::LR)
         || is_known_entry(ea) )
    {
        return;
    }

    std::optional<ipp::Decoded> found;
    for ( unsigned copy_length : {2u, 4u} )
    {
        if ( ea < copy_length + 6 )
            continue;
        const ea_t copy_ea = ea - copy_length;
        const ea_t high_ea = copy_ea - SETHI_LENGTH;
        if ( is_known_entry(copy_ea) || is_known_entry(high_ea) )
            continue;

        for ( unsigned low_length : {2u, 4u} )
        {
            if ( high_ea < low_length )
                continue;
            const absolute_call_layout_t layout = {high_ea - low_length, low_length, high_ea,
                                                   copy_ea, copy_length};
            const std::optional<ipp::Decoded> resolved = resolve_absolute_layout(*insn, ea, layout);
            if ( !resolved )
                continue;
            if ( found )
                return;
            found = resolved;
        }
    }
    if ( found )
        *insn = *found;
}

//--------------------------------------------------------------------
std::optional<ipp::Decoded> decode_at(ea_t ea)
{
    std::optional<ipp::Decoded> insn = decode_bytes_at(ea);
    if ( insn )
    {
        fold_far_call(&*insn, ea);
        fold_absolute_call(&*insn, ea);
    }
    return insn;
}

} // namespace ipp::processor
