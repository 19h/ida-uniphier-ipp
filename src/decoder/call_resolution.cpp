// Folding of multi-instruction call sequences into a known call target.

#include <string>

#include "decoder/operand_text.hpp"
#include "decoder/text.hpp"
#include "ipp/decoder.hpp"

namespace ipp
{

namespace
{
constexpr uint64_t ADDRESS_SPACE_END = uint64_t(1) << 32;
} // namespace

//--------------------------------------------------------------------
static bool is_adjacent(const Decoded &first, const Decoded &second)
{
    return first.end_address() == second.address;
}

//--------------------------------------------------------------------
static bool is_immediate(const Operand &operand)
{
    return operand.kind == OperandKind::Immediate;
}

//--------------------------------------------------------------------
/// sethi LR,I16
static bool is_sethi_lr(const Decoded &insn)
{
    return insn.has_mnemonic("sethi")
        && insn.length == 4
        && insn.operand_count == 2
        && insn.ops[0].reg == LR
        && is_immediate(insn.ops[1]);
}

//--------------------------------------------------------------------
/// brl LR,I16
static bool is_brl_lr(const Decoded &insn)
{
    return insn.has_mnemonic("brl")
        && insn.operand_count == 2
        && insn.ops[0].reg == LR
        && is_immediate(insn.ops[1]);
}

//--------------------------------------------------------------------
bool resolve_far_call(const Decoded &previous, Decoded *call)
{
    if ( call == nullptr || !valid_instruction(previous) || !valid_instruction(*call) )
        return false;
    if ( !is_adjacent(previous, *call) || call->end_address() > ADDRESS_SPACE_END )
        return false;
    if ( previous.e_bit || call->e_bit || !is_sethi_lr(previous) || !is_brl_lr(*call) )
        return false;

    // An unconditional definition holds for any call; a conditional one only
    // for a call under the same predicate.
    if ( previous.predicate != PREDICATE_ALWAYS && previous.predicate != call->predicate )
        return false;

    const uint32_t high_half = static_cast<uint32_t>(previous.ops[1].value) << 16;
    const uint32_t low_half = static_cast<uint32_t>(call->ops[1].value) & 0xffff;
    call->has_target = true;
    call->target = call->address + (high_half | low_half);
    call->ops[1].kind = OperandKind::CodeAddress;
    call->ops[1].value = static_cast<int32_t>(call->target);

    std::string text = "LR,0x";
    append_hex(&text, call->target, 8);
    text += ", c";
    append_decimal(&text, call->predicate);
    set_operand_text(call, text);
    return true;
}

//--------------------------------------------------------------------
/// An unconditional E=0 instruction with two operands and no control flow.
static bool is_plain_definition(const Decoded &insn)
{
    return valid_instruction(insn)
        && !insn.e_bit
        && insn.predicate == PREDICATE_ALWAYS
        && insn.flow == Flow::Sequential
        && insn.operand_count == 2;
}

//--------------------------------------------------------------------
/// E=0 jmpl LR. Its predicate is free: LR holds the same value either way.
static bool is_indirect_call_through_lr(const Decoded &insn)
{
    return valid_instruction(insn)
        && !insn.e_bit
        && insn.flow == Flow::Call
        && insn.has_mnemonic("jmpl")
        && insn.operand_count == 1
        && insn.ops[0].is_register(LR);
}

//--------------------------------------------------------------------
/// mov Ra,I16, for a general register Ra and a signed 16-bit value.
static bool is_low_half_definition(const Decoded &insn)
{
    const Operand &destination = insn.ops[0];
    const Operand &source = insn.ops[1];
    return insn.has_mnemonic("mov")
        && destination.kind == OperandKind::Register
        && destination.reg < LR
        && destination.width == 4
        && destination.writes()
        && is_immediate(source)
        && source.value >= -32768
        && source.value <= 32767;
}

//--------------------------------------------------------------------
/// sethi Ra,I16, for an unsigned 16-bit value.
static bool is_high_half_definition(const Decoded &insn, uint16_t reg)
{
    const Operand &destination = insn.ops[0];
    const Operand &source = insn.ops[1];
    return insn.has_mnemonic("sethi")
        && destination.is_register(reg)
        && destination.width == 4
        && destination.writes()
        && is_immediate(source)
        && source.value >= 0
        && source.value <= 65535;
}

//--------------------------------------------------------------------
/// mov LR,Ra
static bool is_copy_to_lr(const Decoded &insn, uint16_t reg)
{
    const Operand &destination = insn.ops[0];
    const Operand &source = insn.ops[1];
    return insn.has_mnemonic("mov")
        && destination.is_register(LR)
        && destination.writes()
        && source.is_register(reg)
        && source.width == 4
        && source.reads();
}

//--------------------------------------------------------------------
bool resolve_absolute_call(const Decoded &low, const Decoded &high, const Decoded &copy,
                           Decoded *call)
{
    if ( call == nullptr )
        return false;
    if ( !is_plain_definition(low) || !is_plain_definition(high) || !is_plain_definition(copy) )
        return false;
    if ( !is_indirect_call_through_lr(*call) )
        return false;
    if ( !is_adjacent(low, high) || !is_adjacent(high, copy) || !is_adjacent(copy, *call) )
        return false;
    if ( call->end_address() > ADDRESS_SPACE_END )
        return false;

    const uint16_t reg = low.ops[0].reg;
    if ( !is_low_half_definition(low)
         || !is_high_half_definition(high, reg)
         || !is_copy_to_lr(copy, reg) )
    {
        return false;
    }

    const uint32_t high_half = static_cast<uint32_t>(high.ops[1].value) << 16;
    const uint32_t low_half = static_cast<uint32_t>(low.ops[1].value) & 0xffff;
    call->has_target = true;
    call->target = high_half | low_half;
    return true;
}

} // namespace ipp
