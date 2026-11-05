// Constant stack pointer changes, used by the corpus checks and the IDA adapter.

#include "ipp/decoder.hpp"
#include "ipp/semantics.hpp"

namespace ipp
{

//--------------------------------------------------------------------
/// Only arithmetic with SP as the sole destination and input has an established
/// constant delta. A range containing SP is a replacement.
static bool constant_sp_arithmetic(const Decoded &insn, int64_t *delta)
{
    if ( !insn.ops[0].is_register(SP) )
        return false;

    if ( insn.operand_count == 2 && insn.ops[1].kind == OperandKind::Immediate )
    {
        const int32_t amount = insn.ops[1].value;
        if ( insn.has_mnemonic("add") )
        {
            *delta = amount;
            return true;
        }
        if ( insn.has_mnemonic("sub") )
        {
            *delta = -static_cast<int64_t>(amount);
            return true;
        }
    }

    if ( insn.operand_count == 3
         && insn.ops[1].is_register(SP)
         && insn.ops[2].kind == OperandKind::Immediate
         && (insn.has_mnemonic("add") || insn.has_mnemonic("addu")) )
    {
        *delta = insn.ops[2].value;
        return true;
    }
    return false;
}

//--------------------------------------------------------------------
bool stack_pointer_delta(const Decoded &insn, int64_t *delta)
{
    if ( delta == nullptr || !valid_instruction(insn) )
        return false;
    *delta = 0;

    bool replaced = false;
    unsigned updates = 0;
    int32_t increment = 0;
    for ( unsigned i = 0; i < insn.operand_count; ++i )
    {
        const Operand &operand = insn.ops[i];
        if ( operand.writes() && (operand.is_register(SP) || operand.range_covers(SP)) )
            replaced = true;
        if ( operand.reg == SP && operand.updates_base() )
        {
            ++updates;
            increment = operand.value;
        }
    }

    if ( !replaced && updates == 0 )
        return true;
    if ( insn.predicate != PREDICATE_ALWAYS || updates > 1 || (replaced && updates != 0) )
        return false;
    if ( replaced )
        return constant_sp_arithmetic(insn, delta);

    *delta = increment;
    return true;
}

} // namespace ipp
