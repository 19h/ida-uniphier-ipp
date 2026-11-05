#include "processor/analyzer.hpp"

#include <cstdint>
#include <optional>

#include <ida.hpp>

#include <ua.hpp>

#include "ipp/decoder.hpp"
#include "processor/context_decoder.hpp"
#include "processor/insn_encoding.hpp"
#include "processor/instruction_table.hpp"

namespace ipp::processor
{

//--------------------------------------------------------------------
static op_dtype_t data_type_for_width(unsigned bytes)
{
    switch ( bytes )
    {
        case 1:
            return dt_byte;
        case 2:
            return dt_word;
        case 4:
            return dt_dword;
        case 8:
            return dt_qword;
        case 16:
            return dt_byte16;
        default:
            return dt_void;
    }
}

//--------------------------------------------------------------------
/// \return false for an operand kind that has no IDA representation.
static bool fill_operand(op_t *out, const ipp::Operand &operand)
{
    // op_t() clears OF_SHOW, and out_one_operand hides the operand otherwise.
    out->set_shown();
    out->dtype = data_type_for_width(operand.width);
    out->specflag1 = operand.flags;

    const uint32_t value = static_cast<uint32_t>(operand.value);
    switch ( operand.kind )
    {
        case ipp::OperandKind::RegisterRange:
            out->specflag1 |= OPERAND_IS_RANGE;
            out->specval = operand.reg_end;
            [[fallthrough]];
        case ipp::OperandKind::Register:
            out->type = o_reg;
            out->reg = operand.reg;
            return true;
        case ipp::OperandKind::Immediate:
            out->type = o_imm;
            out->value = value;
            return true;
        case ipp::OperandKind::CodeAddress:
            out->type = o_near;
            out->addr = value;
            return true;
        case ipp::OperandKind::Memory:
            out->type = operand.reg == ipp::NoRegister ? o_mem : o_displ;
            out->phrase = operand.reg;
            out->addr = operand.has_flag(ipp::PostIncrement) ? 0 : value;
            out->specval = value;
            return true;
        default:
            return false;
    }
}

//--------------------------------------------------------------------
ssize_t analyze_instruction(insn_t *insn)
{
    if ( insn == nullptr )
        return 0;
    const std::optional<ipp::Decoded> decoded = decode_at(insn->ea);
    if ( !decoded )
        return 0;
    const std::optional<uint16> itype = select_itype(*decoded);
    if ( !itype )
        return 0;

    insn->size = static_cast<uint16>(decoded->length);
    insn->itype = *itype;
    insn->auxpref = decoded->e_bit ? AUXPREF_RAW_E : 0;

    for ( unsigned i = 0; i < UA_MAXOP; ++i )
    {
        insn->ops[i] = op_t();
        insn->ops[i].n = static_cast<uint8>(i);
    }
    for ( unsigned i = 0; i < decoded->operand_count; ++i )
    {
        if ( !fill_operand(&insn->ops[i], decoded->ops[i]) )
            return 0;
    }

    op_t &predicate = insn->ops[decoded->operand_count];
    predicate.type = o_reg;
    predicate.reg = ipp::C0 + decoded->predicate;
    predicate.dtype = dt_byte;
    predicate.set_shown();
    predicate.specflag1 = OPERAND_IS_PREDICATE;
    return insn->size;
}

} // namespace ipp::processor
