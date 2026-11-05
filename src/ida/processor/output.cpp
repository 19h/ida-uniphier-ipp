#include "processor/output.hpp"

#include <optional>

#include <ida.hpp>

#include <lines.hpp>
#include <ua.hpp>

#include "ipp/decoder.hpp"
#include "processor/context_decoder.hpp"
#include "processor/insn_encoding.hpp"

namespace ipp::processor
{

//--------------------------------------------------------------------
/// Print a register, using the SP or GP alias if the encoding spelled it that way.
static void output_register(outctx_t *ctx, unsigned reg, unsigned flags)
{
    if ( reg == ipp::SP && (flags & ipp::SpAlias) != 0 )
    {
        ctx->out_register("SP");
    }
    else if ( reg == ipp::GP && (flags & ipp::GpAlias) != 0 )
    {
        ctx->out_register("GP");
    }
    else
    {
        const char *name = ipp::register_name(static_cast<uint16_t>(reg));
        ctx->out_register(name != nullptr ? name : "<invalid-register>");
    }
}

//--------------------------------------------------------------------
static void output_register_operand(outctx_t *ctx, const op_t &operand)
{
    if ( (operand.specflag1 & OPERAND_IS_PREDICATE) != 0 )
    {
        char name[8];
        qsnprintf(name, sizeof(name), "c%u", static_cast<unsigned>(operand.reg - ipp::C0));
        ctx->out_register(name);
        return;
    }

    output_register(ctx, operand.reg, operand.specflag1);
    if ( (operand.specflag1 & OPERAND_IS_RANGE) != 0 )
    {
        ctx->out_symbol(':');
        output_register(ctx, static_cast<unsigned>(operand.specval), 0);
    }
}

//--------------------------------------------------------------------
/// Print (base+)step, (base,displacement) or (address).
static void output_memory_operand(outctx_t *ctx, const op_t &operand)
{
    const bool has_base = operand.type == o_displ;

    ctx->out_symbol('(');
    if ( has_base )
        output_register(ctx, operand.phrase, operand.specflag1);

    if ( (operand.specflag1 & ipp::PostIncrement) != 0 )
    {
        ctx->out_symbol('+');
        ctx->out_symbol(')');
        op_t step = operand;
        step.type = o_imm;
        step.value = operand.specval;
        ctx->out_value(step, OOFW_32 | OOF_SIGNED);
        return;
    }

    if ( has_base )
        ctx->out_symbol(',');
    if ( (operand.specflag1 & ipp::ExternalSpace) != 0 )
    {
        op_t index = operand;
        index.type = o_imm;
        index.value = operand.addr;
        ctx->out_value(index, OOFW_32);
    }
    else if ( has_base || !ctx->out_name_expr(operand, operand.addr, BADADDR) )
    {
        ctx->out_value(operand, OOF_ADDR | OOFW_32 | OOF_SIGNED);
    }
    ctx->out_symbol(')');
}

//--------------------------------------------------------------------
bool output_operand(outctx_t *ctx, const op_t &operand)
{
    switch ( operand.type )
    {
        case o_reg:
            output_register_operand(ctx, operand);
            return true;
        case o_imm:
            ctx->out_value(operand, OOFW_32 | OOF_SIGNED);
            return true;
        case o_near:
            if ( !ctx->out_name_expr(operand, operand.addr, BADADDR) )
                ctx->out_value(operand, OOF_ADDR | OOFW_32);
            return true;
        case o_displ:
        case o_mem:
            output_memory_operand(ctx, operand);
            return true;
        default:
            return false;
    }
}

//--------------------------------------------------------------------
/// A resolved absolute call keeps its LR operand, so its target goes in a comment.
static void output_resolved_call_target(outctx_t *ctx)
{
    const std::optional<ipp::Decoded> insn = decode_at(ctx->insn.ea);
    if ( !insn
         || !insn->has_target
         || insn->flow != ipp::Flow::Call
         || insn->operand_count != 1
         || insn->ops[0].kind != ipp::OperandKind::Register )
    {
        return;
    }

    ctx->out_line(" ; target=", COLOR_AUTOCMT);
    op_t target;
    target.type = o_near;
    target.addr = insn->target;
    target.dtype = dt_dword;
    output_operand(ctx, target);
}

//--------------------------------------------------------------------
void output_instruction(outctx_t *ctx)
{
    ctx->out_mnem();
    for ( unsigned i = 0; i < UA_MAXOP && ctx->insn.ops[i].type != o_void; ++i )
    {
        if ( i != 0 )
        {
            ctx->out_symbol(',');
            ctx->out_char(' ');
        }
        ctx->out_one_operand(i);
    }
    if ( (ctx->insn.auxpref & AUXPREF_RAW_E) != 0 )
        ctx->out_line(" ; E=1 (raw)", COLOR_AUTOCMT);
    output_resolved_call_target(ctx);
    ctx->flush_outbuf();
}

} // namespace ipp::processor
