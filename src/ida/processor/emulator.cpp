#include "processor/emulator.hpp"

#include <cstdint>
#include <optional>

#include <ida.hpp>

#include <auto.hpp>
#include <bytes.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <xref.hpp>

#include "database_nodes.hpp"
#include "ipp/decoder.hpp"
#include "ipp/semantics.hpp"
#include "processor/context_decoder.hpp"

namespace ipp::processor
{

namespace
{
constexpr uchar TARGET_TAG = 'T';
} // namespace

//--------------------------------------------------------------------
/// True if an automatic call reference from EA to TARGET exists. User references,
/// and those from older modules that are not tracked, must survive re-emulation.
static bool has_automatic_call_reference(ea_t ea, ea_t target)
{
    bool automatic = false;
    xrefblk_t xref;
    for ( bool ok = xref.first_from(ea, XREF_FAR); ok; ok = xref.next_from() )
    {
        if ( xref.iscode && xref.type == fl_CN && xref.to == target && !xref.user )
            automatic = true;
    }
    return automatic;
}

//--------------------------------------------------------------------
/// Keep NODE_NAME's record of the call target resolved at EA in step with the current
/// decode, deleting the automatic reference to any target that no longer applies.
static void reconcile_call_reference(ea_t ea, const ipp::Decoded &insn, const char *mnemonic,
                                     const char *node_name)
{
    const bool resolved = insn.has_target
        && insn.flow == ipp::Flow::Call
        && insn.has_mnemonic(mnemonic)
        && insn.operand_count != 0
        && insn.ops[0].is_register(ipp::LR)
        && is_mapped(insn.target);

    // Separate presence from value: a known target zero is not absence.
    netnode state(node_name, 0, resolved);
    const bool present = state != BADNODE && state.altval_ea(ea) != 0;
    const ea_t previous = present ? state.eaget(ea, TARGET_TAG) : 0;

    if ( present && (!resolved || previous != insn.target) )
    {
        if ( has_automatic_call_reference(ea, previous) )
            del_cref(ea, previous, false);
        state.altdel_ea(ea);
        state.eadel(ea, TARGET_TAG);
    }
    if ( resolved && (!present || previous != insn.target) )
    {
        state.easet(ea, insn.target, TARGET_TAG);
        state.altset_ea(ea, 1);
    }
}

//--------------------------------------------------------------------
static void reconcile_call_references(ea_t ea, const ipp::Decoded &insn)
{
    reconcile_call_reference(ea, insn, "jmpl", ABSOLUTE_CALL_TARGETS_NODE);
    reconcile_call_reference(ea, insn, "brl", FAR_CALL_TARGETS_NODE);
}

//--------------------------------------------------------------------
static void add_memory_references(const insn_t &ida_insn, const ipp::Operand &operand,
                                  unsigned index)
{
    const op_t &ida_operand = ida_insn.ops[index];
    const ea_t address = static_cast<uint32_t>(operand.value);

    if ( operand.reg == ipp::NoRegister && is_mapped(address) )
    {
        if ( operand.width != 0 )
            ida_insn.create_op_data(address, ida_operand);
        if ( operand.reads() )
            ida_insn.add_dref(address, ida_operand.offb, dr_R);
        if ( operand.writes() )
            ida_insn.add_dref(address, ida_operand.offb, dr_W);
    }
    else if ( operand.reg == ipp::SP && may_create_stkvars() )
    {
        const adiff_t displacement = operand.has_flag(ipp::PostIncrement) ? 0 : operand.value;
        if ( ida_insn.create_stkvar(ida_operand, displacement,
                                    operand.width != 0 ? STKVAR_VALID_SIZE : 0) )
        {
            op_stkvar(ida_insn.ea, index);
        }
    }
}

//--------------------------------------------------------------------
static void add_operand_references(const insn_t &ida_insn, const ipp::Decoded &insn)
{
    for ( unsigned i = 0; i < insn.operand_count; ++i )
    {
        const ipp::Operand &operand = insn.ops[i];
        if ( operand.kind == ipp::OperandKind::CodeAddress && insn.flow == ipp::Flow::Sequential )
        {
            const ea_t address = static_cast<uint32_t>(operand.value);
            if ( is_mapped(address) )
                add_dref(ida_insn.ea, address, dr_O);
        }
        // External-register indices are not addresses in this memory.
        if ( operand.kind == ipp::OperandKind::Memory && !operand.has_flag(ipp::ExternalSpace) )
            add_memory_references(ida_insn, operand, i);
    }
}

//--------------------------------------------------------------------
ssize_t emulate_instruction(const insn_t *ida_insn)
{
    if ( ida_insn == nullptr )
        return -1;

    const ea_t ea = ida_insn->ea;
    const std::optional<ipp::Decoded> decoded = decode_at(ea);
    if ( !decoded )
    {
        reconcile_call_references(ea, ipp::Decoded());
        return -1;
    }
    const ipp::Decoded &insn = *decoded;
    reconcile_call_references(ea, insn);

    if ( insn.has_target && is_mapped(insn.target) )
    {
        if ( insn.flow == ipp::Flow::Call )
            add_cref(ea, insn.target, fl_CN);
        if ( insn.flow == ipp::Flow::Branch )
            add_cref(ea, insn.target, fl_JN);
    }
    add_operand_references(*ida_insn, insn);

    const ea_t next_ea = ea + insn.length;
    const ea_t function_start = get_func_start(ea);
    int64_t stack_delta = 0;
    if ( function_start != BADADDR
         && ipp::stack_pointer_delta(insn, &stack_delta)
         && stack_delta != 0 )
    {
        add_func_auto_stkpnt(function_start, next_ea, static_cast<sval_t>(stack_delta));
    }

    // An unconditional call to a function known not to return ends the flow.
    const bool calls_noreturn = insn.flow == ipp::Flow::Call
        && insn.has_target
        && insn.predicate == ipp::PREDICATE_ALWAYS
        && is_mapped(insn.target)
        && !func_does_return(insn.target);
    if ( insn.falls_through && !calls_noreturn && is_mapped(next_ea) )
        add_cref(ea, next_ea, fl_F);
    return 1;
}

} // namespace ipp::processor
