// UniPhier IPP processor module. Encoding and typed operand layouts live in ippdec;
// this adapter translates them into IDA's public instruction model.

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include <ida.hpp>

#include <bitrange.hpp>
#include <frame.hpp>
#include <idp.hpp>
#include <ua.hpp>

#include "ipp/decoder.hpp"
#include "ipp/semantics.hpp"
#include "processor/analyzer.hpp"
#include "processor/context_decoder.hpp"
#include "processor/emulator.hpp"
#include "processor/function_discovery.hpp"
#include "processor/insn_encoding.hpp"
#include "processor/instruction_table.hpp"
#include "processor/output.hpp"

namespace ipp::processor
{

//--------------------------------------------------------------------
/// Answer the is-call, is-return, is-conditional and is-indirect-jump queries.
static ssize_t answer_instruction_query(int event, const insn_t *ida_insn)
{
    if ( ida_insn == nullptr )
        return 0;
    const std::optional<ipp::Decoded> insn = decode_at(ida_insn->ea);
    if ( !insn )
        return 0;

    bool answer = false;
    switch ( event )
    {
        case processor_t::ev_is_call_insn:
            answer = insn->flow == ipp::Flow::Call || insn->flow == ipp::Flow::Trap;
            break;
        case processor_t::ev_is_ret_insn:
            answer = insn->flow == ipp::Flow::Return;
            break;
        case processor_t::ev_is_cond_insn:
            answer = insn->predicate != ipp::PREDICATE_ALWAYS;
            break;
        default: // ev_is_indirect_jump
            answer = insn->flow == ipp::Flow::Branch && !insn->has_target;
            break;
    }
    return answer ? 1 : -1;
}

//--------------------------------------------------------------------
static ssize_t get_register_info(const char **main_name, bitrange_t *range, const char *name)
{
    const int reg = ipp::register_id(name);
    if ( reg < 0 )
        return -1;

    const ipp::RegisterSlice slice = ipp::register_slice(static_cast<uint16_t>(reg));
    *main_name = ipp::register_name(slice.reg);
    if ( range != nullptr )
        *range = bitrange_t(slice.bit_offset, slice.bit_count);
    return 1;
}

//--------------------------------------------------------------------
/// IDA's public record cannot retain RegisterAccess::conservative.
static int get_register_accesses(reg_accesses_t *out, const insn_t *ida_insn)
{
    if ( out == nullptr )
        return -1;
    if ( ida_insn == nullptr )
        return 0;
    const std::optional<ipp::Decoded> insn = decode_at(ida_insn->ea);
    if ( !insn )
        return 0;

    out->clear();
    for ( const ipp::RegisterAccess &effect : ipp::register_accesses(*insn) )
    {
        reg_access_t access;
        access.regnum = effect.storage.reg;
        access.opnum = effect.operand == ipp::IMPLICIT_OPERAND ? UA_MAXOP : effect.operand;
        access.range = bitrange_t(effect.storage.bit_offset, effect.storage.bit_count);
        const int reads = (effect.access & ipp::Read) != 0 ? READ_ACCESS : 0;
        const int writes = (effect.access & ipp::Write) != 0 ? WRITE_ACCESS : 0;
        access.access_type = static_cast<access_type_t>(reads | writes);
        out->push_back(access);
    }
    return 1;
}

//--------------------------------------------------------------------
static ssize_t calculate_stack_delta(sval_t *delta, const insn_t *ida_insn)
{
    if ( ida_insn == nullptr )
        return 0;
    const std::optional<ipp::Decoded> insn = decode_at(ida_insn->ea);
    if ( !insn )
        return 0;

    int64_t value = 0;
    const bool known = ipp::stack_pointer_delta(*insn, &value);
    *delta = static_cast<sval_t>(value);
    return known ? 1 : 0;
}

//--------------------------------------------------------------------
/// C7 always reads one. This implemented constant resolver finds no value for mutable
/// state, and no general register tracker or complete CFR value is claimed.
static ssize_t find_register_value(uval_t *out, const insn_t *ida_insn, int reg)
{
    if ( out == nullptr || ida_insn == nullptr || reg != ipp::C7 )
        return -1;
    *out = ipp::register_known_bits(ipp::C7).value;
    return 1;
}

//--------------------------------------------------------------------
static ssize_t find_operand_value(uval_t *out, const insn_t *ida_insn, int index)
{
    if ( out == nullptr || ida_insn == nullptr || index < 0 || index >= UA_MAXOP )
        return -1;
    const op_t &operand = ida_insn->ops[index];
    if ( operand.type != o_reg
         || operand.reg != ipp::C7
         || (operand.specflag1 & OPERAND_IS_RANGE) != 0 )
    {
        return -1;
    }
    *out = ipp::register_known_bits(ipp::C7).value;
    return 1;
}

//--------------------------------------------------------------------
static ssize_t create_function_frame(ea_t ea)
{
    const std::optional<ipp::Decoded> insn = decode_at(ea);
    int64_t delta = 0;
    if ( !insn || !ipp::stack_pointer_delta(*insn, &delta) || delta > 0 )
        return 0;
    return add_frame_ea(ea, -delta, 0, 0) ? 1 : 0;
}

//--------------------------------------------------------------------
struct ipp_procmod_t : public procmod_t
{
    /// Restores function symbols once the kernel's auto-analysis queues drain.
    struct database_listener_t : public event_listener_t
    {
        ssize_t idaapi on_event(ssize_t event, va_list /*va*/) override
        {
            if ( event == idb_event::auto_empty )
                restore_symbol_functions();
            return 0;
        }
    };

    database_listener_t database_listener;

    ssize_t idaapi on_event(ssize_t event, va_list va) override;
};

//--------------------------------------------------------------------
ssize_t idaapi ipp_procmod_t::on_event(ssize_t event, va_list va)
{
    switch ( event )
    {
        case processor_t::ev_init:
            inf_set_be(true);
            hook_event_listener(HT_IDB, &database_listener, &PH);
            return 1;

        case processor_t::ev_term:
            unhook_event_listener(HT_IDB, &database_listener);
            return 1;

        case processor_t::ev_newprc:
            return 1;

        case processor_t::ev_ana_insn:
            return analyze_instruction(va_arg(va, insn_t *));

        case processor_t::ev_emu_insn:
            return emulate_instruction(va_arg(va, const insn_t *));

        case processor_t::ev_out_insn:
            output_instruction(va_arg(va, outctx_t *));
            return 1;

        case processor_t::ev_out_operand:
        {
            outctx_t *ctx = va_arg(va, outctx_t *);
            const op_t *operand = va_arg(va, const op_t *);
            return ctx != nullptr && operand != nullptr && output_operand(ctx, *operand) ? 1 : -1;
        }

        case processor_t::ev_is_call_insn:
        case processor_t::ev_is_ret_insn:
        case processor_t::ev_is_cond_insn:
        case processor_t::ev_is_indirect_jump:
            return answer_instruction_query(static_cast<int>(event), va_arg(va, const insn_t *));

        case processor_t::ev_str2reg:
            return ipp::register_id(va_arg(va, const char *)) + 1;

        case processor_t::ev_get_reg_info:
        {
            const char **main_name = va_arg(va, const char **);
            bitrange_t *range = va_arg(va, bitrange_t *);
            return get_register_info(main_name, range, va_arg(va, const char *));
        }

        case processor_t::ev_get_reg_accesses:
        {
            reg_accesses_t *out = va_arg(va, reg_accesses_t *);
            return get_register_accesses(out, va_arg(va, const insn_t *));
        }

        case processor_t::ev_calc_spdelta:
        {
            sval_t *delta = va_arg(va, sval_t *);
            return calculate_stack_delta(delta, va_arg(va, const insn_t *));
        }

        case processor_t::ev_find_reg_value:
        {
            uval_t *out = va_arg(va, uval_t *);
            const insn_t *insn = va_arg(va, const insn_t *);
            return find_register_value(out, insn, va_arg(va, int));
        }

        case processor_t::ev_find_op_value:
        {
            uval_t *out = va_arg(va, uval_t *);
            const insn_t *insn = va_arg(va, const insn_t *);
            return find_operand_value(out, insn, va_arg(va, int));
        }

        case processor_t::ev_may_be_func:
        {
            const insn_t *insn = va_arg(va, const insn_t *);
            // 100 requests a distinct entry; see is_function_start().
            return insn != nullptr && is_function_start(insn->ea) ? 100 : 0;
        }

        case processor_t::ev_get_function_retsize:
            *va_arg(va, int *) = 0; // the return address is in LR
            return 1;

        case processor_t::ev_create_function_frame:
            return create_function_frame(va_arg(va, ea_t));

        default:
            return 0;
    }
}

//--------------------------------------------------------------------
static ssize_t idaapi notify(void * /*user_data*/, int event, va_list /*va*/)
{
    if ( event != processor_t::ev_get_procmod )
        return 0;
    return reinterpret_cast<ssize_t>(new ipp_procmod_t);
}

//--------------------------------------------------------------------
static asm_t make_assembler()
{
    asm_t assembler = asm_t();
    assembler.flag = ASH_HEXF3;
    assembler.name = "IPP assembler";
    assembler.origin = "org";
    assembler.end = "end";
    assembler.cmnt = ";";
    assembler.ascsep = '"';
    assembler.accsep = '\'';
    assembler.esccodes = "\"'";
    assembler.a_ascii = "db";
    assembler.a_byte = "db";
    assembler.a_word = "dw";
    assembler.a_dword = "dd";
    assembler.a_qword = "dq";
    assembler.a_bss = "ds %s";
    assembler.a_equ = "equ";
    assembler.a_curip = "$";
    assembler.a_public = "";
    assembler.a_weak = "";
    assembler.a_extrn = "extrn";
    assembler.a_comdef = "";
    return assembler;
}

//--------------------------------------------------------------------
static const std::vector<const char *> &register_names()
{
    static const std::vector<const char *> names = []
    {
        std::vector<const char *> result;
        for ( unsigned reg = 0; reg < ipp::RegisterCount; ++reg )
            result.push_back(ipp::register_name(static_cast<uint16_t>(reg)));
        return result;
    }();
    return names;
}

//--------------------------------------------------------------------
/// \return the instruction code that marks a return, for the kernel's flow analysis.
static int return_itype()
{
    const ipp::Form *forms = ipp::form_table();
    for ( size_t i = 0; i < ipp::form_count(); ++i )
    {
        if ( std::string_view(forms[i].mnemonic) == "jmpr" )
            return unconditional_itype(i);
    }
    return 0;
}

//--------------------------------------------------------------------
static processor_t make_processor()
{
    static const char *const SHORT_NAMES[] = {"ipp", nullptr};
    static const char *const LONG_NAMES[] = {"UniPhier IPP", nullptr};
    static const asm_t assembler = make_assembler();
    static const asm_t *const ASSEMBLERS[] = {&assembler, nullptr};

    const std::vector<instruc_t> &instructions = instruction_table();

    processor_t ph{};
    ph.version = IDP_INTERFACE_VERSION;
    ph.id = 0x1040;
    ph.flag = PR_USE32 | PR_DEFSEG32 | PR_RNAMESOK | PR_NO_SEGMOVE;
    ph.cnbits = 8;
    ph.dnbits = 8;
    ph.psnames = SHORT_NAMES;
    ph.plnames = LONG_NAMES;
    ph.assemblers = ASSEMBLERS;
    ph._notify = notify;
    ph.reg_names = register_names().data();
    ph.regs_num = ipp::RegisterCount;
    ph.reg_first_sreg = ipp::CS;
    ph.reg_last_sreg = ipp::DS;
    ph.reg_code_sreg = ipp::CS;
    ph.reg_data_sreg = ipp::DS;
    ph.instruc_start = 0;
    ph.instruc_end = static_cast<int>(instructions.size());
    ph.instruc = instructions.data();
    ph.icode_return = return_itype();
    ph.real_width[0] = 0;
    ph.real_width[1] = 7;
    ph.real_width[2] = 15;
    ph.real_width[3] = 0;
    return ph;
}

} // namespace ipp::processor

idaman processor_t LPH = ipp::processor::make_processor();
