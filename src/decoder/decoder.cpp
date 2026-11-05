// Single-instruction decoding: table lookup, operand extraction, validation.

#include "ipp/decoder.hpp"

#include <string_view>

#include "byte_order.hpp"
#include "decoder/form_table.hpp"
#include "decoder/operand_program.hpp"
#include "decoder/operand_text.hpp"

namespace ipp
{

namespace
{
constexpr uint16_t E_BIT = 0x8000;
constexpr uint16_t WIDE_PARCEL_BITS = 0x6000;
} // namespace

//--------------------------------------------------------------------
static Decoded make_unresolved(uint32_t address, uint32_t length, bool e_bit = false)
{
    Decoded insn;
    insn.address = address;
    insn.length = length;
    insn.e_bit = e_bit;
    return insn;
}

//--------------------------------------------------------------------
/// \return the index of the first form matching WORD, or form_count() if none does.
static size_t find_form(uint32_t word, Width width)
{
    const Form *forms = form_table();
    const size_t count = form_count();
    for ( size_t i = 0; i < count; ++i )
    {
        if ( forms[i].width == width && (word & forms[i].mask) == forms[i].match )
            return i;
    }
    return count;
}

//--------------------------------------------------------------------
/// Fix values that the embedded disassembler's tables get wrong. The mask and
/// extraction stay as extracted; only the resulting meaning is corrected.
static void apply_semantic_corrections(const Form &form, operand_values_t *values, Decoded *insn)
{
    if ( form.width != Width::W16 )
        return;

    const std::string_view mnemonic = form.mnemonic;

    // The embedded decoder prints c7 for narrow jloop. The instruction
    // appendix explicitly restricts these forms to predicate C6 (Fig.231, 235).
    if ( mnemonic == "jloop" )
    {
        values->items[0] = 6;
        insn->semantic_evidence = "US20040078549A1:Fig231,235";
    }

    // Compact I4 shifts encode counts 1..16, with zero representing 16.
    // The wide I5 forms retain their ordinary 0..31 count (Fig.423/430).
    if ( values->count == 3 && values->items[2] == 0 && (mnemonic == "asl" || mnemonic == "asr") )
    {
        values->items[2] = 16;
        insn->semantic_evidence =
            mnemonic == "asl" ? "US20040078549A1:Fig424" : "US20040078549A1:Fig431";
    }
}

//--------------------------------------------------------------------
/// \return the number of registers selectable by a field indexing from BASE.
static int register_bank_size(int base)
{
    if ( base == R0 || base == FS0 )
        return 32;
    if ( base == C0 )
        return 8;
    if ( base == FD0 || base == XD0 )
        return 64;
    return 2;
}

//--------------------------------------------------------------------
/// Resolve a register from its layout: a fixed BASE, or BASE indexed by the
/// operand value number ARG. Out-of-range values give NoRegister.
static uint16_t resolve_register(int base, int arg, const operand_values_t &values)
{
    if ( base < 0 )
        return NoRegister;
    if ( arg < 0 )
        return static_cast<uint16_t>(base);
    if ( arg >= values.count )
        return NoRegister;

    const int32_t index = values.items[arg];
    if ( index < 0 || index >= register_bank_size(base) )
        return NoRegister;
    return static_cast<uint16_t>(base + index);
}

//--------------------------------------------------------------------
/// \return the transfer width in bytes of the register range in OPERAND.
static uint8_t register_range_width(const Operand &operand)
{
    // The ABI transfer includes the padding beside 16-bit SVR.
    if ( operand.reg == LR && operand.reg_end == SVR )
        return 8;
    if ( operand.reg == NoRegister
         || operand.reg_end == NoRegister
         || operand.reg_end < operand.reg )
    {
        return operand.width;
    }
    const unsigned count = operand.reg_end - operand.reg + 1;
    return static_cast<uint8_t>(count * register_width(operand.reg));
}

//--------------------------------------------------------------------
/// Multiply/accumulate result fields numbered R30/R31 are discarded where the
/// primary equations specify this; they do not create GP/SP writes.
static bool discards_destination(const Operand &operand)
{
    if ( !operand.has_flag(DiscardSpecialDestination) || operand.reg < GP || operand.reg > SP )
        return false;
    return operand.kind == OperandKind::Register
        || (operand.kind == OperandKind::RegisterRange && operand.reg_end <= SP);
}

//--------------------------------------------------------------------
static Operand make_operand(const OperandSpec &spec, const operand_values_t &values,
                            uint32_t address)
{
    Operand operand;
    operand.kind = spec.kind;
    operand.reg = resolve_register(spec.reg_base, spec.reg_arg, values);
    operand.reg_end = resolve_register(spec.end_base, spec.end_arg, values);
    operand.value = spec.value_arg >= 0 && spec.value_arg < values.count
        ? values.items[spec.value_arg]
        : spec.constant;
    operand.width = spec.width;
    operand.access = spec.access;
    operand.flags = spec.flags;

    if ( discards_destination(operand) )
        operand.access = NoAccess;

    switch ( operand.kind )
    {
        case OperandKind::CodeAddress:
            operand.value = static_cast<int32_t>(address + static_cast<uint32_t>(operand.value));
            break;
        case OperandKind::Register:
            operand.width = static_cast<uint8_t>(register_width(operand.reg));
            break;
        case OperandKind::RegisterRange:
            operand.width = register_range_width(operand);
            break;
        default:
            break;
    }
    return operand;
}

//--------------------------------------------------------------------
/// Call covers jmpl and brl. brl writes LR, so the next instruction stays live
/// even when the predicate is 7. br stays Branch and does not fall through in
/// that case. Trap continuation denotes a possible handler return, not ordinary
/// sequential execution.
static bool can_fall_through(const Form &form, uint32_t predicate)
{
    return form.kind != Kind::Insn
        || form.flow == Flow::Sequential
        || form.flow == Flow::Call
        || form.flow == Flow::Trap
        || predicate < PREDICATE_ALWAYS;
}

//--------------------------------------------------------------------
/// Build the record for WORD, which FORM_INDEX matched.
static Decoded make_instruction(size_t form_index, uint32_t word, uint32_t address, uint32_t length,
                                bool e_bit)
{
    const Form &form = form_table()[form_index];
    const operand_program_t program = operand_program(form);
    operand_values_t values =
        evaluate_operand_program(program.bytes, program.size, form.nops, word);
    if ( values.count != form.nops )
        return make_unresolved(address, length, e_bit);

    Decoded insn;
    insn.address = address;
    insn.length = length;
    insn.kind = form.kind;
    insn.flow = form.flow;
    insn.mnemonic = form.mnemonic;
    insn.evidence = form.evidence;
    insn.semantic_evidence = form.semantic_evidence;
    insn.form_index = static_cast<uint16_t>(form_index);
    insn.e_bit = e_bit;

    apply_semantic_corrections(form, &values, &insn);
    set_operand_text(&insn, render_operand_text(form, values, address));

    insn.operand_count = form.operand_count;
    const OperandSpec *specs = operand_specs(form);
    for ( unsigned i = 0; i < form.operand_count; ++i )
        insn.ops[i] = make_operand(specs[i], values, address);

    const uint32_t predicate =
        values.count > 0 ? static_cast<uint32_t>(values.items[0]) : PREDICATE_ALWAYS;
    insn.predicate = static_cast<uint8_t>(predicate);
    insn.falls_through = can_fall_through(form, predicate);

    if ( values.count > 0 && is_pc_relative(form) )
    {
        insn.has_target = true;
        insn.target = address + static_cast<uint32_t>(values.items[values.count - 1]);
    }
    return insn;
}

//--------------------------------------------------------------------
Decoded decode_one(const uint8_t *bytes, size_t size, uint32_t address)
{
    if ( bytes == nullptr || size == 0 )
        return make_unresolved(address, 0);
    if ( size == 1 )
        return make_unresolved(address, 1, (bytes[0] & 0x80) != 0);

    const uint16_t parcel = read_be16(bytes);
    const bool e_bit = (parcel & E_BIT) != 0;
    const bool wide = (parcel & WIDE_PARCEL_BITS) == WIDE_PARCEL_BITS;
    if ( wide && size < 4 )
        return make_unresolved(address, static_cast<uint32_t>(size), e_bit);
    const uint32_t length = wide ? 4 : 2;

    // Alignment is part of instruction validity, not just an adapter check.
    // Retain the parcel/truncation accounting and raw E for diagnostic scans.
    if ( (address & 1) != 0 )
        return make_unresolved(address, length, e_bit);

    const uint32_t word = wide ? read_be32(bytes) : parcel;
    const size_t form_index = find_form(word, wide ? Width::W32 : Width::W16);
    if ( form_index == form_count() )
        return make_unresolved(address, length, e_bit);
    return make_instruction(form_index, word, address, length, e_bit);
}

//--------------------------------------------------------------------
static bool valid_operand(const Operand &operand)
{
    switch ( operand.kind )
    {
        case OperandKind::Register:
            if ( operand.reg >= RegisterCount )
                return false;
            break;
        case OperandKind::RegisterRange:
            if ( operand.reg >= RegisterCount
                 || operand.reg_end >= RegisterCount
                 || operand.reg_end < operand.reg )
            {
                return false;
            }
            break;
        case OperandKind::Memory:
            if ( operand.reg != NoRegister && operand.reg >= RegisterCount )
                return false;
            break;
        case OperandKind::Immediate:
        case OperandKind::CodeAddress:
            break;
        case OperandKind::None:
        default:
            return false;
    }
    return (operand.access & ~static_cast<unsigned>(ReadWrite)) == 0;
}

//--------------------------------------------------------------------
bool valid_instruction(const Decoded &insn)
{
    if ( insn.kind != Kind::Insn
         || (insn.address & 1) != 0
         || (insn.length != 2 && insn.length != 4)
         || insn.form_index >= form_count()
         || insn.mnemonic == nullptr
         || insn.predicate > PREDICATE_ALWAYS
         || insn.operand_count > MAX_OPERANDS )
    {
        return false;
    }

    const Form &form = form_table()[insn.form_index];
    if ( static_cast<uint32_t>(form.width) != insn.length
         || form.operand_count != insn.operand_count )
    {
        return false;
    }

    for ( unsigned i = 0; i < insn.operand_count; ++i )
    {
        if ( !valid_operand(insn.ops[i]) )
            return false;
    }
    return true;
}

} // namespace ipp
