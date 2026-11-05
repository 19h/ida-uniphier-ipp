// Register dependencies of an instruction: explicit operands, the predicate, and
// the supported subset of implicit effects.

#include <string_view>
#include <utility>
#include <vector>

#include "ipp/decoder.hpp"
#include "ipp/semantics.hpp"

namespace ipp
{

namespace
{

constexpr unsigned C7_CFR_BIT = 7;
constexpr unsigned PSR_INTERRUPT_ENABLE_BIT = 16;  // Fig.11
constexpr unsigned PSR_EXCEPTION_HANDLER_BIT = 26; // Fig.11
constexpr unsigned PSR_FIXED_POINT_MODE_BIT = 29;
constexpr unsigned CFR_LINK_SAVE_BITS = 16;

/// Accumulates access records, normalizing each to canonical storage.
class access_collector_t
{
public:
    /// Access to the whole of REG by the explicit operand OPERAND.
    void add_operand(uint16_t reg, unsigned access, unsigned operand, bool conservative)
    {
        add_slice(reg, register_slice(reg), access, operand, conservative);
    }

    /// Access to the whole of REG by an implicit effect.
    void add_implicit(uint16_t reg, unsigned access, bool conservative = false)
    {
        add_slice(reg, register_slice(reg), access, IMPLICIT_OPERAND, conservative);
    }

    /// Access to BITS bits of REG, starting at bit OFFSET, by an implicit effect.
    void add_field(uint16_t reg, unsigned access, unsigned offset, unsigned bits)
    {
        RegisterSlice slice = register_slice(reg);
        slice.bit_offset += static_cast<uint8_t>(offset);
        slice.bit_count = static_cast<uint8_t>(bits);
        add_slice(reg, slice, access, IMPLICIT_OPERAND, false);
    }

    /// Access to the registers FIRST..LAST by an implicit effect.
    void add_implicit_range(unsigned first, unsigned last, unsigned access)
    {
        for ( unsigned reg = first; reg <= last; ++reg )
            add_implicit(static_cast<uint16_t>(reg), access);
    }

    [[nodiscard]] std::vector<RegisterAccess> take() { return std::move(records_); }

private:
    void add_slice(uint16_t reg, const RegisterSlice &slice, unsigned access, unsigned operand,
                   bool conservative)
    {
        if ( reg >= RegisterCount || access == 0 )
            return;

        // C7 is fixed in every view, including CFR/CFR3 and implicit call/return
        // ranges. Split a covering range so neither reads nor writes include it.
        const unsigned end = static_cast<unsigned>(slice.bit_offset) + slice.bit_count;
        if ( slice.reg == CFR && slice.bit_offset <= C7_CFR_BIT && end > C7_CFR_BIT )
        {
            if ( slice.bit_offset < C7_CFR_BIT )
            {
                const unsigned below = C7_CFR_BIT - slice.bit_offset;
                push(CFR, slice.bit_offset, below, access, operand, conservative);
            }
            if ( end > C7_CFR_BIT + 1 )
                push(CFR, C7_CFR_BIT + 1, end - (C7_CFR_BIT + 1), access, operand, conservative);
            return;
        }

        records_.push_back(
            {slice, static_cast<uint8_t>(access), static_cast<uint8_t>(operand), conservative});
    }

    void push(uint16_t reg, unsigned offset, unsigned bits, unsigned access, unsigned operand,
              bool conservative)
    {
        const RegisterSlice slice = {reg, static_cast<uint8_t>(offset), static_cast<uint8_t>(bits)};
        records_.push_back(
            {slice, static_cast<uint8_t>(access), static_cast<uint8_t>(operand), conservative});
    }

    std::vector<RegisterAccess> records_;
};

} // namespace

//--------------------------------------------------------------------
static void add_operand_accesses(access_collector_t *out, const Decoded &insn)
{
    for ( unsigned i = 0; i < insn.operand_count; ++i )
    {
        const Operand &operand = insn.ops[i];
        const bool conservative = operand.has_flag(ConservativeAccess);
        switch ( operand.kind )
        {
            case OperandKind::Register:
                out->add_operand(operand.reg, operand.access, i, conservative);
                break;
            case OperandKind::RegisterRange:
                for ( unsigned reg = operand.reg; reg <= operand.reg_end; ++reg )
                    out->add_operand(static_cast<uint16_t>(reg), operand.access, i, conservative);
                break;
            case OperandKind::Memory:
                out->add_operand(operand.reg, operand.updates_base() ? ReadWrite : Read, i,
                                 conservative);
                break;
            default:
                break;
        }
    }
}

//--------------------------------------------------------------------
/// Effects recorded per form, from the reviewed primary-figure policies.
static void add_form_effects(access_collector_t *out, uint16_t effects)
{
    if ( (effects & StickyOverflow) != 0 )
        out->add_implicit(OVS, ReadWrite);
    if ( (effects & ReadFixedPointMode) != 0 )
        out->add_field(PSR, Read, PSR_FIXED_POINT_MODE_BIT, 1);
    if ( (effects & ReadBitPosition) != 0 )
        out->add_implicit(BPO, Read);
    if ( (effects & ReadAlignment) != 0 )
        out->add_implicit(ALN, Read);
    if ( (effects & ReadVectorCondition2) != 0 )
        out->add_implicit(VC2, Read);
    if ( (effects & ReadVectorCondition0) != 0 )
        out->add_implicit(VC0, Read);
    if ( (effects & WriteVectorConditions) != 0 )
        out->add_implicit_range(VC0, VC3, Write);
    if ( (effects & ReadVectorConditions) != 0 )
        out->add_implicit_range(VC0, VC3, Read);
}

//--------------------------------------------------------------------
static void add_call_effects(access_collector_t *out)
{
    out->add_implicit(LR, Write);
    out->add_implicit(SVR, Write);
    out->add_field(CFR, Read, 0, CFR_LINK_SAVE_BITS);
}

//--------------------------------------------------------------------
/// Fig.256/257: the transition may be suppressed by debug control; destination
/// writes are conservative conditional effects. Vector and debug-control register
/// effects are outside this supported subset.
static void add_privileged_interrupt_effects(access_collector_t *out)
{
    out->add_implicit(PSR, ReadWrite, true);
    out->add_implicit(IPSR, Write, true);
    out->add_implicit(IPC, Write, true);
}

//--------------------------------------------------------------------
static void add_return_effects(access_collector_t *out, const Decoded &insn)
{
    if ( insn.has_mnemonic("jmpr") )
    {
        out->add_implicit(LR, Read);
        out->add_implicit(SVR, Read);
        out->add_field(CFR, Write, 0, CFR_LINK_SAVE_BITS);
    }
    else if ( insn.has_mnemonic("rti") )
    {
        // Fig.255 selects one save bank using PSR.EH (Fig.11, bit 26). The API
        // reports the union of those conditional reads, not both banks as
        // unconditional inputs.
        out->add_field(PSR, Read, PSR_EXCEPTION_HANDLER_BIT, 1);
        out->add_implicit(IPC, Read, true);
        out->add_implicit(IPSR, Read, true);
        out->add_implicit(EPC, Read, true);
        out->add_implicit(EPSR, Read, true);
        out->add_implicit(PSR, Write);
    }
}

//--------------------------------------------------------------------
std::vector<RegisterAccess> register_accesses(const Decoded &insn)
{
    if ( !valid_instruction(insn) )
        return {};

    access_collector_t out;
    add_operand_accesses(&out, insn);
    out.add_operand(static_cast<uint16_t>(C0 + insn.predicate), Read, insn.operand_count, false);

    if ( insn.has_mnemonic("addc") || insn.has_mnemonic("subc") )
    {
        out.add_implicit(C0, ReadWrite);
        out.add_implicit(C0 + 1, Write);
        out.add_implicit(CAS, ReadWrite);
    }

    add_form_effects(&out, form_table()[insn.form_index].implicit_effects);

    if ( insn.has_mnemonic("vcchk") )
    {
        out.add_implicit_range(VC0, VC3, Read);
        out.add_implicit_range(C0, C0 + 5, Write);
    }
    if ( insn.has_mnemonic("mvclovs") )
        out.add_implicit(OVS, ReadWrite);
    if ( insn.has_mnemonic("mvclcas") )
        out.add_implicit(CAS, ReadWrite);

    if ( insn.flow == Flow::Call )
        add_call_effects(&out);

    // Fig.11/248/249: PSR.IE
    if ( insn.has_mnemonic("intd") || insn.has_mnemonic("inte") )
        out.add_field(PSR, Write, PSR_INTERRUPT_ENABLE_BIT, 1);

    if ( insn.flow == Flow::Trap && std::string_view(insn.mnemonic).compare(0, 2, "pi") == 0 )
        add_privileged_interrupt_effects(&out);

    if ( insn.has_mnemonic("settar") )
    {
        out.add_implicit(TAR, Write);
        out.add_implicit(PC, Read);
    }
    if ( insn.has_mnemonic("setlr") )
    {
        out.add_implicit(LR, Write);
        out.add_implicit(PC, Read);
    }

    if ( insn.flow == Flow::Return )
        add_return_effects(&out, insn);

    if ( insn.flow != Flow::Sequential )
    {
        const bool reads_pc =
            insn.flow == Flow::Call || insn.flow == Flow::Trap || insn.has_mnemonic("br");
        out.add_implicit(PC, reads_pc ? ReadWrite : Write, insn.flow == Flow::Trap);
    }
    return out.take();
}

} // namespace ipp
