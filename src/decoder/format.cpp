// Text rendering of decoded instructions.

#include "ipp/format.hpp"

#include <algorithm>

#include "decoder/text.hpp"

namespace ipp
{

//--------------------------------------------------------------------
const char *flow_name(Kind kind, Flow flow)
{
    if ( kind == Kind::NonCode )
        return "noncode";
    if ( kind == Kind::Unresolved )
        return "unresolved";

    switch ( flow )
    {
        case Flow::Sequential:
            return "sequential";
        case Flow::Branch:
            return "branch";
        case Flow::Call:
            return "call";
        case Flow::Return:
            return "return";
        case Flow::Trap:
            return "trap";
    }
    return "unresolved";
}

//--------------------------------------------------------------------
static bool has_address_operand(const Decoded &insn)
{
    const size_t count = std::min<size_t>(insn.operand_count, insn.ops.size());
    for ( size_t i = 0; i < count; ++i )
    {
        if ( insn.ops[i].kind == OperandKind::CodeAddress )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------
std::string format_insn(const Decoded &insn, const uint8_t *raw)
{
    std::string line;
    append_hex(&line, insn.address, 8);
    line += "  ";
    if ( raw != nullptr )
    {
        for ( uint32_t i = 0; i < insn.length; ++i )
            append_hex(&line, raw[i], 2);
    }
    line += "  len=";
    append_decimal(&line, insn.length);
    line += "  ";
    line += insn.mnemonic != nullptr ? insn.mnemonic : "unresolved";
    if ( insn.operands[0] != '\0' )
    {
        line += ' ';
        line += insn.operands;
    }
    line += "  ";
    line += flow_name(insn.kind, insn.flow);

    if ( insn.e_bit )
        line += " ; E=1 (raw)";

    // A call whose target is not an operand still shows the resolved destination.
    if ( insn.has_target && insn.flow == Flow::Call && !has_address_operand(insn) )
    {
        line += " ; target=0x";
        append_hex(&line, insn.target, 8);
    }
    return line;
}

} // namespace ipp
