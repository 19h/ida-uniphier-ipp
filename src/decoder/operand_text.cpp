#include "decoder/operand_text.hpp"

#include "decoder/text.hpp"

namespace ipp
{

//--------------------------------------------------------------------
bool is_pc_relative(const Form &form)
{
    const std::string_view mnemonic = form.mnemonic;
    const std::string_view format = form.format;
    return (mnemonic == "br" || mnemonic == "brl") && format.find("LR,") == std::string_view::npos;
}

//--------------------------------------------------------------------
/// Replace each %d in FORM's format with the next value. A PC-relative form's
/// last value prints as its absolute target address.
static std::string expand_format(const Form &form, const operand_values_t &values, uint32_t address)
{
    const std::string_view format = form.format;
    const bool pc_relative = is_pc_relative(form);

    std::string text;
    int next_value = 0;
    size_t position = 0;
    while ( position < format.size() )
    {
        if ( format.compare(position, 2, "%d") != 0 || next_value >= values.count )
        {
            text.push_back(format[position]);
            ++position;
            continue;
        }

        const int32_t value = values.items[next_value];
        ++next_value;
        position += 2;
        if ( pc_relative && next_value == values.count )
        {
            text += "0x";
            append_hex(&text, address + static_cast<uint32_t>(value), 8);
        }
        else
        {
            append_decimal(&text, value);
        }
    }
    return text;
}

//--------------------------------------------------------------------
/// Remove the leading "[cN] mnemonic " from expanded format text.
static std::string_view strip_predicate_and_mnemonic(std::string_view text,
                                                     std::string_view mnemonic)
{
    if ( text.empty() || text[0] != '[' )
        return text;
    const size_t bracket = text.find(']');
    if ( bracket == std::string_view::npos
         || bracket + 1 >= text.size()
         || text[bracket + 1] != ' ' )
    {
        return text;
    }

    text.remove_prefix(bracket + 2);
    if ( text.compare(0, mnemonic.size(), mnemonic) != 0 )
        return text;
    if ( mnemonic.size() < text.size() && text[mnemonic.size()] != ' ' )
        return text;

    text.remove_prefix(mnemonic.size());
    if ( !text.empty() && text[0] == ' ' )
        text.remove_prefix(1);
    return text;
}

//--------------------------------------------------------------------
std::string render_operand_text(const Form &form, const operand_values_t &values, uint32_t address)
{
    if ( values.count <= 0 )
        return {};

    const std::string expanded = expand_format(form, values, address);
    std::string text(strip_predicate_and_mnemonic(expanded, form.mnemonic));
    if ( !text.empty() )
        text += ", ";
    text += 'c';
    append_decimal(&text, static_cast<uint32_t>(values.items[0]));
    return text;
}

//--------------------------------------------------------------------
void set_operand_text(Decoded *insn, std::string_view text)
{
    const size_t length = text.copy(insn->operands, sizeof(insn->operands) - 1);
    insn->operands[length] = '\0';
}

} // namespace ipp
