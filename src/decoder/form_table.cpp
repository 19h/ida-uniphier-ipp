// The encoding table: generated data behind a small accessor API.

#include <iterator>

#include "decoder/form_table.hpp"

namespace ipp
{

namespace
{
#include "decoder/v8_rules.inc"
} // namespace

//--------------------------------------------------------------------
const Form *form_table()
{
    return FORMS;
}

//--------------------------------------------------------------------
size_t form_count()
{
    return std::size(FORMS);
}

//--------------------------------------------------------------------
const OperandSpec *operand_specs(const Form &form)
{
    return OPERAND_SPECS + form.operand_off;
}

//--------------------------------------------------------------------
operand_program_t operand_program(const Form &form)
{
    const size_t blob_size = std::size(OPERAND_PROGRAMS);
    if ( form.prog_off >= blob_size )
        return {nullptr, 0};
    return {OPERAND_PROGRAMS + form.prog_off, blob_size - form.prog_off};
}

} // namespace ipp
