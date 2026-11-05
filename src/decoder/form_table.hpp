// Internal access to the generated form table's operand programs.

#pragma once

#include <cstddef>
#include <cstdint>

#include "ipp/instruction.hpp"

namespace ipp
{

/// Bytes of an operand program. All programs share one blob, so SIZE runs to the
/// end of the blob rather than the end of this form's own program.
struct operand_program_t
{
    const uint8_t *bytes;
    size_t size;
};

/// \return the operand program of FORM, or an empty view if its offset is invalid.
[[nodiscard]] operand_program_t operand_program(const Form &form);

} // namespace ipp
