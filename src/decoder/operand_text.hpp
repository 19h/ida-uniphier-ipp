// Operand text of a decoded instruction, rendered from a form's format string.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "decoder/operand_program.hpp"
#include "ipp/instruction.hpp"

namespace ipp
{

/// True if FORM's last value is a complete displacement from the instruction.
/// The brl LR form is excluded: it requires an adjacent sethi-LR context, and its
/// low half alone is not a complete displacement.
[[nodiscard]] bool is_pc_relative(const Form &form);

/// Expand FORM's format string with VALUES, moving the predicate to the end:
/// "[c%d] add %d,R%d" becomes "5,R1, c7".
[[nodiscard]] std::string render_operand_text(const Form &form, const operand_values_t &values,
                                              uint32_t address);

/// Store TEXT as INSN's operand text, truncating to the record's inline buffer.
void set_operand_text(Decoded *insn, std::string_view text);

} // namespace ipp
