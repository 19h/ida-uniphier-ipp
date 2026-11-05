// IDA's instruction table, derived from the decoder's form table.
//
// Instruction codes are stored in databases, so existing ones must not change:
//   0                                     "invalid"
//   1 + 2 * form + (conditional ? 1 : 0)  every form, unconditional then conditional
//   after those                           variants of forms that can discard an output

#pragma once

#include <optional>
#include <vector>

#include <ida.hpp>

#include <idp.hpp>

#include "ipp/instruction.hpp"

namespace ipp::processor
{

/// The table for processor_t::instruc. Lives for the life of the module.
[[nodiscard]] const std::vector<instruc_t> &instruction_table();

/// \return the code of the unconditional instruction for FORM_INDEX.
[[nodiscard]] int unconditional_itype(size_t form_index);

/// Choose the instruction code for INSN. A discarded R30/R31 output selects a variant
/// without a false CF_CHG bit. \return nothing if the variant does not exist.
[[nodiscard]] std::optional<uint16> select_itype(const ipp::Decoded &insn);

} // namespace ipp::processor
