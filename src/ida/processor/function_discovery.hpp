// Function boundaries from ELF symbols, and recognition of functions following them.

#pragma once

#include <ida.hpp>

namespace ipp::processor
{

/// \return true if the kernel should start a distinct function at EA: it is a known
///         function symbol, or a symbol end hint followed by recognizable code. This
///         is a bounded discovery heuristic, not a statistical confidence or an ISA
///         assertion.
[[nodiscard]] bool is_function_start(ea_t ea);

/// AU_CODE/AU_TAIL may remove a leaf symbol immediately after a nonreturning call
/// (observed: libc _time32_to_time). Once those passes finish, restore only exact
/// ELF-backed entries, with their original extents. This is not heuristic discovery
/// or a bulk repair.
void restore_symbol_functions();

} // namespace ipp::processor
