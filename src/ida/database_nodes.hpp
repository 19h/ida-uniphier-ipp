// Netnodes through which the loader and processor share facts in a database.
//
// These names are stored in existing databases, so they must not change.

#pragma once

namespace ipp
{

/// Function symbols from the ELF files. Maps an address to its symbol size + 1,
/// so that a zero-sized symbol still reads as present.
inline constexpr char FUNCTION_SYMBOLS_NODE[] = "$ ipp.function-symbols";

/// Addresses where a positive-sized function symbol ends. Each is a hint that a
/// distinct function may begin there; the processor decides by examining the code.
inline constexpr char FUNCTION_ENDS_NODE[] = "$ ipp.function-ends";

/// Call references created for resolved literal-to-LR calls, so that re-emulation
/// can retract them without touching user references.
inline constexpr char ABSOLUTE_CALL_TARGETS_NODE[] = "$ ipp.absolute-call-targets";

/// Call references created for resolved sethi-LR/brl-LR calls, likewise.
inline constexpr char FAR_CALL_TARGETS_NODE[] = "$ ipp.far-call-targets";

} // namespace ipp
