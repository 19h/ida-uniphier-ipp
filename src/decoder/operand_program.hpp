// Interpreter for the bytecode that extracts operand values from a word.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ipp
{

/// Operand values extracted from one instruction word, in format-string order.
struct operand_values_t
{
    static constexpr size_t CAPACITY = 16;

    std::array<int32_t, CAPACITY> items = {};
    int count = 0;
};

/// Run the program in BYTES against WORD until it has yielded OPERAND_COUNT
/// values. A malformed program stops early, leaving fewer values than requested.
[[nodiscard]] operand_values_t evaluate_operand_program(const uint8_t *bytes, size_t size,
                                                        int operand_count, uint32_t word);

} // namespace ipp
