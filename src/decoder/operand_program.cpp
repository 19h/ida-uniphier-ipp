// Operand programs are a small stack machine emitted by tools/gen_v8_rules.py.
// Only opcode positions are control bytes: a 0 inside a constant or a bit
// position is data. Each operand's program ends in OP_YIELD.
//
//   OP_YIELD                  pop the stack's only value as the next operand
//   OP_BITS hi lo             push word[hi:lo]
//   OP_CONSTANT b0 b1 b2 b3   push a little-endian int32
//   OP_CONCAT                 pop low, pop high, push high:low
//   OP_SIGN_EXTEND            sign-extend the top value to 32 bits
//   OP_SHIFT_LEFT n           shift unsigned, then reinterpret as int32
//   OP_ADD n                  add a signed 8-bit constant

#include "decoder/operand_program.hpp"

namespace ipp
{

namespace
{

enum opcode_t : uint8_t
{
    OP_YIELD = 0,
    OP_BITS = 1,
    OP_CONSTANT = 2,
    OP_CONCAT = 3,
    OP_SIGN_EXTEND = 4,
    OP_SHIFT_LEFT = 5,
    OP_ADD = 6,
};

/// A stack value and the number of encoding bits it was built from.
struct slot_t
{
    int32_t value;
    int width;
};

constexpr size_t MAX_STACK_DEPTH = 8;

} // namespace

//--------------------------------------------------------------------
static constexpr uint32_t low_mask(int width)
{
    if ( width <= 0 )
        return 0;
    if ( width >= 32 )
        return 0xffffffffu;
    return (1u << width) - 1u;
}

//--------------------------------------------------------------------
static constexpr int32_t to_signed(uint32_t bits)
{
    return static_cast<int32_t>(bits);
}

//--------------------------------------------------------------------
static constexpr uint32_t to_unsigned(int32_t value)
{
    return static_cast<uint32_t>(value);
}

//--------------------------------------------------------------------
static slot_t extract_bits(uint32_t word, int hi, int lo)
{
    const int width = hi - lo + 1;
    uint32_t bits = 0;
    if ( width > 0 && lo >= 0 && lo < 32 )
        bits = (word >> lo) & low_mask(width);
    return {to_signed(bits), width};
}

//--------------------------------------------------------------------
static uint32_t read_le32(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0])
        | (static_cast<uint32_t>(bytes[1]) << 8)
        | (static_cast<uint32_t>(bytes[2]) << 16)
        | (static_cast<uint32_t>(bytes[3]) << 24);
}

//--------------------------------------------------------------------
static slot_t concat(slot_t high, slot_t low)
{
    uint32_t bits = to_unsigned(low.value);
    if ( low.width > 0 && low.width < 32 )
        bits =
            (to_unsigned(high.value) << low.width) | (to_unsigned(low.value) & low_mask(low.width));
    else if ( low.width <= 0 )
        bits = to_unsigned(high.value);
    return {to_signed(bits), high.width + low.width};
}

//--------------------------------------------------------------------
static slot_t sign_extend(slot_t slot)
{
    uint32_t bits = to_unsigned(slot.value) & low_mask(slot.width);
    if ( slot.width > 0 && slot.width < 32 )
    {
        const uint32_t sign_bit = 1u << (slot.width - 1);
        if ( (bits & sign_bit) != 0 )
            bits |= ~low_mask(slot.width);
    }
    return {to_signed(bits), 32};
}

//--------------------------------------------------------------------
static slot_t shift_left(slot_t slot, int shift)
{
    uint32_t bits = to_unsigned(slot.value);
    if ( shift >= 32 )
        bits = 0;
    else if ( shift > 0 )
        bits <<= shift;
    return {to_signed(bits), slot.width + shift};
}

//--------------------------------------------------------------------
static slot_t add_constant(slot_t slot, int8_t addend)
{
    const int64_t sum = static_cast<int64_t>(slot.value) + addend;
    return {static_cast<int32_t>(sum), slot.width};
}

//--------------------------------------------------------------------
operand_values_t evaluate_operand_program(const uint8_t *bytes, size_t size, int operand_count,
                                          uint32_t word)
{
    operand_values_t result;
    if ( bytes == nullptr || operand_count <= 0 )
        return result;

    slot_t stack[MAX_STACK_DEPTH];
    size_t depth = 0;
    int yields = 0;
    size_t pc = 0;
    while ( pc < size && yields < operand_count )
    {
        const uint8_t opcode = bytes[pc++];
        switch ( opcode )
        {
            case OP_BITS:
                if ( pc + 2 > size || depth >= MAX_STACK_DEPTH )
                    return result;
                stack[depth++] = extract_bits(word, bytes[pc], bytes[pc + 1]);
                pc += 2;
                break;

            case OP_CONSTANT:
                if ( pc + 4 > size || depth >= MAX_STACK_DEPTH )
                    return result;
                stack[depth++] = {to_signed(read_le32(bytes + pc)), 0};
                pc += 4;
                break;

            case OP_CONCAT:
                if ( depth < 2 )
                    return result;
                stack[depth - 2] = concat(stack[depth - 2], stack[depth - 1]);
                --depth;
                break;

            case OP_SIGN_EXTEND:
                if ( depth < 1 )
                    return result;
                stack[depth - 1] = sign_extend(stack[depth - 1]);
                break;

            case OP_SHIFT_LEFT:
                if ( pc >= size || depth < 1 )
                    return result;
                stack[depth - 1] = shift_left(stack[depth - 1], bytes[pc++]);
                break;

            case OP_ADD:
                if ( pc >= size || depth < 1 )
                    return result;
                stack[depth - 1] = add_constant(stack[depth - 1], static_cast<int8_t>(bytes[pc++]));
                break;

            case OP_YIELD:
                if ( depth != 1 )
                    return result;
                depth = 0;
                if ( static_cast<size_t>(result.count) < operand_values_t::CAPACITY )
                    result.items[result.count++] = stack[0].value;
                ++yields;
                break;

            default:
                return result;
        }
    }
    return result;
}

} // namespace ipp
