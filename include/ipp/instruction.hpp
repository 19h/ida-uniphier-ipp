// Instruction data model: the encoding table rows and decoded records.
//
// Every accepted encoding is one row (Form) of form_table(), carrying an
// evidence id. A decoded instruction (Decoded) is a plain, copyable value that
// holds no IDA types.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "ipp/registers.hpp"

namespace ipp
{

enum class Kind : int
{
    Insn = 0,
    NonCode = 1,
    Unresolved = 2,
};

enum class Flow : int
{
    Sequential = 0,
    Branch = 1,
    Call = 2,
    Return = 3,
    Trap = 4, // software interrupt; continuation is a possible handler return
};

enum class Width : int
{
    W16 = 2,
    W32 = 4,
};

enum class OperandKind : uint8_t
{
    None,
    Register,
    RegisterRange,
    Immediate,
    Memory,
    CodeAddress,
};

enum Access : uint8_t
{
    NoAccess = 0,
    Read = 1,
    Write = 2,
    ReadWrite = 3,
};

enum OperandFlags : uint8_t
{
    PostIncrement = 1,
    ExternalSpace = 2,
    SpAlias = 4,
    GpAlias = 8,
    ConservativeAccess = 16,
    DiscardSpecialDestination = 32,
};

enum ImplicitEffects : uint16_t
{
    StickyOverflow = 1,
    ReadFixedPointMode = 2,
    ReadBitPosition = 4,
    ReadAlignment = 8,
    ReadVectorCondition2 = 16,
    ReadVectorConditions = 32,
    WriteVectorConditions = 64,
    ReadVectorCondition0 = 128,
};

/// Predicate register number that makes an instruction unconditional (C7).
inline constexpr uint8_t PREDICATE_ALWAYS = 7;

/// Decoded::form_index of a record that matched no table row.
inline constexpr uint16_t NO_FORM = 0xffff;

/// Capacity of Decoded::ops. The generator rejects forms with more than six explicit
/// operands; the predicate is not one of them.
inline constexpr size_t MAX_OPERANDS = 7;

/// Typed layout of one operand within a Form.
struct OperandSpec
{
    OperandKind kind;
    int16_t reg_base;
    int8_t reg_arg;
    int16_t end_base;
    int8_t end_arg;
    int8_t value_arg;
    int32_t constant;
    uint8_t width;
    uint8_t access;
    uint8_t flags;
};

/// One accepted encoding. Rule order is match order.
struct Form
{
    const char *id;
    const char *mnemonic;
    const char *evidence;
    Flow flow;
    Kind kind;
    Width width;
    uint32_t match;
    uint32_t mask;
    const char *format;
    uint16_t prog_off;
    uint8_t nops;
    uint16_t operand_off;
    uint8_t operand_count;
    const char *semantic_evidence = nullptr;
    uint16_t implicit_effects = 0;
};

/// One decoded operand.
struct Operand
{
    OperandKind kind = OperandKind::None;
    uint16_t reg = NoRegister;
    uint16_t reg_end = NoRegister;
    int32_t value = 0; // immediate, byte displacement, or post-increment amount
    uint8_t width = 0; // bytes; zero when transfer width is not established
    uint8_t access = NoAccess;
    uint8_t flags = 0;

    [[nodiscard]] constexpr bool reads() const { return (access & Read) != 0; }
    [[nodiscard]] constexpr bool writes() const { return (access & Write) != 0; }
    [[nodiscard]] constexpr bool has_flag(OperandFlags flag) const { return (flags & flag) != 0; }

    /// True if this operand is exactly the register NUMBER.
    [[nodiscard]] constexpr bool is_register(uint16_t number) const
    {
        return kind == OperandKind::Register && reg == number;
    }

    /// True if this is a register range that includes the register NUMBER.
    [[nodiscard]] constexpr bool range_covers(uint16_t number) const
    {
        return kind == OperandKind::RegisterRange && reg <= number && reg_end >= number;
    }

    /// True for a memory operand whose base register changes by a nonzero amount.
    [[nodiscard]] constexpr bool updates_base() const
    {
        return kind == OperandKind::Memory && has_flag(PostIncrement) && value != 0;
    }
};

/// One decoded instruction, or an unresolved run of bytes.
///
/// The text and pointer members are C-compatible by design: mnemonic and
/// evidence point at static table strings and operands is an inline buffer, so
/// a record never allocates and can be copied freely during linear scans.
struct Decoded
{
    uint32_t address = 0;
    uint32_t length = 0;
    Kind kind = Kind::Unresolved;
    Flow flow = Flow::Sequential;
    const char *mnemonic = "unresolved";
    const char *evidence = nullptr;
    const char *semantic_evidence = nullptr; // correction beyond the embedded table
    char operands[96] = {};
    bool has_target = false;
    uint32_t target = 0;
    bool falls_through = true;
    uint16_t form_index = NO_FORM;
    uint8_t predicate = PREDICATE_ALWAYS;
    bool e_bit = false; // raw parcel bit 15; its execution semantics are unverified
    uint8_t operand_count = 0;
    std::array<Operand, MAX_OPERANDS> ops = {};

    [[nodiscard]] bool has_mnemonic(std::string_view name) const
    {
        return mnemonic != nullptr && name == mnemonic;
    }

    /// First address after this instruction. Wider than an address, so an
    /// instruction ending exactly at the top of memory does not wrap.
    [[nodiscard]] constexpr uint64_t end_address() const
    {
        return static_cast<uint64_t>(address) + length;
    }
};

/// The encoding table, in match order.
[[nodiscard]] const Form *form_table();

/// \return the number of rows in form_table().
[[nodiscard]] size_t form_count();

/// \return FORM's operand layouts, an array of FORM.operand_count entries.
[[nodiscard]] const OperandSpec *operand_specs(const Form &form);

} // namespace ipp
