// Regression test: typed operands, register aliases, access effects, stack deltas,
// invalid input and call folding, exercised over synthetic encodings.

#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "ipp/decode.hpp"
#include "ipp/elf.hpp"

#include "support/check.hpp"

using ipp::test::text_equals;

//--------------------------------------------------------------------
/// Decode the low SIZE bytes of WORD, as stored big-endian in memory.
static ipp::Decoded decode(uint32_t word, unsigned size, uint32_t address = 0)
{
    uint8_t bytes[4];
    for ( unsigned i = 0; i < size; ++i )
        bytes[i] = static_cast<uint8_t>(word >> ((size - i - 1) * 8));
    return ipp::decode_one(bytes, size, address);
}

//--------------------------------------------------------------------
/// \return the combined access to exactly the given bits of REG.
static unsigned access_to(const ipp::Decoded &insn, uint16_t reg, unsigned bit_offset,
                          unsigned bit_count)
{
    unsigned result = 0;
    for ( const ipp::RegisterAccess &effect : ipp::register_accesses(insn) )
    {
        if ( effect.storage.reg == reg
             && effect.storage.bit_offset == bit_offset
             && effect.storage.bit_count == bit_count )
        {
            result |= effect.access;
        }
    }
    return result;
}

//--------------------------------------------------------------------
static uint64_t low_bits(unsigned count)
{
    return count == 64 ? ~uint64_t(0) : (uint64_t(1) << count) - 1;
}

//--------------------------------------------------------------------
/// \return the bits of REG that INSN accesses in any of the given MODE.
static uint64_t accessed_bits(const ipp::Decoded &insn, uint16_t reg, unsigned mode)
{
    uint64_t result = 0;
    for ( const ipp::RegisterAccess &effect : ipp::register_accesses(insn) )
    {
        if ( effect.storage.reg != reg || (effect.access & mode) == 0 )
            continue;
        result |= low_bits(effect.storage.bit_count) << effect.storage.bit_offset;
    }
    return result;
}

//--------------------------------------------------------------------
/// Compact scalar memory forms: source-aligned FDCT/IDCT and PCM copy.
/// 4080/4090 were incorrectly inferred as ordinary halfword memory; their exact
/// external-register semantics remain unresolved.
static void test_compact_memory_forms()
{
    for ( unsigned base = 0; base < 16; ++base )
    {
        for ( unsigned data = 0; data < 16; ++data )
        {
            for ( unsigned e = 0; e < 2; ++e )
            {
                for ( unsigned pattern : {0x5000u, 0x5010u, 0x5040u, 0x5050u} )
                {
                    const ipp::Decoded insn = decode(pattern | (base << 8) | data | (e << 15), 2);
                    const bool store = (pattern & 0x10) != 0;
                    const bool post = (pattern & 0x40) != 0;
                    CHECK(insn.kind == ipp::Kind::Insn
                          && insn.length == 2
                          && insn.predicate == 7
                          && insn.e_bit == (e != 0));
                    CHECK(text_equals(insn.mnemonic, store ? "sth" : "ldh"));
                    const ipp::Operand &memory = insn.ops[store ? 0 : 1];
                    const ipp::Operand &value = insn.ops[store ? 1 : 0];
                    CHECK(memory.kind == ipp::OperandKind::Memory
                          && memory.width == 2
                          && memory.reg == ipp::R0 + base);
                    CHECK(memory.value == (post ? 2 : 0)
                          && memory.has_flag(ipp::PostIncrement) == post);
                    CHECK(memory.access == (store ? ipp::Write : ipp::Read));
                    CHECK(value.kind == ipp::OperandKind::Register && value.reg == ipp::R0 + data);
                    CHECK(value.access == (store ? ipp::Read : ipp::Write));
                }
                for ( unsigned pattern : {0x4080u, 0x4090u} )
                {
                    const ipp::Decoded insn = decode(pattern | (base << 8) | data | (e << 15), 2);
                    CHECK(insn.kind == ipp::Kind::Unresolved
                          && insn.length == 2
                          && insn.e_bit == (e != 0));
                    CHECK(insn.operand_count == 0 && ipp::register_accesses(insn).empty());
                }
            }
        }
    }
}

//--------------------------------------------------------------------
static void test_register_known_bits()
{
    CHECK(ipp::register_known_bits(ipp::C7).mask == 1);
    CHECK(ipp::register_known_bits(ipp::C7).value == 1);
    for ( ipp::Register reg : {ipp::CFR, ipp::CFR3} )
    {
        CHECK(ipp::register_known_bits(reg).mask == 0x80);
        CHECK(ipp::register_known_bits(reg).value == 0x80);
    }
    for ( ipp::Register reg : {ipp::R0, ipp::C0, ipp::CFR0, ipp::CFR1, ipp::CFR2, ipp::NoRegister} )
        CHECK(ipp::register_known_bits(reg).mask == 0);
    for ( unsigned reg = 0; reg < ipp::RegisterCount; ++reg )
    {
        const ipp::RegisterKnownBits known = ipp::register_known_bits(static_cast<uint16_t>(reg));
        const uint64_t mask = low_bits(ipp::register_slice(static_cast<uint16_t>(reg)).bit_count);
        CHECK((known.mask & ~mask) == 0 && (known.value & ~known.mask) == 0);
    }
}

//--------------------------------------------------------------------
static void test_cfr_access_masks()
{
    CHECK(accessed_bits(decode(0x0f5d, 2), ipp::CFR, ipp::ReadWrite) == 0);
    CHECK(accessed_bits(decode(0x74000000, 4), ipp::CFR, ipp::Read)
          == 1); // C0 predicate remains mutable
    CHECK(accessed_bits(decode(0x602093c7, 4), ipp::CFR, ipp::Read) == 0); // C7 source guard
    CHECK(accessed_bits(decode(0x602093c7, 4), ipp::CFR, ipp::Write) == 3);
    CHECK(accessed_bits(decode(0x60007f27, 4), ipp::CFR, ipp::Read) == 0xffffff7fu);
    CHECK(accessed_bits(decode(0x61007f27, 4), ipp::CFR, ipp::Write) == 0xffffff7fu);
    CHECK(accessed_bits(decode(0x60007fbf, 4), ipp::CFR, ipp::Read) == 0x7fu);
    CHECK(accessed_bits(decode(0x61007fbf, 4), ipp::CFR, ipp::Write) == 0x7fu);
    CHECK(accessed_bits(decode(0x0b20, 2), ipp::CFR, ipp::Read) == 0xff7fu);
    CHECK(accessed_bits(decode(0x014f, 2), ipp::CFR, ipp::Write) == 0xff7fu);
}

//--------------------------------------------------------------------
/// No accepted encoding may report the constant C7 bit as a dependency.
static void test_c7_is_never_a_dependency()
{
    size_t accepted = 0;
    const auto check_word = [&accepted](uint32_t word, unsigned width)
    {
        const ipp::Decoded insn = decode(word, width);
        if ( !ipp::valid_instruction(insn) )
            return;
        ++accepted;
        CHECK((accessed_bits(insn, ipp::CFR, ipp::ReadWrite) & 0x80) == 0);
    };

    for ( uint32_t word = 0; word < 65536; ++word )
    {
        if ( (word & 0x6000) != 0x6000 )
            check_word(word, 2);
    }

    uint32_t state = 0x1040;
    for ( size_t i = 0; i < ipp::form_count(); ++i )
    {
        const ipp::Form &form = ipp::form_table()[i];
        if ( form.width != ipp::Width::W32 )
            continue;
        for ( unsigned sample = 0; sample < 16; ++sample )
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            const uint32_t free_bits = sample == 0 ? 0 : sample == 1 ? 0xffffffffu : state;
            const uint32_t word = form.match | (free_bits & ~form.mask);
            for ( unsigned predicate = 0; predicate < 8; ++predicate )
                check_word((word & ~7u) | predicate, 4);
        }
    }
    std::printf("constant-state accepted cases=%zu\n", accepted);
}

//--------------------------------------------------------------------
static void test_stack_pointer_deltas()
{
    struct stack_case_t
    {
        uint32_t word;
        unsigned width;
        bool known;
        int64_t delta;
    };
    const stack_case_t cases[] = {
        {0x0f5f, 2, true, -8},      {0x0841, 2, true, 8},
        {0x7f5f0047, 4, true, 8},   {0x7c1f0047, 4, true, 8},
        {0x7f5f0040, 4, false, 0}, // conditional SP arithmetic
        {0x40be, 2, false, 0},     // ldp R30:R31,(SP,0): SP is a destination
        {0x60fe9007, 4, false, 0}, // wide pair replacement from a different base
        {0x60feb00f, 4, false, 0}, // pair replacement plus another base's update
        {0x60fdbf1f, 4, false, 0}, // ldq R28:R31,(R0+)16
        {0x7ffdbf1f, 4, false, 0}, // quad replacement and SP writeback overlap
        {0x7ffeb00f, 4, false, 0}, // pair replacement and SP writeback overlap
        {0x7fff600f, 4, false, 0}, // scalar replacement and SP writeback overlap
        {0x7fff6007, 4, false, 0}, // scalar replacement with zero writeback
        {0x7fe0600f, 4, true, 4},  // load into R0 through SP writeback
        {0x7fe0780f, 4, true, 4},  // store through SP writeback
        {0x7fff780f, 4, true, 4},  // SP value is a source, not a destination
        {0x7fffbf1f, 4, true, 16}, // store R28:R31; only base updates SP
        {0x7fe060ff, 4, true, 124}, {0x7fe06407, 4, true, -512},
        {0x7fe06008, 4, false, 0}, // conditional nonzero writeback
        {0x7fe06000, 4, true, 0},  // conditional zero writeback does not change SP
        {0x61a23cf7, 4, true, 0},  // discarded paired SP output
        {0x61a200ff, 4, true, 0},  // discarded scalar SP output
        {0x61bfd087, 4, false, 0}, // extw really writes SP
    };
    for ( const stack_case_t &c : cases )
    {
        const ipp::Decoded insn = decode(c.word, c.width);
        CHECK(ipp::valid_instruction(insn));
        int64_t delta = 1234;
        CHECK(ipp::stack_pointer_delta(insn, &delta) == c.known);
        if ( c.known )
            CHECK(delta == c.delta);
    }

    int64_t invalid_delta = 1234;
    CHECK(!ipp::stack_pointer_delta(ipp::Decoded{}, &invalid_delta));
    CHECK(!ipp::stack_pointer_delta(decode(0x0841, 2), nullptr));
}

//--------------------------------------------------------------------
static void test_register_lookup_and_slices()
{
    const ipp::Decoded insn = decode(0x0f5f, 2);
    CHECK(ipp::valid_instruction(insn));
    CHECK(insn.operand_count == 2 && insn.ops[0].reg == ipp::SP);
    CHECK(insn.ops[0].access == ipp::ReadWrite && insn.ops[1].value == -8);
    CHECK(insn.ops[1].kind == ipp::OperandKind::Immediate && insn.predicate == 7);

    CHECK(ipp::register_id("sp") == 31 && ipp::register_id("R31") == 31);
    CHECK(ipp::register_id("GP") == 30 && ipp::register_id("R30") == 30);
    CHECK(ipp::register_id("not_a_register") == -1);
    CHECK(ipp::register_width(ipp::M0) == 8 && ipp::register_width(ipp::FS0) == 4);
    CHECK(ipp::register_width(ipp::CFR0) == 1);
    CHECK(ipp::register_slice(ipp::CFR0).reg == ipp::CFR
          && ipp::register_slice(ipp::CFR0).bit_offset == 24);
    CHECK(ipp::register_slice(ipp::CFR3).bit_offset == 0);
    CHECK(ipp::register_slice(ipp::MH1).reg == ipp::M1
          && ipp::register_slice(ipp::MH1).bit_offset == 32);
    CHECK(ipp::register_slice(ipp::ML0).reg == ipp::M0
          && ipp::register_slice(ipp::ML0).bit_count == 32);
    CHECK(ipp::register_slice(ipp::FS0 + 2).reg == ipp::XD0 + 1);
    CHECK(ipp::register_slice(ipp::FS0 + 2).bit_offset == 32);
    CHECK(ipp::register_slice(ipp::FS0 + 3).bit_offset == 0);
    CHECK(ipp::register_slice(ipp::FD0 + 2).reg == ipp::XD0 + 1);
    CHECK(ipp::register_slice(ipp::FD0 + 2).bit_count == 64);
    CHECK(ipp::register_slice(ipp::FD0 + 1).reg == ipp::XD0 + 16);
    CHECK(ipp::register_slice(ipp::FD0 + 3).reg == ipp::XD0 + 17);
    for ( unsigned i = 0; i < 32; ++i )
    {
        const ipp::RegisterSlice slice = ipp::register_slice(static_cast<uint16_t>(ipp::FD0 + i));
        CHECK(slice.reg == ipp::XD0 + (i / 2) + (i % 2) * 16);
        CHECK(slice.bit_offset == 0 && slice.bit_count == 64);
    }
    CHECK(ipp::register_slice(ipp::FD0 + 32).reg == ipp::FD0 + 32);

    for ( unsigned reg = 0; reg < ipp::RegisterCount; ++reg )
    {
        const char *name = ipp::register_name(static_cast<uint16_t>(reg));
        CHECK(name != nullptr);
        CHECK(name[0] != 0);
        CHECK(ipp::register_id(name) == static_cast<int>(reg));
    }
}

//--------------------------------------------------------------------
/// Values loaded under one FP name are consumed under its alias.
static void test_floating_point_aliases()
{
    ipp::Decoded insn = decode(0x62f0f487, 4); // atan: coefficient load into XD16
    CHECK(access_to(insn, ipp::XD0 + 16, 0, 64) == ipp::Write);
    insn = decode(0x60c2dda7, 4); // fmsub consumes that value as FD1
    CHECK(access_to(insn, ipp::XD0 + 16, 0, 64) == ipp::Read);
    insn = decode(0x62f1f4c7, 4); // pzero: coefficient load into XD17
    CHECK(access_to(insn, ipp::XD0 + 17, 0, 64) == ipp::Write);
    insn = decode(0x62c6df37, 4); // fmadd consumes it as FD3
    CHECK(access_to(insn, ipp::XD0 + 17, 0, 64) == ipp::Read);
}

//--------------------------------------------------------------------
static void test_memory_and_flow_operands()
{
    ipp::Decoded insn = decode(0x40e1, 2);
    CHECK(insn.ops[0].kind == ipp::OperandKind::Memory && insn.ops[0].reg == ipp::SP);
    CHECK(insn.ops[0].width == 8 && insn.ops[0].access == ipp::Write);
    CHECK(insn.ops[1].kind == ipp::OperandKind::RegisterRange);
    CHECK(insn.ops[1].reg == ipp::LR && insn.ops[1].reg_end == ipp::SVR);

    insn = decode(0x61ea400f, 4);
    CHECK(insn.ops[0].reg == 10 && insn.ops[0].access == ipp::Write);
    CHECK(insn.ops[1].kind == ipp::OperandKind::Memory && insn.ops[1].reg == 1);
    CHECK(insn.ops[1].has_flag(ipp::PostIncrement)
          && insn.ops[1].value == 1
          && insn.ops[1].width == 1);

    insn = decode(0x601e7f67, 4);
    CHECK(insn.ops[0].reg == ipp::GP && insn.ops[1].reg == ipp::PC);

    insn = decode(0x0015, 2, 0xfffffffe);
    CHECK(insn.ops[0].kind == ipp::OperandKind::CodeAddress && insn.target == 0x12);
    CHECK(!insn.falls_through);

    insn = decode(0x0148, 2);
    CHECK(insn.predicate == 0 && insn.falls_through && insn.flow == ipp::Flow::Return);

    insn = decode(0x814f, 2);
    CHECK(insn.e_bit && insn.flow == ipp::Flow::Return);
    CHECK(ipp::format_insn(insn, nullptr).find("E=1 (raw)") != std::string::npos);
}

//--------------------------------------------------------------------
/// Odd addresses retain parcel lengths and raw E, but never yield instructions.
static void test_odd_addresses()
{
    CHECK(!ipp::valid_instruction(decode(0x014f, 2, 1)));
    for ( const std::pair<unsigned, unsigned> &item :
          {std::make_pair(0x014fu, 2u), std::make_pair(0x814fu, 2u),
           std::make_pair(0x60000007u, 4u), std::make_pair(0xe0000007u, 4u)} )
    {
        const ipp::Decoded odd = decode(item.first, item.second, 1);
        CHECK(odd.kind == ipp::Kind::Unresolved && odd.operand_count == 0 && !odd.has_target);
        CHECK(odd.length == item.second && odd.address == 1);
    }

    unsigned classification_errors = 0;
    for ( unsigned parcel = 0; parcel <= 0xffff; ++parcel )
    {
        const uint8_t raw[] = {static_cast<uint8_t>(parcel >> 8), static_cast<uint8_t>(parcel),
                               0xa5, 0x5a};
        const unsigned expected_length = (parcel & 0x6000) == 0x6000 ? 4 : 2;
        for ( uint32_t address : {1u, 0xffffffffu} )
        {
            const ipp::Decoded odd = ipp::decode_one(raw, sizeof(raw), address);
            if ( odd.kind != ipp::Kind::Unresolved
                 || odd.length != expected_length
                 || odd.address != address
                 || odd.e_bit != ((parcel & 0x8000) != 0)
                 || odd.has_target
                 || odd.operand_count != 0
                 || odd.form_index != ipp::NO_FORM
                 || !odd.has_mnemonic("unresolved") )
            {
                ++classification_errors;
            }
        }
    }
    CHECK(classification_errors == 0);

    const uint8_t stream[] = {0x01, 0x4f, 0x60, 0x00, 0x80, 0x07, 0xff};
    const std::vector<ipp::Decoded> items = ipp::decode_linear(stream, sizeof(stream), 1);
    size_t decoded_bytes = 0;
    for ( const ipp::Decoded &item : items )
    {
        CHECK(item.kind == ipp::Kind::Unresolved && !item.has_target && item.operand_count == 0);
        CHECK(item.address == 1 + decoded_bytes);
        decoded_bytes += item.length;
    }
    CHECK(items.size() == 3 && decoded_bytes == sizeof(stream));
    CHECK(items[0].length == 2 && items[1].length == 4 && items[2].length == 1);
    CHECK(items[2].e_bit);

    const uint8_t truncated[] = {0xe0, 0x00, 0x00, 0x07};
    for ( size_t count = 0; count < 4; ++count )
    {
        const ipp::Decoded item = ipp::decode_one(truncated, count, 1);
        CHECK(item.kind == ipp::Kind::Unresolved && item.length == count && item.address == 1);
        CHECK(item.e_bit == (count != 0) && !item.has_target && item.operand_count == 0);
    }
    std::printf("odd-address classification cases=131072 errors=%u; linear bytes=%zu\n",
                classification_errors, decoded_bytes);
}

//--------------------------------------------------------------------
static void test_invalid_records()
{
    CHECK(!ipp::valid_instruction(decode(0x60, 1)));
    CHECK(!ipp::valid_instruction(decode(0x6000, 2)));
    CHECK(!ipp::valid_instruction(decode(0x600000, 3)));
    CHECK(!ipp::valid_instruction(decode(0xfffffff7, 4)));
    CHECK(decode(0xfffffff7, 4).e_bit);

    ipp::Decoded insn = decode(0x014f, 2);
    insn.operand_count = 8;
    CHECK(!ipp::valid_instruction(insn) && ipp::register_accesses(insn).empty());

    insn = decode(0x014f, 2);
    insn.mnemonic = nullptr;
    CHECK(!ipp::valid_instruction(insn) && ipp::register_accesses(insn).empty());

    insn = decode(0x014f, 2);
    insn.ops[0].reg = ipp::RegisterCount;
    CHECK(!ipp::valid_instruction(insn));
}

//--------------------------------------------------------------------
static void test_operand_access_policies()
{
    ipp::Decoded insn = decode(0x61027ec7, 4); // Fig.634: vcmpeqb R1,R2 -> VC flags, no GPR output
    CHECK(text_equals(insn.mnemonic, "vcmpeqb"));
    CHECK(insn.ops[0].access == ipp::Read && insn.ops[1].access == ipp::Read);
    CHECK(access_to(insn, 1, 0, 32) == ipp::Read);
    for ( unsigned bit = 16; bit < 20; ++bit )
        CHECK(access_to(insn, ipp::CFR, bit, 1) == ipp::Write);

    insn = decode(0x6040f007, 4); // Fig.616: immediate vector compare
    CHECK(insn.ops[0].access == ipp::Read);
    CHECK(access_to(insn, ipp::CFR, 16, 1) == ipp::Write);

    insn = decode(0x66037f0f, 4); // movcf C0,C1,C1,C3
    CHECK(text_equals(insn.mnemonic, "movcf"));
    CHECK(insn.ops[0].access == ipp::Write && insn.ops[1].access == ipp::Read);
    CHECK(insn.ops[2].access == ipp::Write && insn.ops[3].access == ipp::Read);

    insn = decode(0x61024107, 4); // Fig.271: addc R0,R1,R2; C0 input and carry output
    CHECK(text_equals(insn.mnemonic, "addc"));
    CHECK(access_to(insn, ipp::CFR, 0, 1) == ipp::ReadWrite);
    CHECK(access_to(insn, ipp::CFR, 1, 1) == ipp::Write);
    CHECK(access_to(insn, ipp::CFR, 8, 1) == ipp::ReadWrite);

    insn = decode(0x61a2d087, 4); // extw M0,R2,R1
    CHECK(text_equals(insn.mnemonic, "extw"));
    CHECK(insn.ops[0].access == ipp::Write
          && insn.ops[1].access == ipp::Write
          && insn.ops[2].access == ipp::Read);

    for ( uint32_t word : {0x1671u, 0x61017f47u} )
    {
        insn = decode(word, word <= 0xffff ? 2 : 4); // mov MH0,R1
        CHECK(insn.ops[0].access == ipp::Write && insn.ops[1].access == ipp::Read);
        CHECK(access_to(insn, 1, 0, 32) == ipp::Read);
        CHECK(access_to(insn, ipp::M0, 32, 32) == ipp::Write);
    }

    insn = decode(0x61a2001f, 4); // mul M0,R3,R1,R2
    CHECK(insn.ops[0].access == ipp::Write && insn.ops[1].access == ipp::Write);
    CHECK(insn.ops[2].access == ipp::Read && insn.ops[3].access == ipp::Read);
    CHECK(access_to(insn, ipp::M0, 0, 64) == ipp::Write);
}

//--------------------------------------------------------------------
/// Multiply result fields numbered R30/R31 are discarded rather than written.
static void test_discarded_destinations()
{
    ipp::Decoded insn;
    for ( unsigned sink : {30u, 31u} )
    {
        insn = decode(0x61a20007 | (sink << 3), 4);
        CHECK(insn.ops[1].reg == sink && insn.ops[1].access == ipp::NoAccess);
        CHECK(insn.ops[1].has_flag(ipp::DiscardSpecialDestination));
        CHECK(access_to(insn, static_cast<uint16_t>(sink), 0, 32) == 0);
    }

    insn = decode(0x7fa200ff, 4); // SP is a real source despite the discarded SP output
    CHECK(insn.ops[1].access == ipp::NoAccess && access_to(insn, ipp::SP, 0, 32) == ipp::Read);

    insn = decode(0x61a23cf7, 4); // paired R30:R31 output is also discarded
    CHECK(insn.ops[1].kind == ipp::OperandKind::RegisterRange
          && insn.ops[1].access == ipp::NoAccess);
    CHECK(access_to(insn, ipp::GP, 0, 32) == 0 && access_to(insn, ipp::SP, 0, 32) == 0);

    insn = decode(0x61bfd087, 4); // extw really writes SP: no blanket GPR filter
    CHECK(insn.ops[1].reg == ipp::SP && insn.ops[1].access == ipp::Write);
}

//--------------------------------------------------------------------
static void test_implicit_effects()
{
    ipp::Decoded insn = decode(0x61a2081f, 4); // fmulhh: fixed point mode input and sticky overflow
    CHECK(access_to(insn, ipp::PSR, 29, 1) == ipp::Read);
    CHECK(access_to(insn, ipp::CFR, 9, 1) == ipp::ReadWrite);

    insn = decode(0x61c2c507, 4); // floating fmul is not fixed-point fmulhh
    CHECK(access_to(insn, ipp::PSR, 29, 1) == 0 && access_to(insn, ipp::CFR, 9, 1) == 0);

    insn = decode(0x61024507, 4); // addvh sticky OVS
    CHECK(access_to(insn, ipp::CFR, 9, 1) == ipp::ReadWrite);

    insn = decode(0x61024207, 4); // adds is a halving add, not saturating addvh
    CHECK(access_to(insn, ipp::CFR, 9, 1) == 0);

    insn = decode(0x61024707, 4);
    CHECK(access_to(insn, ipp::CFR, 24, 5) == ipp::Read);

    insn = decode(0x61a2c807, 4); // valn has a dynamic ALN input
    CHECK(access_to(insn, ipp::CFR, 30, 2) == ipp::Read);

    insn = decode(0x61a2c907, 4); // valn1 uses a fixed alignment
    CHECK(access_to(insn, ipp::CFR, 30, 2) == 0);

    insn = decode(0x61027c07, 4); // vaddhvc reads VC2, not the entire VC bank
    CHECK(access_to(insn, ipp::CFR, 18, 1) == ipp::Read);
    CHECK(access_to(insn, ipp::CFR, 16, 1) == 0 && access_to(insn, ipp::CFR, 19, 1) == 0);

    insn = decode(0x61027907, 4); // vasubb produces four sign flags
    for ( unsigned bit = 16; bit < 20; ++bit )
        CHECK(access_to(insn, ipp::CFR, bit, 1) == ipp::Write);

    insn = decode(0x61a2c707, 4); // vabssumb consumes those sign flags
    for ( unsigned bit = 16; bit < 20; ++bit )
        CHECK(access_to(insn, ipp::CFR, bit, 1) == ipp::Read);
}

//--------------------------------------------------------------------
static void test_floating_point_forms()
{
    ipp::Decoded insn = decode(0x60c2d12f, 4); // libm:fmax, 0x573e
    CHECK(insn.ops[0].access == ipp::ReadWrite && insn.ops[1].access == ipp::Read);
    CHECK(access_to(insn, ipp::XD0 + 1, 0, 64) == ipp::ReadWrite);

    const std::vector<std::pair<uint32_t, const char *>> multiply_add_samples = {
        {0x64c6de07, "fmadd"},
        {0x6ac6ded7, "fmsub"},
        {0x62c6dc0f, "fnmadd"},
        {0x63c2df8f, "fnmsub"},
    };
    for ( const std::pair<uint32_t, const char *> &sample : multiply_add_samples )
    {
        insn = decode(sample.first, 4);
        CHECK(text_equals(insn.mnemonic, sample.second));
        CHECK(insn.operand_count == 4 && insn.ops[0].access == ipp::Write);
        CHECK(insn.ops[1].access == ipp::Read
              && insn.ops[2].access == ipp::Read
              && insn.ops[3].access == ipp::Read);
        CHECK(insn.semantic_evidence != nullptr);
    }

    insn = decode(0x63c2df8f, 4); // libm:fma 0x5952, formerly false FD17 destination
    CHECK(insn.ops[0].reg == ipp::FD0 && insn.ops[1].reg == ipp::FD0 + 3);
    CHECK(insn.ops[2].reg == ipp::FD0 + 2 && insn.ops[3].reg == ipp::FD0 + 3);

    insn = decode(0x6ac6ded7, 4); // libm:fma 0x5986
    CHECK(insn.ops[0].reg == ipp::FD0 + 10 && insn.ops[3].reg == ipp::FD0 + 2);

    insn = decode(0x60c1da8f, 4); // uint64 conversion: GPR words -> odd FD3
    CHECK(text_equals(insn.mnemonic, "fmovp")
          && text_equals(ipp::form_table()[insn.form_index].id, "gcc-783"));
    CHECK(insn.ops[0].reg == ipp::FD0 + 3 && insn.ops[0].access == ipp::Write);
    CHECK(insn.ops[1].reg == 0 && insn.ops[2].reg == 1);
    CHECK(insn.ops[1].access == ipp::Read && insn.ops[2].access == ipp::Read);
    CHECK(insn.semantic_evidence != nullptr);

    insn = decode(0x70c0db07, 4); // reverse move of the result in FD1, not FD32
    CHECK(insn.ops[0].kind == ipp::OperandKind::RegisterRange);
    CHECK(insn.ops[0].reg == 0 && insn.ops[0].reg_end == 1 && insn.ops[0].access == ipp::Write);
    CHECK(insn.ops[1].reg == ipp::FD0 + 1 && insn.ops[1].access == ipp::Read);
    CHECK(!ipp::valid_instruction(decode(0x70c1db07, 4))); // unestablished nonzero unused field

    for ( unsigned raw = 0; raw < 32; ++raw )
    {
        insn = decode(0x60c0db07 | (raw << 24), 4);
        CHECK(insn.ops[1].reg == ipp::FD0 + ((raw & 15) << 1) + (raw >> 4));
    }
    for ( unsigned index = 0; index < 16; ++index )
    {
        insn = decode(0x62c3da87 | (index << 3), 4);
        CHECK(insn.ops[0].reg == ipp::FD0 + index * 2 + 1);
        CHECK(insn.ops[1].reg == 2 && insn.ops[2].reg == 3);
    }

    insn = decode(0x70e06007, 4); // ld R0,(R16+)0: base is read, not written
    CHECK(access_to(insn, 16, 0, 32) == ipp::Read);
}

//--------------------------------------------------------------------
static void test_system_state()
{
    ipp::Decoded insn = decode(0x60017f1f, 4); // pied privilege-state save
    CHECK(text_equals(ipp::form_table()[insn.form_index].id, "gcc-784")
          && insn.ops[0].reg == 1
          && insn.ops[1].reg == ipp::PSR);
    CHECK(insn.ops[0].access == ipp::Write && access_to(insn, ipp::PSR, 0, 32) == ipp::Read);
    CHECK(insn.semantic_evidence != nullptr);

    insn = decode(0x61127f1f, 4);
    CHECK(text_equals(ipp::form_table()[insn.form_index].id, "gcc-785")
          && insn.ops[0].reg == ipp::PSR
          && insn.ops[1].reg == 18);
    CHECK(insn.ops[0].access == ipp::Write && insn.ops[1].access == ipp::Read);

    for ( uint32_t word : {0x62057f8fu, 0x62057fafu} )
    {
        insn = decode(word, 4); // intd / inte
        CHECK(access_to(insn, ipp::PSR, 16, 1) == ipp::Write);
        CHECK(insn.semantic_evidence != nullptr);
    }

    insn = decode(0x076f, 2); // rti: bank selection depends on PSR.EH
    CHECK(insn.flow == ipp::Flow::Return && !insn.falls_through);
    CHECK(access_to(insn, ipp::PSR, 26, 1) == ipp::Read);
    CHECK(access_to(insn, ipp::PSR, 0, 32) == ipp::Write);
    for ( uint16_t reg :
          {uint16_t(ipp::IPC), uint16_t(ipp::IPSR), uint16_t(ipp::EPC), uint16_t(ipp::EPSR)} )
    {
        CHECK(access_to(insn, reg, 0, 32) == ipp::Read);
        bool conditional = false;
        for ( const ipp::RegisterAccess &effect : ipp::register_accesses(insn) )
        {
            if ( effect.storage.reg == reg )
                conditional |= effect.conservative;
        }
        CHECK(conditional);
    }

    for ( uint32_t word : {0x034fu, 0x064fu, 0x62007f8fu} )
    {
        insn = decode(word, word <= 0xffff ? 2 : 4); // pi1 / sc1 / pi1l
        CHECK(insn.flow == ipp::Flow::Trap && insn.falls_through && !insn.has_target);
        CHECK(insn.semantic_evidence != nullptr);
        CHECK(access_to(insn, ipp::LR, 0, 32) == 0 && access_to(insn, ipp::SVR, 0, 16) == 0);
        CHECK(access_to(insn, ipp::PC, 0, 32) == ipp::ReadWrite);
        if ( std::strncmp(insn.mnemonic, "pi", 2) == 0 )
        {
            CHECK(access_to(insn, ipp::PSR, 0, 32) == ipp::ReadWrite);
            CHECK(access_to(insn, ipp::IPSR, 0, 32) == ipp::Write);
        }
    }
}

//--------------------------------------------------------------------
static void test_loops_and_pc_effects()
{
    ipp::Decoded insn = decode(0x118f, 2); // narrow jloop uses implicit C6, Fig.231
    CHECK(text_equals(insn.mnemonic, "jloop") && insn.predicate == 6 && insn.falls_through);
    CHECK(insn.semantic_evidence != nullptr);
    CHECK(insn.ops[2].reg == ipp::TAR && insn.ops[2].access == ipp::Read);
    CHECK(insn.ops[3].access == ipp::ReadWrite);

    insn = decode(0x617f67ff, 4); // explicit c7 wide jloop has no conditional fallthrough
    CHECK(text_equals(insn.mnemonic, "jloop") && insn.predicate == 7 && !insn.falls_through);

    insn = decode(0x0801, 2);
    CHECK(access_to(insn, ipp::PC, 0, 32) == ipp::Read);
    CHECK(access_to(insn, ipp::TAR, 0, 32) == ipp::Write);

    insn = decode(0x014f, 2);
    CHECK(access_to(insn, ipp::PC, 0, 32) == ipp::Write);
}

//--------------------------------------------------------------------
static void test_far_call_resolution()
{
    ipp::Decoded high = decode(0x7700006f, 4, 0x1fee4);
    ipp::Decoded call = decode(0x760126ff, 4, 0x1fee8);
    CHECK(!call.has_target);
    CHECK(ipp::resolve_far_call(high, &call) && call.target == 0xf18a6);
    CHECK(call.ops[1].kind == ipp::OperandKind::CodeAddress);

    call = decode(0x760126ff, 4, 0x1feec);
    CHECK(!ipp::resolve_far_call(high, &call)); // not adjacent

    high = decode(0x77000068, 4, 0x1fee4);
    call = decode(0x760126ff, 4, 0x1fee8);
    CHECK(!ipp::resolve_far_call(high, &call)); // predicate mismatch

    high = decode(0xf700006f, 4, 0x1fee4);
    CHECK(!ipp::resolve_far_call(high, &call)); // unestablished E semantics

    high = decode(0x77060017, 4, 0x0800003e);
    call = decode(0x76043bef, 4, 0x08000042);
    CHECK(ipp::resolve_far_call(high, &call) && call.target == 0x38024f3c);

    const uint8_t far_pair[] = {0x77, 0x00, 0x00, 0x07, 0x76, 0x00, 0x04, 0x07};
    std::vector<ipp::Decoded> items = ipp::decode_linear(far_pair, sizeof(far_pair), 0x1000);
    CHECK(items.size() == 2 && items[1].has_target && items[1].target == 0x1104);

    items = ipp::decode_linear(far_pair, sizeof(far_pair), 0x1000, {0x1000});
    CHECK(items[1].has_target); // entry before the definition is valid

    for ( uint32_t entry : {0x1002u, 0x1004u} )
    {
        items = ipp::decode_linear(far_pair, sizeof(far_pair), 0x1000, {entry});
        CHECK(!items[1].has_target);
        CHECK(items[1].ops[1].kind == ipp::OperandKind::Immediate);
    }

    std::vector<uint8_t> entered(far_pair, far_pair + sizeof(far_pair));
    entered.insert(entered.end(), {0x67, 0x1f, 0x3f, 0xf7}); // br -4, to call
    items = ipp::decode_linear(entered.data(), entered.size(), 0x1000);
    CHECK(items.size() == 3 && items.back().target == 0x1004);
    CHECK(!items[1].has_target);

    entered.assign(far_pair, far_pair + sizeof(far_pair));
    entered.insert(entered.end(), {0x77, 0x1f, 0x3f, 0xff, 0x76, 0x0f, 0x3f, 0xe7});
    items = ipp::decode_linear(entered.data(), entered.size(), 0x1000);
    CHECK(items.size() == 4 && items[3].has_target && items[3].target == 0x1004);
    CHECK(!items[1].has_target); // a later folded call also establishes an entry

    const uint8_t self_call[] = {0x77, 0x00, 0x00, 0x07, 0x76, 0x00, 0x00, 0x07};
    items = ipp::decode_linear(self_call, sizeof(self_call), 0x1000);
    CHECK(!items[1].has_target); // the computed call is its own entry

    high = decode(0x77000007, 4, 0xfffffffc);
    call = decode(0x76000407, 4, 0);
    CHECK(!ipp::resolve_far_call(high, &call)); // adjacency cannot wrap

    high = decode(0x77000007, 4, 0xfffffffa);
    call = decode(0x76000407, 4, 0xfffffffe);
    CHECK(!ipp::resolve_far_call(high, &call)); // instruction extends beyond address space

    high = decode(0x77000007, 4, 0xfffffff8);
    call = decode(0x76000407, 4, 0xfffffffc);
    CHECK(ipp::resolve_far_call(high, &call) && call.target == 0xfc); // exact end is valid
}

//--------------------------------------------------------------------
static void test_absolute_call_in_linear_decode()
{
    // Actual normalized ippboot sequence at 0xd78: literal -> R0 -> LR.
    const uint8_t sequence[] = {0x60, 0x08, 0x9b, 0x67, 0x60, 0x10,
                                0xc0, 0x07, 0x15, 0x70, 0x00, 0x5f};
    std::vector<ipp::Decoded> items = ipp::decode_linear(sequence, sizeof(sequence), 0x80000d78);
    CHECK(items.size() == 4);
    CHECK(items.back().has_target && items.back().target == 0x8000436c);
    CHECK(items.back().ops[0].kind == ipp::OperandKind::Register
          && items.back().ops[0].reg == ipp::LR);
    CHECK(access_to(items.back(), ipp::LR, 0, 32) == ipp::ReadWrite);

    const uint8_t zero_target[] = {0x30, 0x00, 0x60, 0x00, 0xc0, 0x07, 0x15, 0x70, 0x00, 0x5f};
    items = ipp::decode_linear(zero_target, sizeof(zero_target), 0x1000);
    CHECK(items.size() == 4 && items.back().has_target && items.back().target == 0);

    items = ipp::decode_linear(sequence, sizeof(sequence), 0x1000, {0x1000});
    CHECK(items.back().has_target); // the first definition can itself be an entry

    for ( uint32_t entry : {0x1002u, 0x1004u, 0x1006u, 0x1008u, 0x100au} )
    {
        items = ipp::decode_linear(sequence, sizeof(sequence), 0x1000, {entry});
        CHECK(!items.back().has_target);
    }

    std::vector<uint8_t> branch_entry(sequence, sequence + sizeof(sequence));
    branch_entry.insert(branch_entry.end(),
                        {0x67, 0x1f, 0x3f, 0xe7}); // br -8, to the high definition
    items = ipp::decode_linear(branch_entry.data(), branch_entry.size(), 0x1000);
    CHECK(items.size() == 5 && items.back().target == 0x1004);
    CHECK(!items[3].has_target);
}

//--------------------------------------------------------------------
/// Encode "mov Ra,value" and "sethi Ra,value" with every field position exercised.
static uint32_t encode_literal(uint32_t opcode, unsigned reg, uint32_t value)
{
    return opcode | (reg << 24) | ((value >> 11) << 16) | ((value & 0x7ff) << 3);
}

//--------------------------------------------------------------------
static void test_absolute_call_resolution()
{
    unsigned encoded_cases = 0;
    for ( unsigned reg = 0; reg < 32; ++reg )
    {
        for ( uint32_t upper : {0u, 1u, 0x7fffu, 0x8000u, 0xffffu} )
        {
            for ( int32_t lower : {-32768, -1, 0, 1, 127, 128, 32767} )
            {
                const uint32_t bits = static_cast<uint16_t>(lower);
                const ipp::Decoded low = decode(encode_literal(0x60008007u, reg, bits), 4, 0x1000);
                const ipp::Decoded high =
                    decode(encode_literal(0x6000c007u, reg, upper), 4, 0x1004);
                const ipp::Decoded copy = reg < 16 ? decode(0x1570u | reg, 2, 0x1008)
                                                   : decode(0x61007f0fu | (reg << 16), 4, 0x1008);
                ipp::Decoded call = decode(0x005f, 2, copy.address + copy.length);
                const ipp::Decoded original = call;
                CHECK(ipp::resolve_absolute_call(low, high, copy, &call));
                CHECK(call.has_target && call.target == (upper << 16 | bits));
                CHECK(call.ops[0].kind == original.ops[0].kind
                      && call.ops[0].reg == original.ops[0].reg);
                CHECK(call.flow == original.flow && call.falls_through == original.falls_through);
                CHECK(access_to(call, ipp::LR, 0, 32) == access_to(original, ipp::LR, 0, 32));
                ++encoded_cases;
            }
        }
    }

    const ipp::Decoded low = decode(0x60089b67, 4, 0x1000);
    const ipp::Decoded high = decode(0x6010c007, 4, 0x1004);
    ipp::Decoded copy = decode(0x1570, 2, 0x1008);
    ipp::Decoded call =
        decode(0x0058, 2, 0x100a); // conditional call still has the same known LR value
    CHECK(ipp::resolve_absolute_call(low, high, copy, &call) && call.predicate == 0);
    CHECK(!ipp::resolve_absolute_call(low, high, copy, nullptr));

    for ( unsigned changed = 0; changed < 4; ++changed )
    {
        ipp::Decoded a = low;
        ipp::Decoded b = high;
        ipp::Decoded c = copy;
        ipp::Decoded d = decode(0x005f, 2, 0x100a);
        ipp::Decoded *items[] = {&a, &b, &c, &d};
        items[changed]->e_bit = true;
        CHECK(!ipp::resolve_absolute_call(a, b, c, &d));
    }
    for ( unsigned changed = 0; changed < 3; ++changed )
    {
        ipp::Decoded a = low;
        ipp::Decoded b = high;
        ipp::Decoded c = copy;
        ipp::Decoded d = decode(0x005f, 2, 0x100a);
        ipp::Decoded *items[] = {&a, &b, &c};
        items[changed]->predicate = 0;
        CHECK(!ipp::resolve_absolute_call(a, b, c, &d));
    }

    call = decode(0x005f, 2, 0x100c);
    CHECK(!ipp::resolve_absolute_call(low, high, copy, &call));

    copy = decode(0x1571, 2, 0x1008);
    call = decode(0x005f, 2, 0x100a);
    CHECK(!ipp::resolve_absolute_call(low, high, copy, &call));

    std::printf("absolute LR call encoded cases: %u\n", encoded_cases);
}

//--------------------------------------------------------------------
static void test_shift_counts()
{
    unsigned compact_cases = 0;
    for ( unsigned right = 0; right < 2; ++right )
    {
        for ( unsigned e = 0; e < 2; ++e )
        {
            for ( unsigned reg = 0; reg < 16; ++reg )
            {
                for ( unsigned field = 0; field < 16; ++field )
                {
                    const ipp::Decoded insn =
                        decode(0x10a0u | (right << 4) | (reg << 8) | field | (e << 15), 2);
                    const unsigned count = field != 0 ? field : 16;
                    CHECK(insn.kind == ipp::Kind::Insn
                          && insn.length == 2
                          && insn.operand_count == 2);
                    CHECK(text_equals(insn.mnemonic, right != 0 ? "asr" : "asl"));
                    CHECK(insn.predicate == 7 && insn.e_bit == (e != 0));
                    CHECK(insn.ops[0].kind == ipp::OperandKind::Register
                          && insn.ops[0].reg == ipp::R0 + reg);
                    CHECK(insn.ops[1].kind == ipp::OperandKind::Immediate
                          && insn.ops[1].value == static_cast<int>(count));
                    const std::string expected =
                        "R" + std::to_string(reg) + "," + std::to_string(count) + ", c7";
                    CHECK(expected == insn.operands);
                    if ( field == 0 )
                    {
                        CHECK(text_equals(insn.semantic_evidence,
                                          right != 0 ? "US20040078549A1:Fig431"
                                                     : "US20040078549A1:Fig424"));
                    }
                    ++compact_cases;
                }
            }
        }
    }

    // Wide I5 uses all 32 values, including a genuine zero, independently of the
    // compact exception. Exercise every count, predicate and raw E value.
    unsigned wide_cases = 0;
    for ( unsigned right = 0; right < 2; ++right )
    {
        for ( unsigned e = 0; e < 2; ++e )
        {
            for ( unsigned predicate = 0; predicate < 8; ++predicate )
            {
                for ( unsigned count = 0; count < 32; ++count )
                {
                    const ipp::Decoded insn = decode(
                        0x60602800u | (right << 9) | (count << 3) | predicate | (e << 31), 4);
                    CHECK(insn.kind == ipp::Kind::Insn
                          && insn.length == 4
                          && insn.operand_count == 3);
                    CHECK(text_equals(insn.mnemonic, right != 0 ? "asr" : "asl"));
                    CHECK(insn.predicate == predicate && insn.e_bit == (e != 0));
                    CHECK(insn.ops[2].kind == ipp::OperandKind::Immediate
                          && insn.ops[2].value == static_cast<int>(count));
                    ++wide_cases;
                }
            }
        }
    }
    std::printf("compact shift cases: %u; wide shift count controls: %u\n", compact_cases,
                wide_cases);
}

//--------------------------------------------------------------------
static void test_image_rejects_null_input()
{
    ipp::Image empty;
    CHECK(!empty.load_bytes(nullptr, 0, "empty"));
    CHECK(!empty.load_bytes(nullptr, 4, "null"));
}

//--------------------------------------------------------------------
int main()
{
    test_compact_memory_forms();
    test_register_known_bits();
    test_cfr_access_masks();
    test_c7_is_never_a_dependency();
    test_stack_pointer_deltas();
    test_register_lookup_and_slices();
    test_floating_point_aliases();
    test_memory_and_flow_operands();
    test_odd_addresses();
    test_invalid_records();
    test_operand_access_policies();
    test_discarded_destinations();
    test_implicit_effects();
    test_floating_point_forms();
    test_system_state();
    test_loops_and_pc_effects();
    test_far_call_resolution();
    test_absolute_call_in_linear_decode();
    test_absolute_call_resolution();
    test_shift_counts();
    test_image_rejects_null_input();

    std::printf("typed operands, register aliases, invalid bytes, predicates, far calls: %s\n",
                ipp::test::failure_count != 0 ? "FAILED" : "PASS");
    return ipp::test::failure_count != 0 ? 1 : 0;
}
