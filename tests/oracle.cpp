// Oracle test: the form table, the length model, and decoding of the supplied
// libc, ld-elf, aencode and libm images against independently known facts.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "ipp/decode.hpp"
#include "ipp/elf.hpp"

#include "support/check.hpp"

using ipp::test::text_equals;

namespace
{

/// How a decoded extent's bytes divide up, and whether it tiles exactly.
struct byte_partition_t
{
    uint32_t sum = 0;
    uint32_t instruction_bytes = 0;
    uint32_t noncode_bytes = 0;
    uint32_t unresolved_bytes = 0;
    bool overlap_or_gap = false;
};

/// The exact instruction sequence expected in a small section.
struct expected_frame_t
{
    const char *section;
    uint32_t size;
    std::vector<const char *> mnemonics;
    std::vector<uint32_t> lengths;
    uint32_t brl_address;
    uint32_t brl_target;
    uint32_t brl_lr_address;
    uint32_t brl_lr_target;
};

} // namespace

//--------------------------------------------------------------------
template<size_t N>
static ipp::Decoded decode_array(const uint8_t (&bytes)[N], uint32_t address)
{
    return ipp::decode_one(bytes, N, address);
}

//--------------------------------------------------------------------
static std::string base_name(const ipp::Image &image)
{
    return std::filesystem::path(image.label()).filename().string();
}

//--------------------------------------------------------------------
static byte_partition_t partition_bytes(const std::vector<ipp::Decoded> &insns, uint32_t size)
{
    byte_partition_t partition;
    bool first = true;
    uint32_t previous_end = 0;
    for ( const ipp::Decoded &insn : insns )
    {
        if ( insn.length == 0 )
            partition.overlap_or_gap = true;
        if ( !first && insn.address != previous_end )
            partition.overlap_or_gap = true;
        first = false;
        previous_end = insn.address + insn.length;
        partition.sum += insn.length;
        if ( insn.kind == ipp::Kind::Insn )
            partition.instruction_bytes += insn.length;
        else if ( insn.kind == ipp::Kind::NonCode )
            partition.noncode_bytes += insn.length;
        else
            partition.unresolved_bytes += insn.length;
    }
    if ( partition.sum != size )
        partition.overlap_or_gap = true;
    if ( partition.instruction_bytes + partition.noncode_bytes + partition.unresolved_bytes
         != size )
    {
        partition.overlap_or_gap = true;
    }
    return partition;
}

//--------------------------------------------------------------------
static bool evidence_present(const char *id)
{
    const ipp::Form *forms = ipp::form_table();
    for ( size_t i = 0; i < ipp::form_count(); ++i )
    {
        if ( std::strcmp(forms[i].evidence, id) == 0 )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------
static void check_forms()
{
    std::set<std::string> ids;
    const ipp::Form *forms = ipp::form_table();
    CHECK(ipp::form_count() > 0);
    for ( size_t i = 0; i < ipp::form_count(); ++i )
    {
        const ipp::Form &form = forms[i];
        CHECK(form.id != nullptr && form.id[0] != 0);
        CHECK(form.mnemonic != nullptr && form.mnemonic[0] != 0);
        CHECK(form.evidence != nullptr && form.evidence[0] != 0);
        CHECK(ids.insert(form.id).second);
        CHECK(form.kind == ipp::Kind::Insn || form.kind == ipp::Kind::NonCode);
    }

    // 758 platinum InstructionDecode rules, then 26 GCC supplemental encodings.
    CHECK(ipp::form_count() == 784);
    int v8_count = 0;
    int gcc_count = 0;
    for ( size_t i = 0; i < ipp::form_count(); ++i )
    {
        const std::string_view evidence = forms[i].evidence;
        const bool from_v8 = evidence.compare(0, 3, "v8-") == 0;
        CHECK(from_v8 || evidence == "gcc-supplement");
        if ( from_v8 )
            ++v8_count;
        else
            ++gcc_count;
    }
    CHECK(v8_count == 758);
    CHECK(gcc_count == 26);
    CHECK(std::strncmp(forms[0].evidence, "v8-", 3) == 0);
    CHECK(text_equals(forms[758].id, "gcc-758"));
    CHECK(text_equals(forms[758].mnemonic, "br"));
    CHECK(forms[758].width == ipp::Width::W16);
    CHECK(forms[758].mask == 0x78c0u);
    CHECK(forms[758].match == 0u);
    CHECK(forms[758].flow == ipp::Flow::Branch);
    CHECK(text_equals(forms[780].id, "gcc-782"));
    CHECK(text_equals(forms[780].mnemonic, "fnmsub"));

    const char *required_evidence[] = {
        "gcc-supplement", "v8-009fb372", "v8-009fb3a2", "v8-009fbae4", "v8-009fbb42",
        "v8-009fbbda",    "v8-009fbd88", "v8-009fbe0a", "v8-009fbe6a", "v8-009fbf2a",
        "v8-009fc1ca",    "v8-009fcad4", "v8-009fd086", "v8-009fd0be", "v8-009fd40a",
        "v8-009fd4c2",    "v8-009fd6d4", "v8-009fd734", "v8-00a1184c",
    };
    for ( const char *id : required_evidence )
        CHECK(evidence_present(id));
}

//--------------------------------------------------------------------
static void check_return_and_length_model()
{
    const uint8_t ret[] = {0x01, 0x4f};
    ipp::Decoded insn = decode_array(ret, 0x3bfdc);
    CHECK(insn.length == 2);
    CHECK(insn.kind == ipp::Kind::Insn);
    CHECK(insn.flow == ipp::Flow::Return);
    CHECK(text_equals(insn.mnemonic, "jmpr"));
    CHECK(text_equals(insn.evidence, "v8-009fb3a2"));
    CHECK(text_equals(insn.operands, "LR, c7"));
    CHECK(!insn.falls_through);
    CHECK(!insn.has_target);
    CHECK(ipp::format_insn(insn, ret) == "0003bfdc  014f  len=2  jmpr LR, c7  return");

    // Top nibbles 6/7/E/F are 32-bit. A short buffer stays unresolved.
    const uint8_t nibble7[] = {0x70, 0x00};
    insn = decode_array(nibble7, 0);
    CHECK(insn.length == 2);
    CHECK(insn.kind == ipp::Kind::Unresolved);

    const uint8_t short_wide[] = {0x68, 0x00, 0x04};
    insn = decode_array(short_wide, 0);
    CHECK(insn.length == 3);
    CHECK(insn.kind == ipp::Kind::Unresolved);

    const uint8_t one[] = {0x01};
    insn = decode_array(one, 0);
    CHECK(insn.length == 1);
    CHECK(insn.kind == ipp::Kind::Unresolved);

    // 6fff0000 is 32-bit ldbu. 70000000 is dbgm3. Neither is a 16-bit pair.
    const uint8_t ldbu[] = {0x6f, 0xff, 0x00, 0x00};
    insn = decode_array(ldbu, 0);
    CHECK(insn.length == 4);
    CHECK(insn.kind == ipp::Kind::Insn);
    CHECK(text_equals(insn.mnemonic, "ldbu"));
    CHECK(text_equals(insn.evidence, "v8-00a1184c"));

    const uint8_t dbgm[] = {0x70, 0x00, 0x00, 0x00};
    insn = decode_array(dbgm, 0);
    CHECK(insn.length == 4);
    CHECK(text_equals(insn.mnemonic, "dbgm3"));
    CHECK(text_equals(insn.evidence, "v8-009fd4c2"));
}

//--------------------------------------------------------------------
static void check_calls()
{
    // brl writes LR. It is a call, and the next instruction stays live.
    const uint8_t brl_ae[] = {0x68, 0x00, 0x04, 0xc7};
    ipp::Decoded insn = decode_array(brl_ae, 0x08000010);
    CHECK(insn.length == 4);
    CHECK(insn.flow == ipp::Flow::Call);
    CHECK(text_equals(insn.mnemonic, "brl"));
    CHECK(text_equals(insn.evidence, "v8-009fd40a"));
    CHECK(insn.has_target);
    CHECK(insn.target == 0x08000140);
    CHECK(insn.falls_through);
    CHECK(text_equals(insn.operands, "0x08000140, c7"));
    CHECK(ipp::format_insn(insn, brl_ae) == "08000010  680004c7  len=4  brl 0x08000140, c7  call");

    // libc .init: 68082987 calls 0x28940 and falls through into sethi.
    const uint8_t brl_init[] = {0x68, 0x08, 0x29, 0x87};
    insn = decode_array(brl_init, 0x1fee0);
    CHECK(insn.length == 4);
    CHECK(insn.flow == ipp::Flow::Call);
    CHECK(text_equals(insn.mnemonic, "brl"));
    CHECK(text_equals(insn.evidence, "v8-009fd40a"));
    CHECK(insn.has_target);
    CHECK(insn.target == 0x28940);
    CHECK(insn.falls_through);
    CHECK(text_equals(insn.operands, "0x00028940, c7"));
    CHECK(ipp::format_insn(insn, brl_init)
          == "0001fee0  68082987  len=4  brl 0x00028940, c7  call");

    const uint8_t sethi[] = {0x77, 0x00, 0x00, 0x6f};
    insn = decode_array(sethi, 0x1fee4);
    CHECK(insn.length == 4);
    CHECK(insn.flow == ipp::Flow::Sequential);
    CHECK(text_equals(insn.mnemonic, "sethi"));
    CHECK(text_equals(insn.evidence, "v8-009fd734"));
    CHECK(!insn.has_target);
    CHECK(text_equals(insn.operands, "LR,13, c7"));
    CHECK(ipp::format_insn(insn, sethi)
          == "0001fee4  7700006f  len=4  sethi LR,13, c7  sequential");

    // brl LR links LR and falls through. The low half is not a PC target.
    const uint8_t brl_lr[] = {0x76, 0x01, 0x26, 0xff};
    insn = decode_array(brl_lr, 0x1fee8);
    CHECK(insn.length == 4);
    CHECK(insn.flow == ipp::Flow::Call);
    CHECK(insn.falls_through);
    CHECK(text_equals(insn.mnemonic, "brl"));
    CHECK(text_equals(insn.evidence, "v8-009fd6d4"));
    CHECK(!insn.has_target);
    CHECK(text_equals(insn.operands, "LR,6590, c7"));
    CHECK(ipp::format_insn(insn, brl_lr) == "0001fee8  760126ff  len=4  brl LR,6590, c7  call");

    // br does not write LR. Predicate 7 does not fall through.
    const uint8_t br_only[] = {0x60, 0x00, 0x00, 0x07};
    insn = decode_array(br_only, 0x1000);
    CHECK(text_equals(insn.mnemonic, "br"));
    CHECK(insn.flow == ipp::Flow::Branch);
    CHECK(insn.has_target);
    CHECK(!insn.falls_through);
}

//--------------------------------------------------------------------
static void check_compact_data_forms()
{
    const uint8_t cmpne[] = {0x20, 0x30};
    ipp::Decoded insn = decode_array(cmpne, 0x1fed4);
    CHECK(text_equals(insn.mnemonic, "cmpne"));
    CHECK(text_equals(insn.evidence, "v8-009fc1ca"));
    CHECK(text_equals(insn.operands, "C6,R0,R0, c7"));

    const uint8_t ldp[] = {0x40, 0xe0};
    insn = decode_array(ldp, 0x1feec);
    CHECK(text_equals(insn.mnemonic, "ldp"));
    CHECK(text_equals(insn.evidence, "v8-009fd0be"));
    CHECK(text_equals(insn.operands, "LR:SVR,(SP,0), c7"));

    const uint8_t stp[] = {0x40, 0xe1};
    insn = decode_array(stp, 0x1fed2);
    CHECK(text_equals(insn.mnemonic, "stp"));
    CHECK(text_equals(insn.evidence, "v8-009fd086"));
    CHECK(text_equals(insn.operands, "(SP,0),LR:SVR, c7"));

    const uint8_t add_m8[] = {0x0f, 0x5f};
    insn = decode_array(add_m8, 0x1fed0);
    CHECK(text_equals(insn.mnemonic, "add"));
    CHECK(text_equals(insn.evidence, "v8-009fbb42"));
    CHECK(text_equals(insn.operands, "SP,-8, c7"));
    CHECK(ipp::format_insn(insn, add_m8) == "0001fed0  0f5f  len=2  add SP,-8, c7  sequential");

    const uint8_t add_p8[] = {0x08, 0x41};
    insn = decode_array(add_p8, 0x1feee);
    CHECK(text_equals(insn.mnemonic, "add"));
    CHECK(text_equals(insn.operands, "SP,8, c7"));

    const uint8_t add_0[] = {0x08, 0x40};
    insn = decode_array(add_0, 0);
    CHECK(insn.kind == ipp::Kind::Insn);
    CHECK(text_equals(insn.mnemonic, "add"));
    CHECK(text_equals(insn.operands, "SP,0, c7"));

    const uint8_t add3[] = {0x00, 0x80};
    insn = decode_array(add3, 0);
    CHECK(text_equals(insn.mnemonic, "add"));
    CHECK(text_equals(insn.evidence, "v8-009fbbda"));
    CHECK(text_equals(insn.operands, "R0,R0,R0, c7"));

    const uint8_t rsub[] = {0x10, 0x90};
    insn = decode_array(rsub, 0);
    CHECK(text_equals(insn.mnemonic, "rsub"));
    CHECK(text_equals(insn.evidence, "v8-009fcad4"));
    CHECK(text_equals(insn.operands, "R0,0, c7"));

    const uint8_t jmp[] = {0x00, 0x40};
    insn = decode_array(jmp, 0);
    CHECK(text_equals(insn.mnemonic, "jmp"));
    CHECK(text_equals(insn.evidence, "v8-009fb372"));
    CHECK(text_equals(insn.operands, "TAR, c0"));
    CHECK(insn.flow == ipp::Flow::Branch);
    CHECK(!insn.has_target);
    CHECK(insn.falls_through);

    const uint8_t mov[] = {0x3b, 0x01};
    insn = decode_array(mov, 0);
    CHECK(text_equals(insn.mnemonic, "mov"));
    CHECK(text_equals(insn.evidence, "v8-009fbd88"));
    CHECK(text_equals(insn.operands, "R11,1, c7"));

    const uint8_t and_op[] = {0x10, 0x02};
    insn = decode_array(and_op, 0);
    CHECK(text_equals(insn.mnemonic, "and"));
    CHECK(text_equals(insn.evidence, "v8-009fbe0a"));
    CHECK(text_equals(insn.operands, "R0,R2, c7"));

    const uint8_t and2[] = {0x11, 0x03};
    insn = decode_array(and2, 0);
    CHECK(text_equals(insn.mnemonic, "and"));
    CHECK(text_equals(insn.evidence, "v8-009fbe0a"));

    const uint8_t or_op[] = {0x10, 0x12};
    insn = decode_array(or_op, 0);
    CHECK(text_equals(insn.mnemonic, "or"));
    CHECK(text_equals(insn.evidence, "v8-009fbe6a"));

    const uint8_t xor_op[] = {0x10, 0x32};
    insn = decode_array(xor_op, 0);
    CHECK(text_equals(insn.mnemonic, "xor"));
    CHECK(text_equals(insn.evidence, "v8-009fbf2a"));

    const uint8_t nop[] = {0x07, 0x7f};
    insn = decode_array(nop, 0);
    CHECK(insn.kind == ipp::Kind::Insn);
    CHECK(insn.length == 2);
    CHECK(text_equals(insn.mnemonic, "nop"));
    CHECK(text_equals(insn.evidence, "v8-009fbae4"));
    CHECK(text_equals(insn.operands, "c7"));
}

//--------------------------------------------------------------------
static void check_gcc_supplemental_forms()
{
    // 0000 is the GCC 16-bit br. Bit 0 clear selects [c6]; the displacement is 0.
    const uint8_t br0[] = {0x00, 0x00};
    ipp::Decoded insn = decode_array(br0, 0x1fed6);
    CHECK(insn.kind == ipp::Kind::Insn);
    CHECK(insn.length == 2);
    CHECK(text_equals(insn.mnemonic, "br"));
    CHECK(text_equals(insn.evidence, "gcc-supplement"));
    CHECK(insn.flow == ipp::Flow::Branch);
    CHECK(insn.has_target);
    CHECK(insn.target == 0x1fed6);
    CHECK(insn.falls_through);
    CHECK(text_equals(insn.operands, "0x0001fed6, c6"));
    CHECK(ipp::format_insn(insn, br0) == "0001fed6  0000  len=2  br 0x0001fed6, c6  branch");

    // libc .text 0x28b48 is [c7] br +20.
    const uint8_t br_nz[] = {0x00, 0x15};
    insn = decode_array(br_nz, 0x28b48);
    CHECK(text_equals(insn.mnemonic, "br"));
    CHECK(text_equals(insn.evidence, "gcc-supplement"));
    CHECK(insn.flow == ipp::Flow::Branch);
    CHECK(insn.has_target);
    CHECK(insn.target == 0x28b5c);
    CHECK(!insn.falls_through);
    CHECK(text_equals(insn.operands, "0x00028b5c, c7"));
    CHECK(ipp::format_insn(insn, br_nz) == "00028b48  0015  len=2  br 0x00028b5c, c7  branch");

    const uint8_t mov_pc[] = {0x60, 0x1e, 0x7f, 0x67};
    insn = decode_array(mov_pc, 0x288b0);
    CHECK(text_equals(insn.mnemonic, "mov"));
    CHECK(text_equals(insn.evidence, "gcc-supplement"));
    CHECK(insn.flow == ipp::Flow::Sequential);
    CHECK(!insn.has_target);
    CHECK(text_equals(insn.operands, "R30,PC, c7"));

    const uint8_t jmp_memory[] = {0x60, 0xfd, 0x98, 0x07};
    insn = decode_array(jmp_memory, 0);
    CHECK(text_equals(insn.mnemonic, "jmp"));
    CHECK(text_equals(insn.evidence, "gcc-supplement"));
    CHECK(insn.flow == ipp::Flow::Branch);
    CHECK(!insn.has_target);
    CHECK(!insn.falls_through);
    CHECK(text_equals(insn.operands, "(R0), c7"));

    const uint8_t jmpl_memory[] = {0x60, 0xfd, 0x9a, 0x07};
    insn = decode_array(jmpl_memory, 0x2cffc);
    CHECK(text_equals(insn.mnemonic, "jmpl"));
    CHECK(text_equals(insn.evidence, "gcc-supplement"));
    CHECK(insn.flow == ipp::Flow::Call);
    CHECK(insn.falls_through);
    CHECK(!insn.has_target);
    CHECK(text_equals(insn.operands, "(R0), c7"));
}

//--------------------------------------------------------------------
static void check_section(const ipp::Image &image, const char *name, bool require_return_end,
                          bool require_clear, bool optional)
{
    const ipp::Section *section = image.section(name);
    if ( section == nullptr || section->size == 0 )
    {
        CHECK(optional);
        std::printf("PASS %s %s absent\n", base_name(image).c_str(), name);
        return;
    }

    std::vector<uint8_t> bytes;
    CHECK(image.read_va(section->addr, section->size, &bytes));
    CHECK(bytes.size() == section->size);
    const std::vector<ipp::Decoded> insns =
        ipp::decode_linear(bytes.data(), bytes.size(), section->addr);
    const byte_partition_t partition = partition_bytes(insns, section->size);
    CHECK(!partition.overlap_or_gap);
    CHECK(partition.sum == section->size);
    if ( require_clear )
        CHECK(partition.unresolved_bytes == 0);
    if ( require_return_end )
    {
        CHECK(!insns.empty());
        if ( !insns.empty() )
        {
            const ipp::Decoded &last = insns.back();
            CHECK(last.kind == ipp::Kind::Insn);
            CHECK(last.flow == ipp::Flow::Return);
            CHECK(last.length == 2);
            CHECK(text_equals(last.mnemonic, "jmpr"));
        }
    }
    std::printf("PASS %s %s size=%u insn=%u noncode=%u unresolved=%u\n", base_name(image).c_str(),
                name, section->size, partition.instruction_bytes, partition.noncode_bytes,
                partition.unresolved_bytes);
}

//--------------------------------------------------------------------
/// ntohl and htonl are identity functions on this big-endian target.
static void check_identity_function(const ipp::Image &image, const char *symbol_name)
{
    const ipp::Symbol *symbol = image.function(symbol_name);
    CHECK(symbol != nullptr);
    if ( symbol == nullptr )
        return;

    CHECK(symbol->size == 2);
    std::vector<uint8_t> bytes;
    CHECK(image.read_va(symbol->value, symbol->size, &bytes));
    CHECK(bytes.size() == 2);
    CHECK(bytes[0] == 0x01 && bytes[1] == 0x4f);
    const std::vector<ipp::Decoded> insns =
        ipp::decode_linear(bytes.data(), bytes.size(), symbol->value);
    CHECK(insns.size() == 1);
    if ( insns.size() == 1 )
    {
        CHECK(insns[0].length == 2);
        CHECK(insns[0].flow == ipp::Flow::Return);
        CHECK(insns[0].kind == ipp::Kind::Insn);
    }
    std::printf("PASS %s %s va=%08x len=2 return\n", base_name(image).c_str(), symbol_name,
                symbol->value);
}

//--------------------------------------------------------------------
static void check_plt(const ipp::Image &image)
{
    const ipp::Section *plt = image.section(".plt");
    const ipp::Section *rela = image.section(".rela.plt");
    if ( plt == nullptr || rela == nullptr || plt->size == 0 )
    {
        CHECK(base_name(image) != "libc.so.7");
        std::printf("PASS %s plt absent\n", base_name(image).c_str());
        return;
    }

    std::vector<const ipp::Reloc *> slots;
    uint32_t type = 0;
    bool type_set = false;
    for ( const ipp::Reloc &reloc : image.relocs() )
    {
        if ( reloc.section != ".rela.plt" )
            continue;
        if ( !type_set )
        {
            type = reloc.type;
            type_set = true;
        }
        CHECK(reloc.type == type);
        slots.push_back(&reloc);
    }
    CHECK(type_set);
    CHECK(!slots.empty());
    CHECK((slots.size() + 1) != 0);
    CHECK(plt->size % (slots.size() + 1) == 0);
    const uint32_t stride = plt->size / static_cast<uint32_t>(slots.size() + 1);
    CHECK(stride != 0 && (stride % 2) == 0);
    std::printf("PASS %s plt size=%u rela=%zu type=%u stride=%u\n", base_name(image).c_str(),
                plt->size, slots.size(), type, stride);

    if ( base_name(image) == "libc.so.7" )
    {
        CHECK(slots.size() == 800);
        CHECK(type == 178);
        CHECK(stride == 44);
        CHECK(plt->size == 0x89ac);
    }
}

//--------------------------------------------------------------------
static void check_relocation_types(const ipp::Image &image)
{
    std::set<uint32_t> types;
    for ( const ipp::Reloc &reloc : image.relocs() )
    {
        types.insert(reloc.type);
        const char *name = ipp::Image::reloc_name(reloc.type);
        CHECK(name == nullptr || text_equals(name, "R_IPP_COPY"));
    }
    if ( base_name(image) != "libc.so.7" )
        return;

    CHECK(types.count(0) == 1);
    CHECK(types.count(177) == 1);
    CHECK(types.count(178) == 1);
    CHECK(types.count(179) == 1);
    CHECK(types.count(237) == 1);
    CHECK(types.size() == 5);
    CHECK(image.machine() == 0x1040);
    CHECK(image.flags() == 0x00034000);
    const ipp::Section *init = image.section(".init");
    const ipp::Section *fini = image.section(".fini");
    CHECK(init != nullptr && init->size == 0x22);
    CHECK(fini != nullptr && fini->size == 0x1e);

    bool saw_executable = false;
    bool saw_writable = false;
    bool entry_in_executable = false;
    for ( const ipp::Segment &segment : image.segments() )
    {
        if ( !segment.is_load() )
            continue;
        CHECK(segment.filesz <= segment.memsz);
        if ( segment.is_executable() )
        {
            saw_executable = true;
            if ( image.entry() >= segment.va && image.entry() < segment.va + segment.memsz )
                entry_in_executable = true;
        }
        if ( (segment.flags & 2u) != 0 )
            saw_writable = true;
    }
    CHECK(saw_executable && saw_writable && entry_in_executable);
}

//--------------------------------------------------------------------
/// Function symbols must start and end on instruction boundaries of a linear decode
/// of .text, and their direct branches must land on boundaries too.
static void check_function_symbols(const ipp::Image &image)
{
    const ipp::Section *text = image.section(".text");
    CHECK(text != nullptr);
    if ( text == nullptr )
        return;

    std::vector<uint8_t> text_bytes;
    CHECK(image.read_va(text->addr, text->size, &text_bytes));
    const std::vector<ipp::Decoded> linear =
        ipp::decode_linear(text_bytes.data(), text_bytes.size(), text->addr);
    std::vector<char> boundary(text->size + 1, 0);
    uint32_t covered = 0;
    for ( const ipp::Decoded &insn : linear )
    {
        if ( insn.address < text->addr )
            continue;
        const uint32_t offset = insn.address - text->addr;
        if ( offset <= text->size )
            boundary[offset] = 1;
        covered += insn.length;
    }
    CHECK(covered == text->size);
    boundary[text->size] = 1;

    int proven = 0;
    int checked = 0;
    for ( const ipp::Symbol &symbol : image.symbols() )
    {
        if ( !symbol.is_function() || symbol.size == 0 || !symbol.is_defined() )
            continue;
        if ( symbol.value < text->addr || symbol.value > text->addr + text->size )
            continue;
        if ( symbol.size > text->addr + text->size - symbol.value )
            continue;

        ++checked;
        const uint32_t offset = symbol.value - text->addr;
        const std::vector<ipp::Decoded> body =
            ipp::decode_linear(text_bytes.data() + offset, symbol.size, symbol.value);
        const byte_partition_t partition = partition_bytes(body, symbol.size);
        CHECK(!partition.overlap_or_gap);
        CHECK(partition.sum == symbol.size);
        if ( partition.unresolved_bytes != 0 )
            continue;

        ++proven;
        CHECK(boundary[offset] == 1);
        CHECK(offset + symbol.size <= text->size);
        CHECK(boundary[offset + symbol.size] == 1);
        for ( const ipp::Decoded &insn : body )
        {
            if ( !insn.has_target )
                continue;
            if ( insn.target < text->addr || insn.target > text->addr + text->size )
                continue;
            CHECK(boundary[insn.target - text->addr] == 1);
        }
    }
    if ( checked > 0 )
        CHECK(proven > 0);
    std::printf("PASS %s dynsym checked=%d proven=%d\n", base_name(image).c_str(), checked, proven);
}

//--------------------------------------------------------------------
/// Calls in .init must land on instruction boundaries of .text, at a prologue.
static void check_init_calls_land(const ipp::Image &image)
{
    const ipp::Section *init = image.section(".init");
    const ipp::Section *text = image.section(".text");
    if ( init == nullptr || text == nullptr )
    {
        CHECK(base_name(image) != "libc.so.7" && base_name(image) != "aencode");
        std::printf("PASS %s init absent\n", base_name(image).c_str());
        return;
    }

    std::vector<uint8_t> init_bytes;
    std::vector<uint8_t> text_bytes;
    CHECK(image.read_va(init->addr, init->size, &init_bytes));
    CHECK(image.read_va(text->addr, text->size, &text_bytes));
    const std::vector<ipp::Decoded> insns =
        ipp::decode_linear(init_bytes.data(), init_bytes.size(), init->addr);
    const std::vector<ipp::Decoded> text_insns =
        ipp::decode_linear(text_bytes.data(), text_bytes.size(), text->addr);

    std::vector<char> boundary(text->size + 1, 0);
    for ( const ipp::Decoded &insn : text_insns )
    {
        if ( insn.address >= text->addr && insn.address - text->addr <= text->size )
            boundary[insn.address - text->addr] = 1;
    }
    boundary[text->size] = 1;

    int calls = 0;
    for ( const ipp::Decoded &insn : insns )
    {
        if ( !insn.has_target )
            continue;
        ++calls;
        CHECK(insn.flow == ipp::Flow::Call || insn.flow == ipp::Flow::Branch);
        CHECK((insn.target & 1u) == 0);
        if ( insn.target >= text->addr && insn.target < text->addr + text->size )
        {
            CHECK(boundary[insn.target - text->addr] == 1);
            const uint32_t offset = insn.target - text->addr;
            CHECK(text_bytes[offset] == 0x0f || text_bytes[offset] == 0x0e);
        }
    }

    if ( base_name(image) == "aencode" )
    {
        CHECK(calls >= 2);
        bool hit = false;
        for ( const ipp::Decoded &insn : insns )
        {
            if ( insn.has_target && insn.target == 0x08000140 )
                hit = true;
        }
        CHECK(hit);
    }
    std::printf("PASS %s init calls=%d\n", base_name(image).c_str(), calls);
}

//--------------------------------------------------------------------
static void check_frame(const ipp::Image &image, const expected_frame_t &expected)
{
    const ipp::Section *section = image.section(expected.section);
    CHECK(section != nullptr);
    if ( section == nullptr )
        return;

    CHECK(section->size == expected.size);
    std::vector<uint8_t> bytes;
    CHECK(image.read_va(section->addr, section->size, &bytes));
    const std::vector<ipp::Decoded> insns =
        ipp::decode_linear(bytes.data(), bytes.size(), section->addr);
    CHECK(insns.size() == expected.mnemonics.size());

    uint32_t sum = 0;
    for ( size_t i = 0; i < insns.size() && i < expected.mnemonics.size(); ++i )
    {
        const ipp::Decoded &insn = insns[i];
        sum += insn.length;
        CHECK(insn.length == expected.lengths[i]);
        CHECK(text_equals(insn.mnemonic, expected.mnemonics[i]));
        if ( insn.has_mnemonic("brl") )
        {
            CHECK(insn.flow == ipp::Flow::Call);
            CHECK(insn.falls_through);
        }
        if ( insn.has_mnemonic("br") )
        {
            CHECK(insn.flow == ipp::Flow::Branch);
            CHECK(insn.length == 2);
            CHECK(insn.falls_through);
            CHECK(insn.has_target);
            CHECK(insn.target == insn.address);
            CHECK(text_equals(insn.evidence, "gcc-supplement"));
        }
        if ( insn.address == expected.brl_address )
        {
            CHECK(insn.has_target);
            CHECK(insn.target == expected.brl_target);
            CHECK(insn.flow == ipp::Flow::Call);
            CHECK(insn.falls_through);
        }
        if ( expected.brl_lr_address != 0 && insn.address == expected.brl_lr_address )
        {
            CHECK(insn.has_target);
            CHECK(insn.target == expected.brl_lr_target);
            CHECK(text_equals(insn.evidence, "v8-009fd6d4"));
            CHECK(insn.flow == ipp::Flow::Call);
            CHECK(insn.falls_through);
        }
    }
    CHECK(sum == expected.size);
    std::printf("PASS %s %s picture insns=%zu\n", base_name(image).c_str(), expected.section,
                insns.size());
}

//--------------------------------------------------------------------
static void check_supplied_image(const std::string &root, const std::string &name)
{
    ipp::Image image;
    const std::string path = (std::filesystem::path(root) / name).string();
    CHECK(image.load_file(path));
    if ( !image.error().empty() && image.machine() != 0x1040 )
    {
        std::fprintf(stderr, "%s\n", image.error().c_str());
        return;
    }
    CHECK(image.machine() == 0x1040);

    const bool is_libc = name == "libc.so.7";
    const bool has_frames = is_libc || name == "aencode";
    const bool is_dense = is_libc || name == "ld-elf.so.1";
    // ld-elf.so.1 has neither section. libc and aencode .init/.fini are fully
    // tiled. libc and ld-elf .text are fully tiled once the GCC extras are in.
    check_section(image, ".init", is_libc, has_frames, !has_frames);
    check_section(image, ".fini", is_libc, has_frames, !has_frames);
    check_section(image, ".text", false, is_dense, false);
    check_section(image, ".plt", false, is_libc, true);
    check_plt(image);
    check_relocation_types(image);
    check_function_symbols(image);
    check_init_calls_land(image);
}

//--------------------------------------------------------------------
static void check_libc_frames(const ipp::Image &libc)
{
    check_frame(libc,
                {".init",
                 0x22,
                 {"add", "stp", "cmpne", "br", "br", "br", "br", "br", "brl", "sethi", "brl", "ldp",
                  "add", "jmpr"},
                 {2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 2, 2, 2},
                 0x1fee0,
                 0x28940,
                 0x1fee8,
                 0xf18a6});
    check_frame(libc,
                {".fini",
                 0x1e,
                 {"add", "stp", "cmpne", "br", "br", "br", "br", "br", "sethi", "brl", "ldp", "add",
                  "jmpr"},
                 {2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 2, 2, 2},
                 0,
                 0,
                 0xf1914,
                 0x288a0});
}

//--------------------------------------------------------------------
static void check_libc_gcc_sites(const ipp::Image &libc)
{
    std::vector<uint8_t> raw;
    CHECK(libc.read_va(0x288b0, 4, &raw));
    ipp::Decoded insn = ipp::decode_one(raw.data(), raw.size(), 0x288b0);
    CHECK(text_equals(insn.mnemonic, "mov"));
    CHECK(text_equals(insn.evidence, "gcc-supplement"));
    CHECK(text_equals(insn.operands, "R30,PC, c7"));
    CHECK(raw.size() == 4 && raw[0] == 0x60 && raw[1] == 0x1e && raw[2] == 0x7f && raw[3] == 0x67);

    CHECK(libc.read_va(0x28b48, 2, &raw));
    insn = ipp::decode_one(raw.data(), raw.size(), 0x28b48);
    CHECK(raw.size() == 2 && raw[0] == 0x00 && raw[1] == 0x15);
    CHECK(insn.target == 0x28b5c);
    CHECK(text_equals(insn.evidence, "gcc-supplement"));

    CHECK(libc.read_va(0x2cffc, 4, &raw));
    insn = ipp::decode_one(raw.data(), raw.size(), 0x2cffc);
    CHECK(raw.size() == 4 && raw[0] == 0x60 && raw[1] == 0xfd && raw[2] == 0x9a && raw[3] == 0x07);
    CHECK(text_equals(insn.mnemonic, "jmpl"));
    CHECK(text_equals(insn.evidence, "gcc-supplement"));
    CHECK(insn.flow == ipp::Flow::Call);
    CHECK(insn.falls_through);
    CHECK(!insn.has_target);
    std::printf("PASS libc gcc sites mov/br/jmpl\n");
}

//--------------------------------------------------------------------
static void check_libc_anddi3(const ipp::Image &libc)
{
    const ipp::Symbol *anddi = libc.function("__anddi3");
    CHECK(anddi != nullptr);
    if ( anddi == nullptr )
        return;

    std::vector<uint8_t> bytes;
    CHECK(libc.read_va(anddi->value, anddi->size, &bytes));
    const std::vector<ipp::Decoded> body =
        ipp::decode_linear(bytes.data(), bytes.size(), anddi->value);
    const byte_partition_t partition = partition_bytes(body, anddi->size);
    CHECK(partition.unresolved_bytes == 0);
    CHECK(partition.sum == anddi->size);
    CHECK(body.size() >= 3);
    CHECK(bytes.size() == 6);
    CHECK(bytes.size() >= 6
          && bytes[0] == 0x10
          && bytes[1] == 0x02
          && bytes[2] == 0x11
          && bytes[3] == 0x03
          && bytes[4] == 0x01
          && bytes[5] == 0x4f);
    if ( body.size() >= 3 )
    {
        CHECK(text_equals(body[0].mnemonic, "and"));
        CHECK(text_equals(body[0].evidence, "v8-009fbe0a"));
        CHECK(text_equals(body[1].mnemonic, "and"));
        CHECK(text_equals(body[1].evidence, "v8-009fbe0a"));
        CHECK(text_equals(body[2].mnemonic, "jmpr"));
        CHECK(body[2].flow == ipp::Flow::Return);
    }
    std::printf("PASS __anddi3 proven size=%u\n", anddi->size);
}

//--------------------------------------------------------------------
int main(int argc, char **argv)
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if ( argc < 2 )
    {
        std::fprintf(stderr, "usage: ipp-oracle <sample-directory>\n");
        return 2;
    }
    const std::string root = argv[1];
    const auto corpus_file = [&root](const char *name)
    {
        return (std::filesystem::path(root) / name).string();
    };

    check_forms();
    check_return_and_length_model();
    check_calls();
    check_compact_data_forms();
    check_gcc_supplemental_forms();

    for ( const char *name : {"libc.so.7", "ld-elf.so.1", "aencode"} )
        check_supplied_image(root, name);

    ipp::Image libc;
    CHECK(libc.load_file(corpus_file("libc.so.7")));
    check_identity_function(libc, "ntohl");
    check_identity_function(libc, "htonl");
    check_libc_frames(libc);

    ipp::Image ld;
    CHECK(ld.load_file(corpus_file("ld-elf.so.1")));
    CHECK(ld.contains_cstring("%s: Unexpected R_IPP_COPY relocation in shared library"));
    CHECK(ld.contains_cstring("rtld-elf/ipp/reloc.c:63\n"));
    std::printf("PASS ld-elf NUL-terminated relocation diagnostic/source strings\n");

    ipp::Image libm;
    CHECK(libm.load_file(corpus_file("libm.so.5")));
    check_section(libm, ".text", false, true, false);

    check_libc_gcc_sites(libc);
    check_libc_anddi3(libc);

    if ( ipp::test::failure_count != 0 )
    {
        std::fprintf(stderr, "FAILED %d\n", ipp::test::failure_count);
        return 1;
    }
    std::printf("PASS oracle\n");
    return 0;
}
