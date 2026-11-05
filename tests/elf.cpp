// ELF reader test: metadata edge cases, failure state and address mapping, over
// fixtures built byte by byte. Offsets are spelled out here rather than shared with
// the parser, so a wrong constant there cannot go unnoticed.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ipp/elf.hpp"

#include "support/check.hpp"

namespace
{

using bytes_t = std::vector<uint8_t>;

// Elf32_Ehdr
constexpr size_t EH_TYPE = 16;
constexpr size_t EH_MACHINE = 18;
constexpr size_t EH_VERSION = 20;
constexpr size_t EH_ENTRY = 24;
constexpr size_t EH_PHOFF = 28;
constexpr size_t EH_SHOFF = 32;
constexpr size_t EH_EHSIZE = 40;
constexpr size_t EH_PHENTSIZE = 42;
constexpr size_t EH_PHNUM = 44;
constexpr size_t EH_SHENTSIZE = 46;
constexpr size_t EH_SHNUM = 48;
constexpr size_t EH_SHSTRNDX = 50;
constexpr uint32_t EH_SIZE = 52;

// Elf32_Phdr, placed directly after the file header.
constexpr size_t PH_TYPE = EH_SIZE + 0;
constexpr size_t PH_OFFSET = EH_SIZE + 4;
constexpr size_t PH_VADDR = EH_SIZE + 8;
constexpr size_t PH_PADDR = EH_SIZE + 12;
constexpr size_t PH_FILESZ = EH_SIZE + 16;
constexpr size_t PH_MEMSZ = EH_SIZE + 20;
constexpr size_t PH_FLAGS = EH_SIZE + 24;
constexpr size_t PH_ALIGN = EH_SIZE + 28;
constexpr uint32_t PH_ENTRY_SIZE = 32;

// Elf32_Shdr
constexpr size_t SH_NAME = 0;
constexpr size_t SH_TYPE = 4;
constexpr size_t SH_FLAGS = 8;
constexpr size_t SH_ADDR = 12;
constexpr size_t SH_OFFSET = 16;
constexpr size_t SH_SIZE = 20;
constexpr size_t SH_LINK = 24;
constexpr size_t SH_INFO = 28;
constexpr size_t SH_ADDRALIGN = 32;
constexpr size_t SH_ENTSIZE = 36;
constexpr uint32_t SH_ENTRY_SIZE = 40;

// Elf32_Sym
constexpr size_t ST_NAME = 0;
constexpr size_t ST_VALUE = 4;
constexpr size_t ST_SIZE = 8;
constexpr size_t ST_INFO = 12;
constexpr size_t ST_SHNDX = 14;
constexpr uint32_t ST_ENTRY_SIZE = 16;

constexpr uint32_t PT_LOAD_TYPE = 1;
constexpr uint32_t SHT_PROGBITS_TYPE = 1;
constexpr uint32_t SHT_SYMTAB_TYPE = 2;
constexpr uint32_t SHT_STRTAB_TYPE = 3;
constexpr uint32_t SHT_NOBITS_TYPE = 8;
constexpr uint32_t SHT_SYMTAB_SHNDX_TYPE = 18;
constexpr uint32_t SHF_ALLOC_EXEC = 6;
constexpr uint32_t SHF_EXEC_ONLY = 4;
constexpr uint32_t ET_EXEC_TYPE = 2;
constexpr uint32_t SHN_XINDEX_VALUE = 0xffff;
constexpr uint8_t GLOBAL_FUNCTION_INFO = 0x12;
constexpr uint32_t MACHINE_IPP = 0x1040;
constexpr uint32_t PF_READ_EXEC = 5;
constexpr uint32_t PROGRAM_WORD = 0x014f077f;

// Layout of the metadata fixture.
constexpr uint32_t FIXTURE_CODE = 0x100;
constexpr uint32_t FIXTURE_STRINGS = 0x110;
constexpr uint32_t FIXTURE_SYMBOLS = 0x120;
constexpr uint32_t FIXTURE_ENTRY_SYMBOL = FIXTURE_SYMBOLS + ST_ENTRY_SIZE;
constexpr uint32_t FIXTURE_NAMES = 0x140;
constexpr uint32_t FIXTURE_INDEXES = 0x168;
constexpr uint32_t FIXTURE_SECTIONS = 0x180;
constexpr uint32_t FIXTURE_TEXT_VA = 0x1000;

// Section numbers of the plain (not extended) metadata fixture.
constexpr uint32_t TEXT_SECTION = 1;
constexpr uint32_t STRINGS_SECTION = 2;
constexpr uint32_t SYMBOLS_SECTION = 3;
constexpr uint32_t NAMES_SECTION = 4;
constexpr uint32_t PLAIN_SECTION_COUNT = 5;

// Values of the extended-index variant, where section zero carries the counts.
constexpr uint32_t EXTENDED_SECTION_COUNT = 0x10002;
constexpr uint32_t EXTENDED_TEXT_SECTION = 0x10000;
constexpr uint32_t EXTENDED_NAMES_SECTION = 0x10001;
constexpr uint32_t INDEX_TABLE_SECTION = 1;

constexpr char SYMBOL_STRINGS[] = "\0entry";
constexpr char SECTION_NAMES[] = "\0.text\0.strtab\0.symtab\0.shstrtab";

// Layout of the address-mapping fixture.
constexpr uint32_t MAPPING_SECTIONS = 0x140;
constexpr uint32_t MAPPING_FILE_SIZE = 0x1e0;
constexpr uint32_t MAPPING_CODE = 0x100;
constexpr uint32_t MAPPING_METADATA = 0x104;
constexpr uint32_t MAPPING_NAMES = 0x108;
constexpr char MAPPING_SECTION_NAMES[] = "\0.debug\0.text\0.shstrtab\0";

/// The contents of one section header.
struct section_fields_t
{
    uint32_t name;
    uint32_t type;
    uint32_t flags;
    uint32_t va;
    uint32_t offset;
    uint32_t size;
    uint32_t link = 0;
    uint32_t entsize = 0;
};

} // namespace

//--------------------------------------------------------------------
static void put_be(bytes_t &raw, size_t offset, uint32_t value, unsigned size = 4)
{
    for ( unsigned i = 0; i < size; ++i )
        raw[offset + i] = static_cast<uint8_t>(value >> (8 * (size - 1 - i)));
}

//--------------------------------------------------------------------
static uint32_t get_be32(const bytes_t &raw, size_t offset)
{
    return uint32_t(raw[offset]) << 24
        | uint32_t(raw[offset + 1]) << 16
        | uint32_t(raw[offset + 2]) << 8
        | raw[offset + 3];
}

//--------------------------------------------------------------------
static size_t section_field(uint32_t index, size_t field)
{
    return FIXTURE_SECTIONS + size_t(SH_ENTRY_SIZE) * index + field;
}

//--------------------------------------------------------------------
/// Write a section header into the table named by the fixture's e_shoff.
static void put_section(bytes_t &raw, uint32_t index, const section_fields_t &fields)
{
    const size_t start = get_be32(raw, EH_SHOFF) + size_t(SH_ENTRY_SIZE) * index;
    put_be(raw, start + SH_NAME, fields.name);
    put_be(raw, start + SH_TYPE, fields.type);
    put_be(raw, start + SH_FLAGS, fields.flags);
    put_be(raw, start + SH_ADDR, fields.va);
    put_be(raw, start + SH_OFFSET, fields.offset);
    put_be(raw, start + SH_SIZE, fields.size);
    put_be(raw, start + SH_LINK, fields.link);
    put_be(raw, start + SH_ENTSIZE, fields.entsize);
}

//--------------------------------------------------------------------
static void put_file_header(bytes_t &raw, uint32_t entry, uint32_t section_table,
                            uint32_t section_count, uint32_t names_index)
{
    std::memcpy(raw.data(), "\177ELF\1\2\1", 7);
    put_be(raw, EH_TYPE, ET_EXEC_TYPE, 2);
    put_be(raw, EH_MACHINE, MACHINE_IPP, 2);
    put_be(raw, EH_VERSION, 1);
    put_be(raw, EH_ENTRY, entry);
    put_be(raw, EH_PHOFF, EH_SIZE);
    put_be(raw, EH_SHOFF, section_table);
    put_be(raw, EH_EHSIZE, EH_SIZE, 2);
    put_be(raw, EH_PHENTSIZE, PH_ENTRY_SIZE, 2);
    put_be(raw, EH_PHNUM, 1, 2);
    put_be(raw, EH_SHENTSIZE, SH_ENTRY_SIZE, 2);
    put_be(raw, EH_SHNUM, section_count, 2);
    put_be(raw, EH_SHSTRNDX, names_index, 2);
}

//--------------------------------------------------------------------
/// One PT_LOAD, one symbol table and a section-name table. The extended variant
/// moves .text and the names beyond the 16-bit range, using the gABI escape fields
/// in section zero and a parallel symbol-index table.
static bytes_t metadata_fixture(bool extended = false)
{
    const uint32_t section_count = extended ? EXTENDED_SECTION_COUNT : PLAIN_SECTION_COUNT;
    const uint32_t text_section = extended ? EXTENDED_TEXT_SECTION : TEXT_SECTION;
    const uint32_t names_section = extended ? EXTENDED_NAMES_SECTION : NAMES_SECTION;

    bytes_t raw(FIXTURE_SECTIONS + size_t(SH_ENTRY_SIZE) * section_count);
    put_file_header(raw, FIXTURE_TEXT_VA, FIXTURE_SECTIONS, extended ? 0 : section_count,
                    extended ? SHN_XINDEX_VALUE : names_section);

    put_be(raw, PH_TYPE, PT_LOAD_TYPE);
    put_be(raw, PH_OFFSET, FIXTURE_CODE);
    put_be(raw, PH_VADDR, FIXTURE_TEXT_VA);
    put_be(raw, PH_FILESZ, 4);
    put_be(raw, PH_MEMSZ, 4);
    put_be(raw, PH_FLAGS, PF_READ_EXEC);
    put_be(raw, PH_ALIGN, 2);

    put_be(raw, FIXTURE_CODE, PROGRAM_WORD);
    std::memcpy(raw.data() + FIXTURE_STRINGS, SYMBOL_STRINGS, sizeof(SYMBOL_STRINGS));
    std::memcpy(raw.data() + FIXTURE_NAMES, SECTION_NAMES, sizeof(SECTION_NAMES));

    put_be(raw, FIXTURE_ENTRY_SYMBOL + ST_NAME, 1);
    put_be(raw, FIXTURE_ENTRY_SYMBOL + ST_VALUE, FIXTURE_TEXT_VA);
    put_be(raw, FIXTURE_ENTRY_SYMBOL + ST_SIZE, 4);
    raw[FIXTURE_ENTRY_SYMBOL + ST_INFO] = GLOBAL_FUNCTION_INFO;
    put_be(raw, FIXTURE_ENTRY_SYMBOL + ST_SHNDX, extended ? SHN_XINDEX_VALUE : text_section, 2);

    put_section(raw, text_section,
                {1, SHT_PROGBITS_TYPE, SHF_ALLOC_EXEC, FIXTURE_TEXT_VA, FIXTURE_CODE, 4});
    put_section(raw, STRINGS_SECTION,
                {7, SHT_STRTAB_TYPE, 0, 0, FIXTURE_STRINGS, sizeof(SYMBOL_STRINGS)});
    put_section(raw, SYMBOLS_SECTION,
                {15, SHT_SYMTAB_TYPE, 0, 0, FIXTURE_SYMBOLS, 2 * ST_ENTRY_SIZE, STRINGS_SECTION,
                 ST_ENTRY_SIZE});
    put_section(raw, names_section,
                {23, SHT_STRTAB_TYPE, 0, 0, FIXTURE_NAMES, sizeof(SECTION_NAMES)});

    if ( extended )
    {
        put_be(raw, section_field(0, SH_SIZE), section_count);
        put_be(raw, section_field(0, SH_LINK), names_section);
        put_section(raw, INDEX_TABLE_SECTION,
                    {0, SHT_SYMTAB_SHNDX_TYPE, 0, 0, FIXTURE_INDEXES, 8, SYMBOLS_SECTION, 4});
        put_be(raw, FIXTURE_INDEXES + 4, text_section);
    }
    return raw;
}

//--------------------------------------------------------------------
static void clear_section_names(bytes_t &raw)
{
    for ( uint32_t i = 0; i < PLAIN_SECTION_COUNT; ++i )
        put_be(raw, section_field(i, SH_NAME), 0);
}

//--------------------------------------------------------------------
static void check_failed_load_state(const ipp::Image &image)
{
    CHECK(image.sections().empty() && image.symbols().empty() && image.segments().empty());
    CHECK(image.machine() == 0 && image.entry() == 0);
}

//--------------------------------------------------------------------
static void check_accepted_metadata(ipp::Image &image, const bytes_t &baseline,
                                    const bytes_t &extended)
{
    CHECK(image.load_bytes(baseline.data(), baseline.size(), "named"));
    CHECK(image.function("entry") != nullptr);

    bytes_t nameless = baseline;
    put_be(nameless, EH_SHSTRNDX, 0, 2);
    clear_section_names(nameless);
    CHECK(image.load_bytes(nameless.data(), nameless.size(), "no-section-names"));
    CHECK(image.sections().size() == PLAIN_SECTION_COUNT && image.function("entry") != nullptr);
    for ( const ipp::Section &section : image.sections() )
        CHECK(section.name.empty());
    CHECK(image.executable_va(FIXTURE_TEXT_VA, 4));

    bytes_t empty = baseline;
    clear_section_names(empty);
    put_be(empty, section_field(NAMES_SECTION, SH_SIZE), 0);
    CHECK(image.load_bytes(empty.data(), empty.size(), "empty-section-names"));
    CHECK(image.sections().size() == PLAIN_SECTION_COUNT && image.function("entry") != nullptr);

    CHECK(image.load_bytes(extended.data(), extended.size(), "extended-indexes"));
    CHECK(image.sections().size() == EXTENDED_SECTION_COUNT);
    const ipp::Symbol *function = image.function("entry");
    CHECK(function != nullptr && function->shndx == EXTENDED_TEXT_SECTION);
    CHECK(image.section(".text") != nullptr && image.executable_va(FIXTURE_TEXT_VA, 4));

    bytes_t inactive = baseline;
    for ( size_t field : {SH_NAME, SH_FLAGS, SH_ADDR, SH_OFFSET, SH_SIZE, SH_LINK, SH_INFO,
                          SH_ADDRALIGN, SH_ENTSIZE} )
    {
        put_be(inactive, section_field(0, field), 0xffffffff);
    }
    CHECK(image.load_bytes(inactive.data(), inactive.size(), "inactive-section-fields"));
    CHECK(image.sections()[0].flags == 0 && image.sections()[0].size == 0);

    bytes_t substring = baseline;
    put_be(substring, FIXTURE_ENTRY_SYMBOL + ST_NAME, 2);
    put_be(substring, section_field(TEXT_SECTION, SH_NAME), 2);
    CHECK(image.load_bytes(substring.data(), substring.size(), "string-subindexes"));
    CHECK(image.function("ntry") != nullptr && image.section("text") != nullptr);

    bytes_t empty_symbols = baseline;
    put_be(empty_symbols, FIXTURE_ENTRY_SYMBOL + ST_NAME, 0);
    put_be(empty_symbols, section_field(STRINGS_SECTION, SH_SIZE), 0);
    CHECK(image.load_bytes(empty_symbols.data(), empty_symbols.size(), "empty-symbol-strings"));
    CHECK(image.symbols().size() == 2);
    for ( const ipp::Symbol &symbol : image.symbols() )
        CHECK(symbol.name.empty());
}

//--------------------------------------------------------------------
static void check_rejected_metadata(ipp::Image &image, const bytes_t &baseline,
                                    const bytes_t &extended)
{
    const auto reject = [&image](const bytes_t &raw, const char *label)
    {
        CHECK(!image.load_bytes(raw.data(), raw.size(), label));
        CHECK(!image.error().empty());
        check_failed_load_state(image);
    };

    bytes_t bad = baseline;
    put_be(bad, section_field(NAMES_SECTION, SH_TYPE), SHT_NOBITS_TYPE);
    reject(bad, "NOBITS-section-names");

    bad = baseline;
    put_be(bad, section_field(NAMES_SECTION, SH_TYPE), SHT_PROGBITS_TYPE);
    reject(bad, "PROGBITS-section-names");

    bad = baseline;
    bad[FIXTURE_NAMES + get_be32(bad, section_field(NAMES_SECTION, SH_SIZE)) - 1] = 'X';
    reject(bad, "unterminated-section-names");

    bad = baseline;
    put_be(bad, section_field(TEXT_SECTION, SH_NAME), 0x100);
    reject(bad, "section-name-outside-table");

    bad = baseline;
    put_be(bad, section_field(STRINGS_SECTION, SH_TYPE), SHT_NOBITS_TYPE);
    reject(bad, "NOBITS-symbol-names");

    bad = baseline;
    bad[FIXTURE_STRINGS + get_be32(bad, section_field(STRINGS_SECTION, SH_SIZE)) - 1] = 'X';
    reject(bad, "unterminated-symbol-name");

    bad = baseline;
    put_be(bad, FIXTURE_ENTRY_SYMBOL + ST_NAME, 0x100);
    reject(bad, "symbol-name-outside-table");

    bad = extended;
    put_be(bad, FIXTURE_INDEXES + 4, EXTENDED_SECTION_COUNT);
    reject(bad, "extended-symbol-index-outside-table");

    bad = extended;
    put_be(bad, section_field(INDEX_TABLE_SECTION, SH_TYPE), 0);
    reject(bad, "missing-symbol-index-table");

    bad = extended;
    put_be(bad, section_field(INDEX_TABLE_SECTION, SH_ENTSIZE), 8);
    reject(bad, "symbol-index-entry-size");

    bad = extended;
    put_be(bad, section_field(INDEX_TABLE_SECTION, SH_SIZE), 4);
    reject(bad, "symbol-index-count");

    bad = extended;
    put_be(bad, FIXTURE_INDEXES, 1);
    reject(bad, "nonextended-symbol-with-index");

    bad = extended;
    put_be(bad, section_field(0, SH_TYPE), 1);
    reject(bad, "non-NULL-extension-header");

    bad = extended;
    put_be(bad, section_field(0, SH_LINK), EXTENDED_SECTION_COUNT);
    reject(bad, "extended-section-name-index");

    bad = extended;
    bad.resize(bad.size() - 1);
    reject(bad, "truncated-extended-section-table");

    bad = baseline;
    put_be(bad, FIXTURE_ENTRY_SYMBOL + ST_SHNDX, PLAIN_SECTION_COUNT, 2);
    reject(bad, "direct-symbol-index-outside-table");
}

//--------------------------------------------------------------------
/// A failed load must not leave the previous file's state behind.
static void check_state_after_failure(ipp::Image &image, const bytes_t &baseline)
{
    CHECK(image.load_bytes(baseline.data(), baseline.size(), "state-before-null"));
    CHECK(!image.load_bytes(nullptr, 1, "null"));
    CHECK(image.sections().empty() && image.symbols().empty() && image.segments().empty());
    CHECK(image.machine() == 0 && image.entry() == 0 && image.bytes().empty());

    CHECK(image.load_bytes(baseline.data(), baseline.size(), "state-before-file-error"));
    CHECK(!image.load_file("/dev/null/ipp-absent"));
    CHECK(image.sections().empty() && image.symbols().empty() && image.segments().empty());
    CHECK(image.machine() == 0 && image.entry() == 0 && image.bytes().empty());
}

//--------------------------------------------------------------------
static void check_cstring_boundary(ipp::Image &image, const bytes_t &baseline)
{
    bytes_t text = baseline;
    put_be(text, FIXTURE_CODE, 0x41424344);
    CHECK(image.load_bytes(text.data(), text.size(), "cstring-boundary"));
    CHECK(image.contains_cstring("ABCD"));
    CHECK(image.contains_cstring("BCD"));
    CHECK(!image.contains_cstring("ABC"));
}

//--------------------------------------------------------------------
static void check_metadata()
{
    const bytes_t baseline = metadata_fixture();
    const bytes_t extended = metadata_fixture(true);
    ipp::Image image;
    check_accepted_metadata(image, baseline, extended);
    check_rejected_metadata(image, baseline, extended);
    check_state_after_failure(image, baseline);
    check_cstring_boundary(image, baseline);
}

//--------------------------------------------------------------------
/// PT_LOAD maps four real bytes. Metadata has the same sh_addr=0 convention used by
/// nonallocated sections in the supplied binaries.
static bytes_t mapping_fixture(uint32_t address, bool executable_metadata)
{
    bytes_t raw(MAPPING_FILE_SIZE);
    put_file_header(raw, address, MAPPING_SECTIONS, 4, 3);

    put_be(raw, PH_TYPE, PT_LOAD_TYPE);
    put_be(raw, PH_OFFSET, MAPPING_CODE);
    put_be(raw, PH_VADDR, address);
    put_be(raw, PH_PADDR, address);
    put_be(raw, PH_FILESZ, 4);
    put_be(raw, PH_MEMSZ, 4);
    put_be(raw, PH_FLAGS, PF_READ_EXEC);
    put_be(raw, PH_ALIGN, 1);

    put_be(raw, MAPPING_CODE, PROGRAM_WORD);
    put_be(raw, MAPPING_METADATA, 0xdeadbeef);
    std::memcpy(raw.data() + MAPPING_NAMES, MAPPING_SECTION_NAMES, sizeof(MAPPING_SECTION_NAMES));

    put_section(
        raw, 1,
        {1, SHT_PROGBITS_TYPE, executable_metadata ? SHF_EXEC_ONLY : 0, 0, MAPPING_METADATA, 4});
    put_section(raw, 2, {8, SHT_PROGBITS_TYPE, SHF_ALLOC_EXEC, address, MAPPING_CODE, 4});
    put_section(raw, 3, {14, SHT_STRTAB_TYPE, 0, 0, MAPPING_NAMES, sizeof(MAPPING_SECTION_NAMES)});
    return raw;
}

//--------------------------------------------------------------------
static void check_address_mapping(uint32_t address, bool executable_metadata)
{
    const bytes_t program = {0x01, 0x4f, 0x07, 0x7f};
    const bytes_t raw = mapping_fixture(address, executable_metadata);
    ipp::Image image;
    CHECK(image.load_bytes(raw.data(), raw.size(), "address-mapping"));
    CHECK(image.sections().size() == 4);
    CHECK(image.section(".debug") != nullptr);
    CHECK(image.executable_va(address, 4));
    CHECK(!image.executable_va(address + 4));

    bytes_t bytes;
    CHECK(image.read_va(address, 4, &bytes));
    CHECK(bytes == program);
    CHECK(!image.read_va(address + 4, 1, &bytes) && bytes.empty());
    CHECK(!image.read_va(address + 3, 2, &bytes) && bytes.empty());
    if ( address != 0 )
    {
        bytes.assign(4, 0xff);
        CHECK(!image.read_va(0, 4, &bytes) && bytes.empty());
        CHECK(!image.executable_va(0, 4));
    }

    // A sectionless executable still exposes its PT_LOAD bytes.
    bytes_t sectionless = raw;
    put_be(sectionless, EH_SHOFF, 0);
    put_be(sectionless, EH_SHNUM, 0, 2);
    put_be(sectionless, EH_SHSTRNDX, 0, 2);
    CHECK(image.load_bytes(sectionless.data(), sectionless.size(), "sectionless"));
    CHECK(image.read_va(address, 4, &bytes));
    CHECK(bytes == program);
    CHECK(image.executable_va(address, 4));
}

//--------------------------------------------------------------------
int main()
{
    check_metadata();
    for ( uint32_t address : {0u, 0x1000u} )
    {
        for ( bool executable_metadata : {false, true} )
            check_address_mapping(address, executable_metadata);
    }
    std::printf("ELF names, extended indexes, failure state, allocated sections, address zero, "
                "PT_LOAD fallback: %s\n",
                ipp::test::failure_count != 0 ? "FAILED" : "PASS");
    return ipp::test::failure_count != 0 ? 1 : 0;
}
