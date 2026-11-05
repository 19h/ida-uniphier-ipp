#include "elf/elf_parser.hpp"

#include <cstring>
#include <utility>

#include "byte_order.hpp"
#include "elf/elf_format.hpp"

namespace ipp
{

using namespace elf;

namespace
{

constexpr uint64_t ADDRESS_SPACE_END = uint64_t(1) << 32;

/// One parse of one file. Each step reports the first problem through fail().
class elf_parser_t
{
public:
    elf_parser_t(const std::vector<uint8_t> &bytes, ImageMetadata *out, std::string *error)
        : bytes_(bytes), out_(out), error_(error)
    {
    }

    bool parse()
    {
        if ( !parse_file_header()
             || !resolve_extended_section_counts()
             || !check_table_entry_sizes()
             || !parse_program_headers()
             || !parse_section_headers()
             || !parse_symbol_tables() )
        {
            return false;
        }
        parse_relocations();
        return true;
    }

private:
    bool fail(const char *message)
    {
        *error_ = message;
        return false;
    }

    [[nodiscard]] uint16_t read16(size_t offset) const { return read_be16(bytes_.data() + offset); }
    [[nodiscard]] uint32_t read32(size_t offset) const { return read_be32(bytes_.data() + offset); }
    [[nodiscard]] bool fits(size_t offset, size_t size) const
    {
        return extent_fits(bytes_.size(), offset, size);
    }

    bool parse_file_header();
    bool resolve_extended_section_counts();
    bool check_table_entry_sizes();
    bool parse_program_headers();
    bool parse_section_headers();
    bool parse_section_names(std::vector<Section> *sections);
    bool parse_symbol_tables();
    bool parse_symbol_table(const Section &table, uint32_t table_index, bool dynamic);
    bool find_symbol_index_table(const Section **found, uint32_t table_index,
                                 uint32_t symbol_count);
    void parse_relocations();

    [[nodiscard]] bool valid_string_table(const Section &table) const;
    [[nodiscard]] bool read_string(const Section &table, uint32_t index, std::string *out) const;

    const std::vector<uint8_t> &bytes_;
    ImageMetadata *out_;
    std::string *error_;

    uint32_t phoff_ = 0;
    uint32_t shoff_ = 0;
    uint16_t phentsize_ = 0;
    uint16_t phnum_ = 0;
    uint16_t shentsize_ = 0;
    uint32_t shnum_ = 0;
    uint32_t shstrndx_ = 0;
};

} // namespace

//--------------------------------------------------------------------
bool elf_parser_t::parse_file_header()
{
    if ( !fits(0, FILE_HEADER_SIZE) )
        return fail("truncated ELF header");

    const uint8_t *ident = bytes_.data();
    if ( std::memcmp(ident, "\177ELF", 4) != 0
         || ident[4] != CLASS_32
         || ident[5] != DATA_BIG_ENDIAN )
    {
        return fail("not ELF32 big-endian");
    }

    out_->type = read16(EH_TYPE);
    out_->machine = read16(EH_MACHINE);
    if ( out_->machine != MACHINE_IPP )
        return fail("e_machine is not 0x1040");

    out_->entry = read32(EH_ENTRY);
    phoff_ = read32(EH_PHOFF);
    shoff_ = read32(EH_SHOFF);
    out_->flags = read32(EH_FLAGS);
    phentsize_ = read16(EH_PHENTSIZE);
    phnum_ = read16(EH_PHNUM);
    shentsize_ = read16(EH_SHENTSIZE);
    shnum_ = read16(EH_SHNUM);
    shstrndx_ = read16(EH_SHSTRNDX);
    return true;
}

//--------------------------------------------------------------------
/// Section zero carries the wider values when the ELF header uses escape fields.
/// Resolve them before treating SHT_NULL as inactive metadata.
bool elf_parser_t::resolve_extended_section_counts()
{
    const bool extended_count = shnum_ == 0 && shoff_ != 0;
    const bool extended_names = shstrndx_ == SHN_XINDEX;
    if ( !extended_count && !extended_names )
        return true;

    if ( shoff_ == 0
         || shentsize_ < SECTION_HEADER_SIZE
         || !fits(shoff_, SECTION_HEADER_SIZE)
         || read32(shoff_ + SH_TYPE) != SHT_NULL )
    {
        return fail("invalid extended section header");
    }

    if ( shnum_ == 0 )
    {
        shnum_ = read32(shoff_ + SH_SIZE);
        if ( shnum_ == 0 )
            return fail("empty extended section table");
    }
    if ( extended_names )
        shstrndx_ = read32(shoff_ + SH_LINK);
    return true;
}

//--------------------------------------------------------------------
bool elf_parser_t::check_table_entry_sizes()
{
    if ( (phnum_ != 0 && phentsize_ < PROGRAM_HEADER_SIZE)
         || (shnum_ != 0 && shentsize_ < SECTION_HEADER_SIZE) )
    {
        return fail("unexpected program or section entry size");
    }
    return true;
}

//--------------------------------------------------------------------
bool elf_parser_t::parse_program_headers()
{
    if ( phnum_ == 0 )
        return true;

    const uint64_t table_size = static_cast<uint64_t>(phnum_) * phentsize_;
    if ( phoff_ > bytes_.size() || table_size > bytes_.size() - phoff_ )
        return fail("program headers out of range");

    for ( uint32_t i = 0; i < phnum_; ++i )
    {
        const size_t header = size_t(phoff_) + size_t(i) * phentsize_;
        Segment segment;
        segment.type = read32(header + PH_TYPE);
        segment.offset = read32(header + PH_OFFSET);
        segment.va = read32(header + PH_VADDR);
        segment.filesz = read32(header + PH_FILESZ);
        segment.memsz = read32(header + PH_MEMSZ);
        segment.flags = read32(header + PH_FLAGS);

        const bool valid_extent = segment.filesz <= segment.memsz
            && fits(segment.offset, segment.filesz)
            && uint64_t(segment.va) + segment.memsz <= ADDRESS_SPACE_END;
        if ( segment.is_load() && !valid_extent )
            return fail("invalid PT_LOAD extent");

        out_->segments.push_back(segment);
    }
    return true;
}

//--------------------------------------------------------------------
bool elf_parser_t::parse_section_headers()
{
    if ( shnum_ == 0 )
    {
        if ( shstrndx_ != SHN_UNDEF )
            return fail("section names without section headers");
        return true;
    }

    const uint64_t table_size = static_cast<uint64_t>(shnum_) * shentsize_;
    if ( shoff_ == 0 || shoff_ > bytes_.size() || table_size > bytes_.size() - shoff_ )
        return fail("section headers out of range");
    if ( shstrndx_ >= shnum_ )
        return fail("section name index out of range");

    std::vector<Section> sections(shnum_);
    for ( uint32_t i = 0; i < shnum_; ++i )
    {
        const size_t header = size_t(shoff_) + size_t(i) * shentsize_;
        Section section;
        section.type = read32(header + SH_TYPE);
        // The other fields of SHT_NULL are undefined, or escape metadata.
        if ( section.type == SHT_NULL )
            continue;
        section.flags = read32(header + SH_FLAGS);
        section.addr = read32(header + SH_ADDR);
        section.offset = read32(header + SH_OFFSET);
        section.size = read32(header + SH_SIZE);
        section.link = read32(header + SH_LINK);
        section.entsize = read32(header + SH_ENTSIZE);

        if ( (section.type != SHT_NOBITS && !fits(section.offset, section.size))
             || uint64_t(section.addr) + section.size > ADDRESS_SPACE_END )
        {
            return fail("invalid section extent");
        }
        sections[i] = std::move(section);
    }

    if ( !parse_section_names(&sections) )
        return false;
    out_->sections = std::move(sections);
    return true;
}

//--------------------------------------------------------------------
/// SHN_UNDEF means there is no section-name table, not an empty table at index
/// zero. Empty real string tables separately permit index zero.
bool elf_parser_t::parse_section_names(std::vector<Section> *sections)
{
    if ( shstrndx_ == SHN_UNDEF )
        return true;

    const Section &names = (*sections)[shstrndx_];
    if ( !valid_string_table(names) )
        return fail("invalid section name string table");

    for ( uint32_t i = 0; i < shnum_; ++i )
    {
        Section &section = (*sections)[i];
        if ( section.type == SHT_NULL )
            continue;
        const size_t header = size_t(shoff_) + size_t(i) * shentsize_;
        if ( !read_string(names, read32(header + SH_NAME), &section.name) )
            return fail("section name out of range or unterminated");
    }
    return true;
}

//--------------------------------------------------------------------
bool elf_parser_t::parse_symbol_tables()
{
    const std::vector<Section> &sections = out_->sections;
    for ( size_t i = 0; i < sections.size(); ++i )
    {
        if ( sections[i].type == SHT_DYNSYM
             && !parse_symbol_table(sections[i], static_cast<uint32_t>(i), true) )
        {
            return false;
        }
    }
    for ( size_t i = 0; i < sections.size(); ++i )
    {
        if ( sections[i].type == SHT_SYMTAB
             && !parse_symbol_table(sections[i], static_cast<uint32_t>(i), false) )
        {
            return false;
        }
    }
    return true;
}

//--------------------------------------------------------------------
/// Find the SHT_SYMTAB_SHNDX table parallel to a symbol table. Having none is
/// fine, and leaves FOUND null; an invalid or duplicate one is an error.
bool elf_parser_t::find_symbol_index_table(const Section **found, uint32_t table_index,
                                           uint32_t symbol_count)
{
    *found = nullptr;
    for ( const Section &section : out_->sections )
    {
        if ( section.type != SHT_SYMTAB_SHNDX || section.link != table_index )
            continue;
        if ( *found != nullptr
             || section.entsize != sizeof(uint32_t)
             || section.size != uint64_t(symbol_count) * sizeof(uint32_t) )
        {
            return fail("invalid or duplicate symbol section-index table");
        }
        *found = &section;
    }
    return true;
}

//--------------------------------------------------------------------
bool elf_parser_t::parse_symbol_table(const Section &table, uint32_t table_index, bool dynamic)
{
    const std::vector<Section> &sections = out_->sections;
    if ( table.entsize < SYMBOL_SIZE
         || table.size % table.entsize != 0
         || table.link >= sections.size() )
    {
        return fail("invalid symbol table layout or string-table link");
    }

    const Section &strings = sections[table.link];
    if ( !valid_string_table(strings) )
        return fail("invalid symbol name string table");

    const uint32_t count = table.size / table.entsize;
    const Section *indexes = nullptr;
    if ( !find_symbol_index_table(&indexes, table_index, count) )
        return false;

    for ( uint32_t i = 0; i < count; ++i )
    {
        const size_t record = size_t(table.offset) + size_t(i) * table.entsize;
        Symbol symbol;
        symbol.value = read32(record + ST_VALUE);
        symbol.size = read32(record + ST_SIZE);
        symbol.info = bytes_[record + ST_INFO];
        symbol.shndx = read16(record + ST_SHNDX);

        const uint32_t extended =
            indexes != nullptr ? read32(size_t(indexes->offset) + size_t(i) * sizeof(uint32_t)) : 0;
        if ( symbol.shndx == SHN_XINDEX )
        {
            if ( indexes == nullptr || extended == SHN_UNDEF || extended >= sections.size() )
                return fail("missing or invalid extended symbol section index");
            symbol.shndx = extended;
        }
        else if ( extended != 0
                  || (symbol.shndx < SHN_LORESERVE && symbol.shndx >= sections.size()) )
        {
            return fail("invalid symbol section index");
        }

        symbol.from_dynsym = dynamic;
        symbol.table_section = table_index;
        symbol.index = i;
        if ( !read_string(strings, read32(record + ST_NAME), &symbol.name) )
            return fail("symbol name out of range or unterminated");

        out_->symbols.push_back(std::move(symbol));
    }
    return true;
}

//--------------------------------------------------------------------
/// Malformed relocation sections are skipped rather than rejected: the rest of
/// the file stays usable, and they simply contribute no records.
void elf_parser_t::parse_relocations()
{
    for ( const Section &section : out_->sections )
    {
        if ( section.type != SHT_RELA && section.type != SHT_REL )
            continue;
        const bool explicit_addend = section.type == SHT_RELA;
        const uint32_t minimum_size = explicit_addend ? RELA_SIZE : REL_SIZE;
        if ( section.entsize != 0 && section.entsize < minimum_size )
            continue;
        const uint32_t record_size = section.entsize != 0 ? section.entsize : minimum_size;
        if ( section.size % record_size != 0 || !fits(section.offset, section.size) )
            continue;

        const uint32_t count = section.size / record_size;
        for ( uint32_t i = 0; i < count; ++i )
        {
            const size_t record = size_t(section.offset) + size_t(i) * record_size;
            const uint32_t info = read32(record + R_INFO);
            Reloc reloc;
            reloc.section = section.name;
            reloc.offset = read32(record + R_OFFSET);
            reloc.type = info & 0xff;
            reloc.sym = info >> 8;
            reloc.symbol_table = section.link;
            reloc.explicit_addend = explicit_addend;
            reloc.addend = explicit_addend ? static_cast<int32_t>(read32(record + R_ADDEND)) : 0;
            out_->relocs.push_back(std::move(reloc));
        }
    }
}

//--------------------------------------------------------------------
bool elf_parser_t::valid_string_table(const Section &table) const
{
    if ( table.type != SHT_STRTAB || !fits(table.offset, table.size) )
        return false;
    if ( table.size == 0 )
        return true;
    return bytes_[table.offset] == 0 && bytes_[size_t(table.offset) + table.size - 1] == 0;
}

//--------------------------------------------------------------------
bool elf_parser_t::read_string(const Section &table, uint32_t index, std::string *out) const
{
    out->clear();
    // Zero means no name, including in an empty table.
    if ( index == 0 )
        return true;
    if ( index >= table.size || !fits(table.offset, table.size) )
        return false;

    const char *start =
        reinterpret_cast<const char *>(bytes_.data() + size_t(table.offset) + index);
    const void *end = std::memchr(start, 0, table.size - index);
    if ( end == nullptr )
        return false;
    out->assign(start, static_cast<const char *>(end));
    return true;
}

//--------------------------------------------------------------------
bool parse_elf(const std::vector<uint8_t> &bytes, ImageMetadata *out, std::string *error)
{
    elf_parser_t parser(bytes, out, error);
    return parser.parse();
}

} // namespace ipp
