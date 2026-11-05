// Image: loading an ELF file and querying its contents by name and address.

#include <fstream>
#include <string>

#include <sys/stat.h>

#include "elf/elf_format.hpp"
#include "elf/elf_parser.hpp"
#include "ipp/elf.hpp"

namespace ipp
{

//--------------------------------------------------------------------
const char *Image::reloc_name(uint32_t /*type*/)
{
    return nullptr;
}

//--------------------------------------------------------------------
void Image::reset(const std::string &label)
{
    label_ = label;
    error_.clear();
    bytes_.clear();
    metadata_ = {};
}

//--------------------------------------------------------------------
bool Image::parse()
{
    if ( parse_elf(bytes_, &metadata_, &error_) )
        return true;
    metadata_ = {};
    return false;
}

//--------------------------------------------------------------------
bool Image::load_file(const std::string &path)
{
    reset(path);

    // stat() rather than std::filesystem::file_size(): non-regular inputs such as
    // devices must reach the ELF checks rather than fail as a size query.
    struct stat info;
    if ( stat(path.c_str(), &info) != 0 || info.st_size < 0 )
    {
        error_ = "stat failed: " + path;
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if ( !file.is_open() )
    {
        error_ = "open failed: " + path;
        return false;
    }

    bytes_.resize(static_cast<size_t>(info.st_size));
    if ( !bytes_.empty() )
    {
        file.read(reinterpret_cast<char *>(bytes_.data()),
                  static_cast<std::streamsize>(bytes_.size()));
        if ( static_cast<size_t>(file.gcount()) != bytes_.size() )
        {
            error_ = "short read: " + path;
            bytes_.clear();
            return false;
        }
    }
    return parse();
}

//--------------------------------------------------------------------
bool Image::load_bytes(const uint8_t *data, size_t size, const std::string &label)
{
    reset(label);
    if ( data == nullptr && size != 0 )
    {
        error_ = "null ELF input";
        return false;
    }
    if ( size != 0 )
        bytes_.assign(data, data + size);
    return parse();
}

//--------------------------------------------------------------------
const Section *Image::section(std::string_view name) const
{
    for ( const Section &section : metadata_.sections )
    {
        if ( section.name == name )
            return &section;
    }
    return nullptr;
}

//--------------------------------------------------------------------
const Symbol *Image::function(std::string_view name) const
{
    const Symbol *found = nullptr;
    for ( const Symbol &symbol : metadata_.symbols )
    {
        if ( symbol.name != name
             || !symbol.is_function()
             || !symbol.is_defined()
             || symbol.size == 0 )
        {
            continue;
        }
        if ( found == nullptr || (symbol.from_dynsym && !found->from_dynsym) )
            found = &symbol;
    }
    return found;
}

//--------------------------------------------------------------------
const Symbol *Image::reloc_symbol(const Reloc &reloc) const
{
    for ( const Symbol &symbol : metadata_.symbols )
    {
        if ( symbol.table_section == reloc.symbol_table && symbol.index == reloc.sym )
            return &symbol;
    }
    return nullptr;
}

//--------------------------------------------------------------------
/// \return true if [VA, VA+LENGTH) lies within [BASE, BASE+SIZE), without overflow.
static bool extent_contains(uint32_t base, uint32_t size, uint32_t va, uint32_t length)
{
    return va >= base && va - base < size && length <= size - (va - base);
}

//--------------------------------------------------------------------
bool Image::executable_va(uint32_t va, uint32_t length) const
{
    bool has_executable_sections = false;
    for ( const Section &section : metadata_.sections )
    {
        if ( section.type == elf::SHT_NULL || !section.is_allocated() || !section.is_executable() )
            continue;
        has_executable_sections = true;
        if ( extent_contains(section.addr, section.size, va, length) )
            return true;
    }
    if ( has_executable_sections )
        return false;

    for ( const Segment &segment : metadata_.segments )
    {
        if ( segment.is_load()
             && segment.is_executable()
             && extent_contains(segment.va, segment.memsz, va, length) )
        {
            return true;
        }
    }
    return false;
}

//--------------------------------------------------------------------
bool Image::read_va(uint32_t va, uint32_t length, std::vector<uint8_t> *out) const
{
    if ( out == nullptr )
        return false;
    out->clear();

    const auto copy_from_file = [&](size_t offset)
    {
        if ( !extent_fits(bytes_.size(), offset, length) )
            return false;
        out->assign(bytes_.data() + offset, bytes_.data() + offset + length);
        return true;
    };

    for ( const Section &section : metadata_.sections )
    {
        if ( section.type == elf::SHT_NULL
             || section.is_nobits()
             || !section.is_allocated()
             || section.size == 0
             || va < section.addr )
        {
            continue;
        }
        const uint32_t delta = va - section.addr;
        if ( delta > section.size || length > section.size - delta )
            continue;
        return copy_from_file(size_t(section.offset) + delta);
    }

    for ( const Segment &segment : metadata_.segments )
    {
        if ( !segment.is_load() || segment.filesz == 0 || va < segment.va )
            continue;
        const uint32_t delta = va - segment.va;
        if ( delta > segment.filesz || length > segment.filesz - delta )
            continue;
        return copy_from_file(size_t(segment.offset) + delta);
    }
    return false;
}

//--------------------------------------------------------------------
bool Image::contains_cstring(std::string_view text) const
{
    if ( text.empty() )
        return false;

    std::string terminated(text);
    terminated.push_back('\0');
    const std::string_view contents(reinterpret_cast<const char *>(bytes_.data()), bytes_.size());
    return contents.find(terminated) != std::string_view::npos;
}

} // namespace ipp
