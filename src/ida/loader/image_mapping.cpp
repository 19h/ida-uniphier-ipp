#include <iterator>
#include <set>
#include <string>

#include <ida.hpp>

#include <bytes.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <segment.hpp>

#include "loader/loader_steps.hpp"

namespace ipp::loader
{

namespace
{

/// Bits of Segment::flags that map directly to segment permissions.
constexpr unsigned PROGRAM_HEADER_PERMISSIONS = SEGPERM_EXEC | SEGPERM_WRITE | SEGPERM_READ;

} // namespace

//--------------------------------------------------------------------
std::string database_name(unsigned image_number, const std::string &name)
{
    if ( image_number == 0 )
        return name;
    return "image" + std::to_string(image_number) + "_" + name;
}

//--------------------------------------------------------------------
/// Overlap is a load error, never permission to replace another image.
static void require_unmapped(ea_t start, ea_t end)
{
    ea_t ea = start;
    while ( ea < end )
    {
        if ( is_mapped(ea) )
            loader_failure("companion mapping overlaps existing memory at 0x%llx", uint64(ea));
        const ea_t next = get_next_segment_ea(ea);
        if ( next >= end )
            break;
        ea = next;
    }
}

//--------------------------------------------------------------------
/// The addresses at which [START, END) splits to preserve section boundaries.
static std::set<ea_t> segment_boundaries(const ipp::Image &image, ea_t start, ea_t end)
{
    std::set<ea_t> boundaries = {start, end};
    for ( const ipp::Section &section : image.sections() )
    {
        if ( section.is_allocated()
             && section.size != 0
             && section.addr >= start
             && uint64(section.addr) + section.size <= end )
        {
            boundaries.insert(section.addr);
            boundaries.insert(ea_t(section.addr) + section.size);
        }
    }
    return boundaries;
}

//--------------------------------------------------------------------
static const ipp::Section *find_covering_section(const ipp::Image &image, ea_t start, ea_t end)
{
    for ( const ipp::Section &section : image.sections() )
    {
        if ( section.is_allocated()
             && section.size != 0
             && start >= section.addr
             && end <= uint64(section.addr) + section.size )
        {
            return &section;
        }
    }
    return nullptr;
}

//--------------------------------------------------------------------
/// Add one segment covering [START, END), described by its section if it has one.
static void add_image_segment(const ipp::Image &image, const ipp::Segment &load, ea_t start,
                              ea_t end, sel_t selector, unsigned image_number, unsigned serial)
{
    const ipp::Section *section = find_covering_section(image, start, end);

    // Nameless mapped sections receive generated names.
    char generated_name[40];
    qsnprintf(generated_name, sizeof(generated_name), "IMAGE%u_LOAD%u", image_number, serial);
    const bool has_name = section != nullptr && !section->name.empty();
    const std::string name = database_name(image_number, has_name ? section->name : generated_name);

    const bool is_code = section != nullptr ? section->is_executable()
                                            : image.sections().empty() && load.is_executable();

    unsigned permissions = load.flags & PROGRAM_HEADER_PERMISSIONS;
    if ( section != nullptr )
    {
        permissions = SEGPERM_READ;
        if ( section->is_writable() )
            permissions |= SEGPERM_WRITE;
        if ( is_code )
            permissions |= SEGPERM_EXEC;
    }

    const char *segment_class = "DATA";
    if ( is_code )
        segment_class = "CODE";
    else if ( section != nullptr && section->is_nobits() )
        segment_class = "BSS";

    segment_info_t info;
    info.start_ea = start;
    info.end_ea = end;
    info.set_sel(selector);
    info.set_bitness(1);
    info.set_align(saRelByte);
    info.set_comb(scPub);
    info.set_perm(static_cast<uchar>(permissions));
    info.set_name(name.c_str());
    info.set_sclass(segment_class);
    if ( !add_segment_ex(&info, ADDSEG_SPARSE) )
        loader_failure("cannot map %s", name.c_str());
}

//--------------------------------------------------------------------
void map_image(const ipp::Image &image, linput_t *input, unsigned image_number)
{
    const sel_t selector = allocate_selector(0);
    set_selector(selector, 0);

    unsigned serial = 0;
    for ( const ipp::Segment &load : image.segments() )
    {
        if ( !load.is_load() || load.memsz == 0 )
            continue;

        const ea_t start = load.va;
        const ea_t end = start + load.memsz;
        require_unmapped(start, end);

        const std::set<ea_t> boundaries = segment_boundaries(image, start, end);
        for ( auto p = boundaries.begin(), q = std::next(p); q != boundaries.end(); ++p, ++q )
        {
            add_image_segment(image, load, *p, *q, selector, image_number, serial);
            ++serial;
        }

        if ( load.filesz != 0
             && !file2base(input, load.offset, start, start + load.filesz, FILEREG_PATCHABLE) )
        {
            loader_failure("file2base failed");
        }
    }
}

} // namespace ipp::loader
