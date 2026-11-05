// ELF32 big-endian UniPhier IPP loader. Preserve file mappings, section boundaries,
// function extents, imports, and observed relocation operations.

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <ida.hpp>

#include <diskio.hpp>
#include <entry.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <segment.hpp>

#include "ipp/elf.hpp"
#include "loader/loader_steps.hpp"

namespace ipp::loader
{

namespace
{

constexpr size_t ELF_HEADER_SIZE = 52;
constexpr int64 MAX_INPUT_SIZE = int64(64) * 1024 * 1024;
constexpr uint16_t ELF_TYPE_SHARED_OBJECT = 3;
constexpr std::string_view COMPANIONS_OPTION = "companions=";

using image_list_t = std::vector<std::unique_ptr<ipp::Image>>;

} // namespace

//--------------------------------------------------------------------
static int idaapi accept_file(qstring *format, qstring *processor, linput_t *input,
                              const char * /*name*/)
{
    if ( format == nullptr || processor == nullptr || input == nullptr )
        return 0;

    uint8 header[ELF_HEADER_SIZE];
    qlseek(input, 0, SEEK_SET);
    if ( qlread(input, header, sizeof(header)) != static_cast<ssize_t>(sizeof(header))
         || std::memcmp(header, "\177ELF", 4) != 0
         || header[4] != 1 // ELFCLASS32
         || header[5] != 2 // ELFDATA2MSB
         || header[18] != 0x10
         || header[19] != 0x40 )
    {
        return 0;
    }
    *format = "UniPhier IPP ELF";
    *processor = "ipp";
    return 1;
}

//--------------------------------------------------------------------
static void read_primary_image(ipp::Image *image, linput_t *input)
{
    const int64 size = qlsize(input);
    if ( size < int64(ELF_HEADER_SIZE) || size > MAX_INPUT_SIZE )
        loader_failure("unexpected file size");

    std::vector<uint8_t> raw(static_cast<size_t>(size));
    qlseek(input, 0, SEEK_SET);
    if ( qlread(input, raw.data(), raw.size()) != static_cast<ssize_t>(raw.size()) )
        loader_failure("short read");
    if ( !image->load_bytes(raw.data(), raw.size(), "input") )
        loader_failure("%s", image->error().c_str());
}

//--------------------------------------------------------------------
static void map_companion(image_list_t *companions, const std::string &path)
{
    auto image = std::make_unique<ipp::Image>();
    if ( !image->load_file(path) )
        loader_failure("%s", image->error().c_str());

    linput_t *input = open_linput(path.c_str(), false);
    if ( input == nullptr )
        loader_failure("cannot open companion");
    map_image(*image, input, static_cast<unsigned>(companions->size() + 1));
    close_linput(input);
    companions->push_back(std::move(image));
}

//--------------------------------------------------------------------
/// Map the images named by -Oelfipp:companions=<path>;<path>. Explicit opt-in: no
/// automatic file search, rebasing, or modification of the supplied files.
static image_list_t map_companions()
{
    image_list_t companions;
    const char *options = get_plugin_options("elfipp");
    if ( options == nullptr
         || std::string_view(options).compare(0, COMPANIONS_OPTION.size(), COMPANIONS_OPTION) != 0 )
    {
        return companions;
    }

    const std::string paths = options + COMPANIONS_OPTION.size();
    size_t begin = 0;
    while ( begin < paths.size() )
    {
        const size_t end = paths.find(';', begin);
        map_companion(&companions,
                      paths.substr(begin, end == std::string::npos ? end : end - begin));
        if ( end == std::string::npos )
            break;
        begin = end + 1;
    }
    return companions;
}

//--------------------------------------------------------------------
/// ELF e_entry=0 explicitly denotes absence, unlike a decoded target whose separate
/// has_target flag can establish address zero as valid.
static void set_program_entry(const ipp::Image &primary)
{
    const uint32_t entry = primary.entry();
    if ( entry == 0 )
        return;
    if ( !primary.executable_va(entry) )
    {
        msg("IPP: e_entry 0x%llx is outside executable mappings; no entry added\n", uint64(entry));
        return;
    }

    segment_info_t segment;
    if ( !get_segment_info(&segment, entry) )
        loader_failure("entry point is not mapped");

    // The entry list does not initialize these program-start fields. All selectors
    // have base zero, so the initial IP is the linked ELF VA.
    inf_set_start_cs(segment.get_sel());
    inf_set_start_ip(entry);
    inf_set_start_ea(entry);
    add_entry(entry, entry, "start", true);
}

//--------------------------------------------------------------------
static void idaapi load_file(linput_t *input, ushort /*neflags*/, const char * /*format*/)
{
    ipp::Image primary;
    read_primary_image(&primary, input);

    if ( !set_processor_type("ipp", SETPROC_LOADER) )
        loader_failure("processor ipp was not loaded");
    inf_set_be(true);
    inf_set_64bit(false);
    inf_set_32bit(true);
    inf_set_dll(primary.type() == ELF_TYPE_SHARED_OBJECT);

    // Map every image first, so that references between them resolve.
    map_image(primary, input, 0);
    const image_list_t companions = map_companions();

    apply_relocations(primary, 0);
    define_symbols(primary, 0);
    for ( size_t i = 0; i < companions.size(); ++i )
    {
        const unsigned image_number = static_cast<unsigned>(i + 1);
        apply_relocations(*companions[i], image_number);
        define_symbols(*companions[i], image_number);
    }

    set_program_entry(primary);
}

} // namespace ipp::loader

idaman loader_t LDSC = {
    IDP_INTERFACE_VERSION,
    0,
    ipp::loader::accept_file,
    ipp::loader::load_file,
    nullptr,
    nullptr,
    nullptr,
};
