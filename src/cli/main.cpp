// ipp-dec: command-line disassembly and coverage reporting.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ipp/decode.hpp"
#include "ipp/elf.hpp"

namespace fs = std::filesystem;

namespace
{

constexpr int EXIT_FAILED = 1;
constexpr int EXIT_USAGE = 2;

/// Bytes of one section, classified by what the decoder made of them.
struct section_coverage_t
{
    uint64_t instruction_bytes = 0;
    uint64_t noncode_bytes = 0;
    uint64_t unresolved_bytes = 0;
};

/// A range of virtual addresses to disassemble.
struct extent_t
{
    uint32_t va;
    uint32_t length;
};

} // namespace

//--------------------------------------------------------------------
static void print_usage()
{
    std::cerr
        << "usage:\n"
        << "  ipp-dec <elf> --section <name>\n"
        << "  ipp-dec <elf> --symbol <name>\n"
        << "  ipp-dec <elf> --va <hex> --length <hex-or-dec>\n"
        << "  ipp-dec --forms\n"
        << "  ipp-dec --coverage <elf>...\n";
}

//--------------------------------------------------------------------
/// Parse decimal, or hex and octal with their usual prefixes.
static std::optional<uint32_t> parse_u32(const char *text)
{
    if ( text[0] == '\0' )
        return std::nullopt;
    char *end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 0);
    if ( end == text || *end != '\0' || value > 0xffffffffULL )
        return std::nullopt;
    return static_cast<uint32_t>(value);
}

//--------------------------------------------------------------------
static bool has_elf_magic(const fs::path &path)
{
    std::ifstream file(path, std::ios::binary);
    char magic[4];
    file.read(magic, sizeof(magic));
    return file.gcount() == sizeof(magic) && std::memcmp(magic, "\177ELF", sizeof(magic)) == 0;
}

//--------------------------------------------------------------------
/// Expand directories to the ELF files directly inside them. Other arguments are
/// taken as files, so a bad path is reported when it fails to load.
static std::vector<std::string> collect_elf_paths(int count, char **arguments)
{
    std::vector<std::string> paths;
    for ( int i = 0; i < count; ++i )
    {
        if ( !fs::is_directory(arguments[i]) )
        {
            paths.emplace_back(arguments[i]);
            continue;
        }
        for ( const fs::directory_entry &entry : fs::directory_iterator(arguments[i]) )
        {
            if ( entry.is_regular_file() && has_elf_magic(entry.path()) )
                paths.push_back(entry.path().string());
        }
    }
    std::sort(paths.begin(), paths.end());
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    return paths;
}

//--------------------------------------------------------------------
/// Decode BYTES from start to end, without folding, to classify every byte.
/// \return nothing if the decoder fails to make progress.
static std::optional<section_coverage_t> measure_coverage(const std::vector<uint8_t> &bytes,
                                                          uint32_t address)
{
    section_coverage_t coverage;
    size_t offset = 0;
    while ( offset < bytes.size() )
    {
        const size_t remaining = bytes.size() - offset;
        const ipp::Decoded insn = ipp::decode_one(bytes.data() + offset, remaining,
                                                  address + static_cast<uint32_t>(offset));
        if ( insn.length == 0 || insn.length > remaining )
            return std::nullopt;

        switch ( insn.kind )
        {
            case ipp::Kind::Insn:
                coverage.instruction_bytes += insn.length;
                break;
            case ipp::Kind::NonCode:
                coverage.noncode_bytes += insn.length;
                break;
            case ipp::Kind::Unresolved:
                coverage.unresolved_bytes += insn.length;
                break;
        }
        offset += insn.length;
    }
    return coverage;
}

//--------------------------------------------------------------------
static int report_file_coverage(const std::string &path)
{
    ipp::Image image;
    if ( !image.load_file(path) )
    {
        std::cerr << image.error() << "\n";
        return EXIT_FAILED;
    }

    const std::string file = fs::path(image.label()).filename().string();
    bool any_code = false;
    for ( const ipp::Section &section : image.sections() )
    {
        if ( !section.has_code() )
            continue;
        any_code = true;

        std::vector<uint8_t> bytes;
        if ( !image.read_va(section.addr, section.size, &bytes) )
        {
            std::cerr << "unreadable " << file << " " << section.name << "\n";
            return EXIT_FAILED;
        }

        const std::optional<section_coverage_t> coverage = measure_coverage(bytes, section.addr);
        if ( !coverage )
            return EXIT_FAILED;

        std::cout
            << file
            << "\t"
            << section.name
            << "\t"
            << section.size
            << "\t"
            << coverage->instruction_bytes
            << "\t"
            << coverage->noncode_bytes
            << "\t"
            << coverage->unresolved_bytes
            << "\n";
    }
    if ( !any_code )
        std::cout << file << "\t<no executable sections>\t0\t0\t0\t0\n";
    return EXIT_SUCCESS;
}

//--------------------------------------------------------------------
static int run_coverage(int count, char **arguments)
{
    std::cout << "file\tsection\tsize\tinsn_bytes\tnoncode_bytes\tunresolved_bytes\n";
    const std::vector<std::string> paths = collect_elf_paths(count, arguments);
    if ( paths.empty() )
    {
        std::cerr << "no ELF inputs\n";
        return EXIT_FAILED;
    }
    for ( const std::string &path : paths )
    {
        const int status = report_file_coverage(path);
        if ( status != EXIT_SUCCESS )
            return status;
    }
    return EXIT_SUCCESS;
}

//--------------------------------------------------------------------
static int run_list_forms()
{
    std::cout << "form\tmnemonic\tflow\tevidence\n";
    const ipp::Form *forms = ipp::form_table();
    for ( size_t i = 0; i < ipp::form_count(); ++i )
    {
        const ipp::Form &form = forms[i];
        std::cout
            << form.id
            << "\t"
            << form.mnemonic
            << "\t"
            << ipp::flow_name(ipp::Kind::Insn, form.flow)
            << "\t"
            << form.evidence
            << "\n";
    }
    return EXIT_SUCCESS;
}

//--------------------------------------------------------------------
/// Addresses that control flow can enter other than by falling through: the
/// program entry and all function symbols. These gate the call folds.
static std::vector<uint32_t> collect_known_entries(const ipp::Image &image)
{
    std::vector<uint32_t> entries;
    if ( image.entry() != 0 && image.executable_va(image.entry()) )
        entries.push_back(image.entry());
    for ( const ipp::Symbol &symbol : image.symbols() )
    {
        if ( symbol.is_defined() && symbol.is_function() && image.executable_va(symbol.value) )
            entries.push_back(symbol.value);
    }
    return entries;
}

//--------------------------------------------------------------------
static void print_disassembly(const ipp::Image &image, const std::vector<uint8_t> &bytes,
                              uint32_t va)
{
    const std::vector<uint32_t> entries = collect_known_entries(image);
    const std::vector<ipp::Decoded> insns =
        ipp::decode_linear(bytes.data(), bytes.size(), va, entries);
    size_t offset = 0;
    for ( const ipp::Decoded &insn : insns )
    {
        std::cout << ipp::format_insn(insn, bytes.data() + offset) << "\n";
        offset += insn.length;
    }
}

//--------------------------------------------------------------------
static int run_disassemble(int argc, char **argv)
{
    ipp::Image image;
    if ( !image.load_file(argv[1]) )
    {
        std::cerr << image.error() << "\n";
        return EXIT_FAILED;
    }

    const std::string_view selector = argv[2];
    const char *argument = argv[3];
    extent_t extent = {};
    if ( selector == "--section" )
    {
        const ipp::Section *section = image.section(argument);
        if ( section == nullptr )
        {
            std::cerr << "no section " << argument << "\n";
            return EXIT_FAILED;
        }
        extent = {section->addr, section->size};
    }
    else if ( selector == "--symbol" )
    {
        const ipp::Symbol *symbol = image.function(argument);
        if ( symbol == nullptr )
        {
            std::cerr << "no function " << argument << "\n";
            return EXIT_FAILED;
        }
        extent = {symbol->value, symbol->size};
    }
    else if ( selector == "--va" )
    {
        const std::optional<uint32_t> va = parse_u32(argument);
        if ( !va || argc < 6 || std::string_view(argv[4]) != "--length" )
        {
            print_usage();
            return EXIT_USAGE;
        }
        const std::optional<uint32_t> length = parse_u32(argv[5]);
        if ( !length )
        {
            print_usage();
            return EXIT_USAGE;
        }
        extent = {*va, *length};
    }
    else
    {
        print_usage();
        return EXIT_USAGE;
    }

    std::vector<uint8_t> bytes;
    if ( !image.read_va(extent.va, extent.length, &bytes) )
    {
        std::cerr << "va extent not in a loaded section\n";
        return EXIT_FAILED;
    }
    print_disassembly(image, bytes, extent.va);
    return EXIT_SUCCESS;
}

//--------------------------------------------------------------------
int main(int argc, char **argv)
{
    if ( argc >= 2 && std::string_view(argv[1]) == "--forms" )
        return run_list_forms();
    if ( argc >= 2 && std::string_view(argv[1]) == "--coverage" )
        return run_coverage(argc - 2, argv + 2);
    if ( argc < 4 )
    {
        print_usage();
        return EXIT_USAGE;
    }
    return run_disassemble(argc, argv);
}
