// Corpus test: decode every executable section of the 212 supplied ELF images and
// hold the results to exact baselines. Specific to the supplied corpus.

#include <cstdio>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "ipp/decode.hpp"
#include "ipp/elf.hpp"

namespace fs = std::filesystem;

namespace
{

// Exact baselines of the supplied corpus.
constexpr unsigned EXPECTED_FILES = 212;
constexpr unsigned EXPECTED_SECTIONS = 696;
constexpr uint64_t EXPECTED_BYTES = 98302772;
constexpr uint64_t EXPECTED_DIRECT_TARGETS = 3434046;
constexpr uint64_t EXPECTED_SYMBOLS = 34574;
constexpr uint64_t EXPECTED_FAR_CALLS = 922846;

// Separate ceilings, so that one category cannot hide new gaps in the other. The
// 19,107 compact external-access candidates were previously misclassified as
// ordinary halfword memory; their withdrawal cannot hide new wide gaps.
constexpr uint64_t MAX_UNRESOLVED_COMPACT_BYTES = 38214;
constexpr uint64_t MAX_UNRESOLVED_WIDE_BYTES = 38836;

constexpr unsigned MAX_REPORTED_INVALID = 12;

struct corpus_stats_t
{
    unsigned files = 0;
    unsigned sections = 0;
    uint64_t bytes = 0;
    uint64_t items = 0;
    uint64_t unresolved_bytes = 0;
    uint64_t unresolved_compact_bytes = 0;
    uint64_t unresolved_wide_bytes = 0;
    uint64_t direct_targets = 0;
    uint64_t symbols = 0;
    uint64_t far_calls = 0;
    unsigned boundary_errors = 0;
    unsigned typed_invalid = 0;
    unsigned unexpected_unknown = 0;
};

} // namespace

//--------------------------------------------------------------------
/// IDA databases and their sidecars live beside the samples without being samples.
static bool is_database_file(const fs::path &path)
{
    static const std::set<std::string> extensions = {".id0", ".id1", ".id2", ".nam",
                                                     ".til", ".i64", ".idb"};
    return extensions.count(path.extension().string()) != 0;
}

//--------------------------------------------------------------------
/// Account for one unresolved record. Only the 0x4080/0x4090 compact patterns are
/// known gaps; any other compact or truncated record is unexpected.
static void count_unresolved(corpus_stats_t *stats, const ipp::Decoded &insn, const uint8_t *raw)
{
    stats->unresolved_bytes += insn.length;
    if ( insn.length == 4 )
    {
        stats->unresolved_wide_bytes += 4;
    }
    else if ( insn.length == 2 )
    {
        const unsigned parcel = (raw[0] << 8) | raw[1];
        const unsigned pattern = parcel & 0x70f0;
        if ( pattern != 0x4080 && pattern != 0x4090 )
            ++stats->unexpected_unknown;
        stats->unresolved_compact_bytes += 2;
    }
    else
    {
        ++stats->unexpected_unknown;
    }
}

//--------------------------------------------------------------------
/// Function symbols contained in SECTION must start and end on boundaries.
static void check_symbol_boundaries(corpus_stats_t *stats, const ipp::Image &image,
                                    const ipp::Section &section, const std::vector<bool> &boundary)
{
    for ( const ipp::Symbol &symbol : image.symbols() )
    {
        if ( !symbol.is_function()
             || !symbol.is_defined()
             || symbol.size == 0
             || symbol.value < section.addr
             || uint64_t(symbol.value) + symbol.size > uint64_t(section.addr) + section.size )
        {
            continue;
        }
        ++stats->symbols;
        const uint32_t start = symbol.value - section.addr;
        if ( !boundary[start] || !boundary[start + symbol.size] )
            ++stats->boundary_errors;
    }
}

//--------------------------------------------------------------------
/// \return false if the decoder fails to make progress.
static bool scan_section(corpus_stats_t *stats, const ipp::Image &image,
                         const ipp::Section &section, const fs::path &path)
{
    ++stats->sections;
    stats->bytes += section.size;

    const uint8_t *raw = image.bytes().data() + section.offset;
    std::vector<bool> boundary(section.size + 1, false);
    std::vector<uint32_t> direct_targets;
    ipp::Decoded previous;
    uint32_t offset = 0;
    while ( offset < section.size )
    {
        const uint32_t remaining = section.size - offset;
        ipp::Decoded insn = ipp::decode_one(raw + offset, remaining, section.addr + offset);
        if ( insn.length == 0 || insn.length > remaining )
            return false;

        boundary[offset] = true;
        ++stats->items;
        if ( insn.kind == ipp::Kind::Unresolved )
        {
            count_unresolved(stats, insn, raw + offset);
        }
        else if ( !ipp::valid_instruction(insn) )
        {
            if ( stats->typed_invalid < MAX_REPORTED_INVALID )
            {
                std::fprintf(stderr, "invalid typed operands %s:%08x %s\n", path.filename().c_str(),
                             insn.address, insn.operands);
            }
            ++stats->typed_invalid;
        }

        // Existing direct displacements are checked independently of folding.
        if ( insn.has_target
             && insn.target >= section.addr
             && insn.target - section.addr < section.size )
        {
            direct_targets.push_back(insn.target - section.addr);
        }
        if ( ipp::resolve_far_call(previous, &insn) )
            ++stats->far_calls;

        previous = insn;
        offset += insn.length;
    }
    boundary[section.size] = true;

    for ( uint32_t target : direct_targets )
    {
        ++stats->direct_targets;
        if ( !boundary[target] )
            ++stats->boundary_errors;
    }
    check_symbol_boundaries(stats, image, section, boundary);
    return true;
}

//--------------------------------------------------------------------
int main(int argc, char **argv)
{
    if ( argc != 2 )
        return 2;

    corpus_stats_t stats;
    for ( const fs::directory_entry &entry : fs::directory_iterator(argv[1]) )
    {
        const fs::path &path = entry.path();
        if ( !entry.is_regular_file() || path.filename() == ".DS_Store" || is_database_file(path) )
            continue;

        ipp::Image image;
        if ( !image.load_file(path.string()) )
        {
            std::fprintf(stderr, "%s: %s\n", path.c_str(), image.error().c_str());
            return 1;
        }
        ++stats.files;
        for ( const ipp::Section &section : image.sections() )
        {
            if ( section.has_code() && !scan_section(&stats, image, section, path) )
                return 1;
        }
    }

    std::printf(
        "files=%u sections=%u bytes=%llu items=%llu unresolved_bytes=%llu direct_targets=%llu "
        "symbols=%llu far_calls=%llu boundary_errors=%u typed_invalid=%u\n",
        stats.files, stats.sections, static_cast<unsigned long long>(stats.bytes),
        static_cast<unsigned long long>(stats.items),
        static_cast<unsigned long long>(stats.unresolved_bytes),
        static_cast<unsigned long long>(stats.direct_targets),
        static_cast<unsigned long long>(stats.symbols),
        static_cast<unsigned long long>(stats.far_calls), stats.boundary_errors,
        stats.typed_invalid);
    if ( stats.files != EXPECTED_FILES
         || stats.sections != EXPECTED_SECTIONS
         || stats.bytes != EXPECTED_BYTES
         || stats.direct_targets != EXPECTED_DIRECT_TARGETS
         || stats.symbols != EXPECTED_SYMBOLS
         || stats.far_calls != EXPECTED_FAR_CALLS
         || stats.boundary_errors != 0
         || stats.typed_invalid != 0 )
    {
        return 1;
    }

    std::printf("unresolved_compact_bytes=%llu unresolved_wide_bytes=%llu unexpected_unknown=%u\n",
                static_cast<unsigned long long>(stats.unresolved_compact_bytes),
                static_cast<unsigned long long>(stats.unresolved_wide_bytes),
                stats.unexpected_unknown);
    const bool within_ceilings = stats.unresolved_compact_bytes <= MAX_UNRESOLVED_COMPACT_BYTES
        && stats.unresolved_wide_bytes <= MAX_UNRESOLVED_WIDE_BYTES
        && stats.unexpected_unknown == 0;
    return within_ceilings ? 0 : 1;
}
