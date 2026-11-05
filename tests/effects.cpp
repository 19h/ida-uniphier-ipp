// Validate access ranges and measure semantic-policy occurrences in supplied code.
// This is not native instruction execution or a vendor encoding oracle.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "ipp/decode.hpp"
#include "ipp/elf.hpp"

namespace fs = std::filesystem;

namespace
{

constexpr unsigned EXPECTED_FILES = 212;
constexpr unsigned C7_CFR_BIT = 7;
constexpr unsigned PREDICATE_COUNT = 8;

struct effect_stats_t
{
    unsigned files = 0;
    uint64_t policy_sites_checked = 0;
    uint64_t suppressed_outputs = 0;
    uint64_t scalar_sinks = 0;
    uint64_t paired_sinks = 0;
    uint64_t mh_move_sites = 0;
    uint64_t mul_sites = 0;
    uint64_t sp_write_sites = 0;
    uint64_t sp_range_write_sites = 0;
    uint64_t sp_overlapping_write_sites = 0;
    uint64_t sp_unknown_delta_sites = 0;
    uint64_t odd_fd_sites = 0;
    uint64_t unconditional_sites = 0;
    uint64_t explicit_c7_reads = 0;
    uint64_t aggregate_cfr_sites = 0;
    uint64_t aggregate_cfr_samples = 0;
    std::map<unsigned, uint64_t> effect_bit_sites;
    std::vector<bool> sampled_aggregate_cfr;
};

} // namespace

//--------------------------------------------------------------------
static std::vector<fs::path> find_elf_files(const fs::path &directory)
{
    std::vector<fs::path> paths;
    for ( const fs::directory_entry &entry : fs::directory_iterator(directory) )
    {
        if ( !entry.is_regular_file() )
            continue;
        std::ifstream stream(entry.path(), std::ios::binary);
        char magic[4];
        stream.read(magic, sizeof(magic));
        if ( stream.gcount() == sizeof(magic) && std::memcmp(magic, "\177ELF", sizeof(magic)) == 0 )
            paths.push_back(entry.path());
    }
    return paths;
}

//--------------------------------------------------------------------
/// A true stack delta must never accompany a range write or overlapping update.
/// \return false if a delta is reported known when it cannot be.
static bool check_stack_writes(effect_stats_t *stats, const ipp::Decoded &insn,
                               const fs::path &path)
{
    bool replaced = false;
    bool range_write = false;
    bool update = false;
    for ( const ipp::Operand &operand : insn.ops )
    {
        if ( operand.writes() )
        {
            replaced |= operand.is_register(ipp::SP);
            if ( operand.range_covers(ipp::SP) )
            {
                replaced = true;
                range_write = true;
            }
        }
        update |= operand.reg == ipp::SP && operand.updates_base();
    }
    if ( !replaced && !update )
        return true;

    ++stats->sp_write_sites;
    stats->sp_range_write_sites += range_write;
    stats->sp_overlapping_write_sites += replaced && update;
    int64_t delta = 0;
    const bool known = ipp::stack_pointer_delta(insn, &delta);
    stats->sp_unknown_delta_sites += !known;
    if ( (range_write || (replaced && update)) && known )
    {
        std::fprintf(stderr, "false known SP delta %s:%08x\n", path.filename().c_str(),
                     insn.address);
        return false;
    }
    return true;
}

//--------------------------------------------------------------------
/// \return false if an access record is outside its register, or names C7.
static bool check_access_ranges(const ipp::Decoded &insn, const fs::path &path)
{
    for ( const ipp::RegisterAccess &access : ipp::register_accesses(insn) )
    {
        const unsigned limit = 8 * ipp::register_width(access.storage.reg);
        const unsigned end = unsigned(access.storage.bit_offset) + access.storage.bit_count;
        if ( access.storage.reg == ipp::CFR
             && access.storage.bit_offset <= C7_CFR_BIT
             && end > C7_CFR_BIT )
        {
            std::fprintf(stderr, "constant C7 dependency %s:%08x\n", path.filename().c_str(),
                         insn.address);
            return false;
        }
        if ( access.storage.reg >= ipp::RegisterCount
             || access.storage.bit_count == 0
             || end > limit
             || access.access == 0
             || (access.access & ~unsigned(ipp::ReadWrite)) != 0 )
        {
            std::fprintf(stderr, "invalid access range %s:%08x\n", path.filename().c_str(),
                         insn.address);
            return false;
        }
    }
    return true;
}

//--------------------------------------------------------------------
/// \return false if the instruction breaks an invariant.
static bool check_instruction(effect_stats_t *stats, const ipp::Decoded &insn, const fs::path &path)
{
    if ( !ipp::valid_instruction(insn) )
        return false;

    const ipp::Form &form = ipp::form_table()[insn.form_index];
    stats->unconditional_sites += insn.predicate == ipp::PREDICATE_ALWAYS;

    bool aggregate_cfr = insn.flow == ipp::Flow::Call || insn.has_mnemonic("jmpr");
    bool odd_fd = false;
    for ( const ipp::Operand &operand : insn.ops )
    {
        if ( operand.kind != ipp::OperandKind::Register )
            continue;
        stats->explicit_c7_reads += operand.reg == ipp::C7 && operand.reads();
        aggregate_cfr |= operand.reg == ipp::CFR || operand.reg == ipp::CFR3;
        odd_fd |= operand.reg >= ipp::FD0
            && operand.reg < ipp::FD0 + 32
            && (operand.reg - ipp::FD0) % 2 != 0;
    }

    if ( !check_stack_writes(stats, insn, path) )
        return false;

    for ( unsigned bit = 0; bit < 16; ++bit )
    {
        if ( (form.implicit_effects & (1u << bit)) != 0 )
            ++stats->effect_bit_sites[1u << bit];
    }

    bool discards_output = false;
    for ( const ipp::Operand &operand : insn.ops )
    {
        if ( !operand.has_flag(ipp::DiscardSpecialDestination) || operand.access != ipp::NoAccess )
            continue;
        ++stats->suppressed_outputs;
        discards_output = true;
        if ( operand.kind == ipp::OperandKind::RegisterRange )
            ++stats->paired_sinks;
        else
            ++stats->scalar_sinks;
    }

    const bool mh_move = insn.has_mnemonic("mov")
        && insn.operand_count == 2
        && insn.ops[0].reg >= ipp::MH0
        && insn.ops[0].reg <= ipp::MH1;
    stats->mh_move_sites += mh_move;
    stats->mul_sites += insn.has_mnemonic("mul");
    stats->odd_fd_sites += odd_fd;
    stats->aggregate_cfr_sites += aggregate_cfr;

    const size_t sample = size_t(PREDICATE_COUNT) * insn.form_index + insn.predicate;
    const bool new_cfr_sample = aggregate_cfr && !stats->sampled_aggregate_cfr[sample];
    if ( new_cfr_sample )
    {
        stats->sampled_aggregate_cfr[sample] = true;
        ++stats->aggregate_cfr_samples;
    }

    if ( form.implicit_effects == 0 && !discards_output && !mh_move && !odd_fd && !new_cfr_sample )
        return true;
    ++stats->policy_sites_checked;
    return check_access_ranges(insn, path);
}

//--------------------------------------------------------------------
/// \return false if the file fails to load or breaks an invariant.
static bool scan_file(effect_stats_t *stats, const fs::path &path)
{
    ipp::Image image;
    if ( !image.load_file(path.string()) )
        return false;
    ++stats->files;

    for ( const ipp::Section &section : image.sections() )
    {
        if ( !section.has_code() )
            continue;
        const uint8_t *bytes = image.bytes().data() + section.offset;
        uint32_t offset = 0;
        while ( offset < section.size )
        {
            const uint32_t remaining = section.size - offset;
            const ipp::Decoded insn =
                ipp::decode_one(bytes + offset, remaining, section.addr + offset);
            if ( insn.length == 0 || insn.length > remaining )
                return false;
            offset += insn.length;
            if ( insn.kind == ipp::Kind::Insn && !check_instruction(stats, insn, path) )
                return false;
        }
    }
    return true;
}

//--------------------------------------------------------------------
static void write_json_report(const std::string &path, const effect_stats_t &stats)
{
    std::ofstream out(path);
    out
        << "{\n  \"files\": "
        << stats.files
        << ",\n  \"policy_sites_checked\": "
        << stats.policy_sites_checked
        << ",\n  \"suppressed_outputs\": "
        << stats.suppressed_outputs
        << ",\n  \"scalar_sinks\": "
        << stats.scalar_sinks
        << ",\n  \"paired_sinks\": "
        << stats.paired_sinks
        << ",\n  \"mh_move_sites\": "
        << stats.mh_move_sites
        << ",\n  \"mul_sites\": "
        << stats.mul_sites
        << ",\n  \"sp_write_sites\": "
        << stats.sp_write_sites
        << ",\n  \"sp_range_write_sites\": "
        << stats.sp_range_write_sites
        << ",\n  \"sp_overlapping_write_sites\": "
        << stats.sp_overlapping_write_sites
        << ",\n  \"sp_unknown_delta_sites\": "
        << stats.sp_unknown_delta_sites
        << ",\n  \"odd_fd_sites\": "
        << stats.odd_fd_sites
        << ",\n  \"unconditional_instruction_sites\": "
        << stats.unconditional_sites
        << ",\n  \"explicit_c7_read_operands\": "
        << stats.explicit_c7_reads
        << ",\n  \"aggregate_cfr_sites\": "
        << stats.aggregate_cfr_sites
        << ",\n  \"aggregate_cfr_form_predicate_samples\": "
        << stats.aggregate_cfr_samples
        << ",\n  \"effect_bit_site_counts\": {";
    bool first = true;
    for ( const auto &[flag, count] : stats.effect_bit_sites )
    {
        if ( !first )
            out << ',';
        first = false;
        out << '\n' << "    \"" << flag << "\": " << count;
    }
    out << "\n  },\n  \"scope\": \"Production corpus access-range validation; no native "
           "semantics\"\n}\n";
}

//--------------------------------------------------------------------
int main(int argc, char **argv)
{
    if ( argc != 2 && argc != 3 )
        return 2;

    effect_stats_t stats;
    stats.sampled_aggregate_cfr.assign(ipp::form_count() * PREDICATE_COUNT, false);
    for ( const fs::path &path : find_elf_files(argv[1]) )
    {
        if ( !scan_file(&stats, path) )
            return 1;
    }

    std::printf("files=%u policy_access_records_checked=%llu suppressed_outputs=%llu scalar=%llu "
                "paired=%llu mh_moves=%llu mul_sites=%llu\n",
                stats.files, static_cast<unsigned long long>(stats.policy_sites_checked),
                static_cast<unsigned long long>(stats.suppressed_outputs),
                static_cast<unsigned long long>(stats.scalar_sinks),
                static_cast<unsigned long long>(stats.paired_sinks),
                static_cast<unsigned long long>(stats.mh_move_sites),
                static_cast<unsigned long long>(stats.mul_sites));
    if ( argc == 3 )
        write_json_report(argv[2], stats);

    const bool passed = stats.files == EXPECTED_FILES
        && stats.policy_sites_checked != 0
        && stats.suppressed_outputs != 0
        && stats.mh_move_sites != 0;
    return passed ? 0 : 1;
}
