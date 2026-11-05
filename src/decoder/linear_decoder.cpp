// Linear decoding of a whole extent, with call folding guarded by known entries.

#include <set>
#include <vector>

#include "ipp/decoder.hpp"

namespace ipp
{

namespace
{

/// A call that a fold would resolve, if no entry interrupts its sequence.
struct fold_candidate_t
{
    size_t index;
    Decoded resolved;
};

} // namespace

//--------------------------------------------------------------------
/// Decode consecutive instructions without any call folding.
static std::vector<Decoded> decode_sequence(const uint8_t *bytes, size_t size, uint32_t address)
{
    std::vector<Decoded> insns;
    size_t offset = 0;
    while ( offset < size )
    {
        const Decoded insn =
            decode_one(bytes + offset, size - offset, address + static_cast<uint32_t>(offset));
        if ( insn.length == 0 || insn.length > size - offset )
            break;
        insns.push_back(insn);
        offset += insn.length;
    }
    return insns;
}

//--------------------------------------------------------------------
/// Apply CANDIDATES whose sequence of DEFINITION_COUNT + 1 instructions contains no
/// known entry. The first definition can itself be an entry; any later parcel cannot.
static void apply_folds(std::vector<Decoded> *insns,
                        const std::vector<fold_candidate_t> &candidates, size_t definition_count,
                        const std::set<uint32_t> &known_entries)
{
    for ( const fold_candidate_t &candidate : candidates )
    {
        const uint32_t first = (*insns)[candidate.index - definition_count].address;
        const uint32_t last = (*insns)[candidate.index].address;
        const auto entry = known_entries.upper_bound(first);
        if ( entry == known_entries.end() || *entry > last )
            (*insns)[candidate.index] = candidate.resolved;
    }
}

//--------------------------------------------------------------------
std::vector<Decoded> decode_linear(const uint8_t *bytes, size_t size, uint32_t address,
                                   const std::vector<uint32_t> &entries)
{
    std::vector<Decoded> insns = decode_sequence(bytes, size, address);

    std::set<uint32_t> known_entries(entries.begin(), entries.end());
    for ( const Decoded &insn : insns )
    {
        if ( insn.has_target )
            known_entries.insert(insn.target);
    }

    // Collect every candidate's destination before applying any of them. Even
    // subsequently rejected candidates act as entry barriers; otherwise resolution
    // order could let one fold bypass another edge.
    std::vector<fold_candidate_t> far_calls;
    for ( size_t i = 1; i < insns.size(); ++i )
    {
        Decoded resolved = insns[i];
        if ( resolve_far_call(insns[i - 1], &resolved) )
        {
            known_entries.insert(resolved.target);
            far_calls.push_back({i, resolved});
        }
    }
    std::vector<fold_candidate_t> absolute_calls;
    for ( size_t i = 3; i < insns.size(); ++i )
    {
        Decoded resolved = insns[i];
        if ( resolve_absolute_call(insns[i - 3], insns[i - 2], insns[i - 1], &resolved) )
        {
            known_entries.insert(resolved.target);
            absolute_calls.push_back({i, resolved});
        }
    }

    apply_folds(&insns, far_calls, 1, known_entries);
    apply_folds(&insns, absolute_calls, 3, known_entries);
    return insns;
}

} // namespace ipp
