#include "processor/function_discovery.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <tuple>
#include <vector>

#include <ida.hpp>

#include <bytes.hpp>
#include <funcs.hpp>
#include <netnode.hpp>
#include <ua.hpp>

#include "database_nodes.hpp"
#include "ipp/decoder.hpp"
#include "ipp/semantics.hpp"
#include "processor/context_decoder.hpp"

namespace ipp::processor
{

namespace
{

constexpr ea_t PROLOGUE_WINDOW = 64;
constexpr ea_t LEAF_WINDOW = 256;
constexpr ea_t LAST_PROBED_ADDRESS = 0xfffffeffu;
constexpr int64_t MIN_FRAME_SIZE = 8;
constexpr unsigned MAX_LEAF_PROBE_STEPS = 1024;

// Condition flags C0..C6 can change; C7 always reads one. Predicate facts are tracked
// as bit masks over C0..C7, and only within one leaf probe.
constexpr unsigned MUTABLE_FLAG_COUNT = 7;
constexpr uint8 C7_FACT = 0x80;

/// One path through a leaf probe.
struct leaf_path_t
{
    ea_t ea;
    int64_t sp_delta;
    uint8 known_flags;
    uint8 flag_values;
};

/// A probe state, and the stack delta with which it was first reached.
using leaf_state_t = std::tuple<ea_t, uint8, uint8>;
using visited_states_t = std::map<leaf_state_t, int64_t>;

/// Explores the paths of a candidate leaf function. It is a closed leaf if every path
/// within LIMIT reaches jmpr with SP balanced, making no calls and leaving the return
/// state alone. Instructions under an unknown predicate fork the exploration.
class leaf_probe_t
{
public:
    leaf_probe_t(ea_t begin, ea_t limit, const netnode &symbols)
        : begin_(begin), limit_(limit), symbols_(symbols)
    {
    }

    [[nodiscard]] bool is_closed_leaf()
    {
        pending_.push_back({begin_, 0, C7_FACT, C7_FACT});
        unsigned steps = 0;
        while ( !pending_.empty() )
        {
            ++steps;
            if ( steps > MAX_LEAF_PROBE_STEPS )
                return false;

            const leaf_path_t path = pending_.back();
            pending_.pop_back();
            if ( !visit(path) )
                return false;
        }
        return found_return_;
    }

private:
    /// Each of these returns false if the candidate is rejected.
    [[nodiscard]] bool visit(leaf_path_t path);
    [[nodiscard]] bool execute(leaf_path_t path, const ipp::Decoded &insn, ea_t next_ea);

    ea_t begin_;
    ea_t limit_;
    const netnode &symbols_;
    std::vector<leaf_path_t> pending_;
    visited_states_t visited_;
    bool found_return_ = false;
};

} // namespace

//--------------------------------------------------------------------
static bool is_instruction_boundary(ea_t ea)
{
    const flags64_t flags = get_flags(ea);
    return !is_data(flags) && !is_tail(flags);
}

//--------------------------------------------------------------------
static bool is_declared_function(ea_t ea, const netnode &symbols)
{
    return symbols.altval_ea(ea) != 0 || get_func_start(ea) == ea;
}

//--------------------------------------------------------------------
static bool writes_return_state(const ipp::Decoded &insn)
{
    for ( const ipp::RegisterAccess &access : ipp::register_accesses(insn) )
    {
        if ( (access.access & ipp::Write) != 0
             && (access.storage.reg == ipp::LR || access.storage.reg == ipp::SVR) )
        {
            return true;
        }
    }
    return false;
}

//--------------------------------------------------------------------
/// stp (SP,n),LR:SVR, storing the return state inside the allocated frame.
static bool saves_return_state(const ipp::Decoded &insn, int64_t frame_size)
{
    if ( insn.operand_count != 2 )
        return false;
    const ipp::Operand &memory = insn.ops[0];
    const ipp::Operand &value = insn.ops[1];
    return memory.kind == ipp::OperandKind::Memory
        && memory.reg == ipp::SP
        && memory.access == ipp::Write
        && memory.width == 8
        && !memory.has_flag(ipp::PostIncrement)
        && memory.value >= 0
        && int64_t(memory.value) + 8 <= frame_size
        && value.kind == ipp::OperandKind::RegisterRange
        && value.reg == ipp::LR
        && value.reg_end == ipp::SVR;
}

//--------------------------------------------------------------------
/// A stack allocation, then only plain instructions, up to saving the return state.
static bool is_framed_prologue(ea_t ea, ea_t limit, const netnode &symbols)
{
    const std::optional<ipp::Decoded> first = decode_bytes_at(ea);
    int64_t allocation = 0;
    if ( !first
         || first->predicate != ipp::PREDICATE_ALWAYS
         || first->e_bit
         || first->operand_count == 0
         || !first->ops[0].is_register(ipp::SP)
         || first->flow != ipp::Flow::Sequential
         || !ipp::stack_pointer_delta(*first, &allocation)
         || allocation > -MIN_FRAME_SIZE )
    {
        return false;
    }
    const int64_t frame_size = -allocation;

    ea_t next = ea + first->length;
    while ( next < limit )
    {
        if ( is_declared_function(next, symbols) || !is_instruction_boundary(next) )
            return false;

        const std::optional<ipp::Decoded> insn = decode_bytes_at(next);
        int64_t step = 0;
        if ( !insn
             || next + insn->length > limit
             || insn->predicate != ipp::PREDICATE_ALWAYS
             || insn->e_bit
             || insn->flow != ipp::Flow::Sequential
             || !ipp::stack_pointer_delta(*insn, &step)
             || step != 0
             || writes_return_state(*insn) )
        {
            return false;
        }
        if ( saves_return_state(*insn, frame_size) )
            return true;
        next += insn->length;
    }
    return false;
}

//--------------------------------------------------------------------
/// Instructions known not to change a condition flag except by writing it explicitly,
/// so that flag facts survive them.
static bool preserves_predicate_facts(const ipp::Decoded &insn)
{
    for ( unsigned i = 0; i < insn.operand_count; ++i )
    {
        if ( insn.ops[i].has_flag(ipp::ConservativeAccess) )
            return false;
    }

    if ( (insn.has_mnemonic("mov") || insn.has_mnemonic("sethi"))
         && (insn.operand_count == 0
             || insn.ops[0].kind != ipp::OperandKind::Register
             || insn.ops[0].reg >= ipp::LR) )
    {
        return false;
    }

    static constexpr std::string_view TRANSPARENT_MNEMONICS[] = {
        "mov", "sethi", "add", "addu",   "sub",   "or",    "and", "xor", "not", "asl",
        "asr", "lsr",   "msk", "mskgen", "s1add", "s2add", "br",  "ld",  "ldp", "ldq",
        "ldb", "ldbu",  "ldh", "ldhu",   "st",    "stp",   "stq", "stb", "sth",
    };
    for ( std::string_view name : TRANSPARENT_MNEMONICS )
    {
        if ( insn.has_mnemonic(name) )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------
static bool can_visit_in_leaf(ea_t ea, ea_t begin, ea_t limit, const netnode &symbols)
{
    if ( ea < begin || ea >= limit || (ea & 1) != 0 )
        return false;
    if ( ea != begin && is_declared_function(ea, symbols) )
        return false;
    return is_instruction_boundary(ea);
}

//--------------------------------------------------------------------
/// Forget facts about condition flags that INSN writes.
static void forget_written_flags(leaf_path_t *path, const ipp::Decoded &insn)
{
    for ( const ipp::RegisterAccess &access : ipp::register_accesses(insn) )
    {
        if ( (access.access & ipp::Write) == 0 || access.storage.reg != ipp::CFR )
            continue;
        const unsigned first_bit = access.storage.bit_offset;
        const unsigned end_bit = first_bit + access.storage.bit_count;
        for ( unsigned flag = 0; flag < MUTABLE_FLAG_COUNT; ++flag )
        {
            if ( first_bit <= flag && end_bit > flag )
                path->known_flags &= static_cast<uint8>(~(1u << flag));
        }
    }
}

//--------------------------------------------------------------------
bool leaf_probe_t::visit(leaf_path_t path)
{
    if ( !can_visit_in_leaf(path.ea, begin_, limit_, symbols_) )
        return false;

    // A state seen before needs no second visit, but must agree on the stack depth.
    path.flag_values &= path.known_flags;
    const leaf_state_t state = std::make_tuple(path.ea, path.known_flags, path.flag_values);
    const visited_states_t::const_iterator p = visited_.find(state);
    if ( p != visited_.end() )
        return p->second == path.sp_delta;
    visited_.emplace(state, path.sp_delta);

    const std::optional<ipp::Decoded> insn = decode_bytes_at(path.ea);
    if ( !insn || path.ea + insn->length > limit_ || insn->e_bit )
        return false;
    const ea_t next_ea = path.ea + insn->length;

    const uint8 predicate_bit = static_cast<uint8>(1u << insn->predicate);
    const bool predicate_known = (path.known_flags & predicate_bit) != 0;

    // Known false: the instruction is skipped.
    if ( predicate_known && (path.flag_values & predicate_bit) == 0 )
    {
        pending_.push_back({next_ea, path.sp_delta, path.known_flags, path.flag_values});
        return true;
    }

    // Unknown: queue the outcome where it is false, and carry on with it true.
    if ( !predicate_known )
    {
        const uint8 known = path.known_flags | predicate_bit;
        const uint8 values = path.flag_values & static_cast<uint8>(~predicate_bit);
        pending_.push_back({next_ea, path.sp_delta, known, values});
        path.known_flags |= predicate_bit;
        path.flag_values |= predicate_bit;
    }
    return execute(path, *insn, next_ea);
}

//--------------------------------------------------------------------
bool leaf_probe_t::execute(leaf_path_t path, const ipp::Decoded &insn, ea_t next_ea)
{
    if ( insn.flow == ipp::Flow::Call || insn.flow == ipp::Flow::Trap || writes_return_state(insn) )
        return false;

    // This path executes the instruction. Project only the predicate for the existing
    // constant-SP-effect query; the public conditional query remains unknown when its
    // execution condition is not established.
    ipp::Decoded executed = insn;
    executed.predicate = ipp::PREDICATE_ALWAYS;
    int64_t step = 0;
    if ( !ipp::stack_pointer_delta(executed, &step) )
        return false;
    const int64_t sp_delta = path.sp_delta + step;

    forget_written_flags(&path, insn);
    if ( !preserves_predicate_facts(insn) )
        path.known_flags = C7_FACT;
    path.flag_values &= path.known_flags;

    if ( insn.flow == ipp::Flow::Return )
    {
        if ( !insn.has_mnemonic("jmpr") || sp_delta != 0 )
            return false;
        found_return_ = true;
    }
    else if ( insn.flow == ipp::Flow::Branch )
    {
        if ( !insn.has_target )
            return false;
        pending_.push_back({insn.target, sp_delta, path.known_flags, path.flag_values});
    }
    else
    {
        pending_.push_back({next_ea, sp_delta, path.known_flags, path.flag_values});
    }
    return true;
}

//--------------------------------------------------------------------
/// True if a function symbol ended at EA and recognizable code follows it.
static bool starts_after_symbol_end(ea_t ea, const netnode &symbols)
{
    netnode ends(FUNCTION_ENDS_NODE);
    if ( ends == BADNODE
         || ends.altval_ea(ea) == 0
         || ea > LAST_PROBED_ADDRESS
         || (ea & 1) != 0
         || !is_instruction_boundary(ea) )
    {
        return false;
    }

    const std::optional<ipp::Decoded> first = decode_bytes_at(ea);
    if ( !first || first->predicate != ipp::PREDICATE_ALWAYS || first->e_bit )
        return false;
    return is_framed_prologue(ea, ea + PROLOGUE_WINDOW, symbols)
        || leaf_probe_t(ea, ea + LEAF_WINDOW, symbols).is_closed_leaf();
}

//--------------------------------------------------------------------
bool is_function_start(ea_t ea)
{
    netnode symbols(FUNCTION_SYMBOLS_NODE);
    if ( symbols == BADNODE )
        return false;
    return symbols.altval_ea(ea) != 0 || starts_after_symbol_end(ea, symbols);
}

//--------------------------------------------------------------------
void restore_symbol_functions()
{
    netnode symbols(FUNCTION_SYMBOLS_NODE);
    if ( symbols == BADNODE )
        return;

    for ( nodeidx_t key = symbols.altfirst(); key != BADNODE; key = symbols.altnext(key) )
    {
        const ea_t ea = node2ea(key);
        if ( get_func_start(ea) != BADADDR || !decode_at(ea) )
            continue;
        const uint64 size = symbols.altval(key) - 1;
        create_insn(ea);
        add_func(ea, size != 0 ? ea + size : BADADDR);
    }
}

} // namespace ipp::processor
