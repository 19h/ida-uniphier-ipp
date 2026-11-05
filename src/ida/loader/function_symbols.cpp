#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <string>

#include <ida.hpp>

#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <ua.hpp>

#include "database_nodes.hpp"
#include "loader/loader_steps.hpp"

namespace ipp::loader
{

namespace
{

/// Largest declared size of each function start. Sized by uint32, as in the file.
using function_extents_t = std::map<uint32, uint32>;

constexpr int SYMBOL_NAME_FLAGS = SN_NOCHECK | SN_PUBLIC | SN_NOWARN | SN_NODUMMY;
constexpr uint64 LAST_32BIT_ADDRESS = 0xffffffffu;

} // namespace

//--------------------------------------------------------------------
/// Name the image's symbols and record its function symbols for the processor.
static function_extents_t name_symbols(const ipp::Image &image, unsigned image_number)
{
    function_extents_t extents;
    netnode symbols(FUNCTION_SYMBOLS_NODE, 0, true);
    for ( const ipp::Symbol &symbol : image.symbols() )
    {
        if ( !symbol.is_defined() || symbol.name.empty() )
            continue;

        const std::string name = database_name(image_number, symbol.name);
        const uint32 checked_size = symbol.size != 0 ? symbol.size : 1;
        if ( symbol.is_function() && image.executable_va(symbol.value, checked_size) )
        {
            set_name(symbol.value, name.c_str(), SYMBOL_NAME_FLAGS);
            add_entry(symbol.value, symbol.value, name.c_str(), true);
            const uint64 stored_size = uint64(symbol.size) + 1;
            symbols.altset_ea(symbol.value, std::max(symbols.altval_ea(symbol.value), stored_size));
            uint32 &extent = extents[symbol.value];
            extent = std::max(extent, symbol.size);
        }
        else if ( symbol.is_object() && is_mapped(symbol.value) )
        {
            set_name(symbol.value, name.c_str(), SYMBOL_NAME_FLAGS);
        }
    }
    return extents;
}

//--------------------------------------------------------------------
/// A positive symbol size also identifies a boundary. It does not by itself declare a
/// new function: the processor validates code there when the kernel asks whether to
/// merge a following chunk. Exclude ends inside any other declared extent and already
/// declared starts.
static void record_function_ends(const ipp::Image &image, const function_extents_t &extents)
{
    // For each function start, the furthest end among it and all earlier functions.
    std::map<uint32, uint64> furthest_end;
    uint64 furthest = 0;
    for ( const auto &[start, size] : extents )
    {
        furthest = std::max(furthest, uint64(start) + size);
        furthest_end[start] = furthest;
    }

    netnode ends(FUNCTION_ENDS_NODE, 0, true);
    for ( const auto &[start, size] : extents )
    {
        const uint64 end = uint64(start) + size;
        if ( size == 0
             || end > LAST_32BIT_ADDRESS
             || (end & 1) != 0
             || extents.count(static_cast<uint32>(end)) != 0
             || !image.executable_va(static_cast<uint32>(end)) )
        {
            continue;
        }

        const auto q = furthest_end.lower_bound(static_cast<uint32>(end));
        if ( q == furthest_end.begin() || std::prev(q)->second > end )
            continue;
        ends.altset_ea(ea_t(end), uint64(start) + 1);
    }
}

//--------------------------------------------------------------------
static void create_functions(const function_extents_t &extents)
{
    for ( const auto &[start, size] : extents )
    {
        create_insn(start);
        if ( !add_func(start, size != 0 ? ea_t(start) + size : BADADDR) )
            auto_make_proc(start);
    }
}

//--------------------------------------------------------------------
void define_symbols(const ipp::Image &image, unsigned image_number)
{
    const function_extents_t extents = name_symbols(image, image_number);
    record_function_ends(image, extents);
    create_functions(extents);
}

} // namespace ipp::loader
