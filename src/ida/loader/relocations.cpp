// Dynamic relocations, by the operations recovered from the supplied runtime linker
// (ld-elf.so.1:0x1432-0x15de). Numeric roles are deliberately separate from unverified
// official R_IPP_* names. COPY, lazy PLT, unresolved external and TLS bindings remain
// explicit pending runtime operations: this is not a dynamic linker.

#include <cstdint>
#include <string>

#include <ida.hpp>

#include <bytes.hpp>
#include <fixup.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <segment.hpp>
#include <xref.hpp>

#include "loader/loader_steps.hpp"

namespace ipp::loader
{

namespace
{

constexpr uint32_t RELOC_NONE = 0;
constexpr uint32_t RELOC_COPY = 176;
constexpr uint32_t RELOC_SYMBOL_WORD = 177;
constexpr uint32_t RELOC_PLT_SLOT = 178;
constexpr uint32_t RELOC_BASE_RELATIVE = 179;
constexpr uint32_t RELOC_TLS_FIRST = 180;
constexpr uint32_t RELOC_TLS_LAST = 182;
constexpr uint32_t RELOC_SYMBOL_WORD_ALTERNATE = 237;

constexpr asize_t WORD_SIZE = 4;

} // namespace

//--------------------------------------------------------------------
static bool is_word_mapped(ea_t ea)
{
    return is_mapped(ea) && is_mapped(ea + WORD_SIZE - 1);
}

//--------------------------------------------------------------------
/// Store a resolved 32-bit address, recording it as a fixup and a data reference.
/// Loader fixups alter the database, not the source ELF.
static void write_address_word(ea_t ea, uint32 target)
{
    put_dword(ea, target);
    fixup_data_t fixup(FIXUP_OFF32);
    fixup.off = target;
    fixup.set(ea);
    if ( is_mapped(target) )
        add_dref(ea, target, dr_O);
}

//--------------------------------------------------------------------
/// Keep lazy PLT values and unresolved external values intact. A name and import
/// record do not pretend the external symbol was resolved.
static void record_pending_binding(const ipp::Reloc &reloc, const ipp::Symbol &symbol,
                                   unsigned image_number, netnode *imports)
{
    const bool is_copy = reloc.type == RELOC_COPY;
    if ( !is_copy )
        create_dword(reloc.offset, WORD_SIZE);
    set_import_name(*imports, reloc.offset, symbol.name.c_str());

    const std::string cell_name = is_copy ? symbol.name : "__imp_" + symbol.name;
    set_name(reloc.offset, database_name(image_number, cell_name).c_str(),
             SN_NOCHECK | SN_NOWARN | SN_NODUMMY);
}

//--------------------------------------------------------------------
/// Apply one relocation. \return true if it created a pending import.
static bool apply_relocation(const ipp::Image &image, const ipp::Reloc &reloc,
                             unsigned image_number, netnode *imports)
{
    const ipp::Symbol *symbol = image.reloc_symbol(reloc);
    const bool has_symbol_name = symbol != nullptr && !symbol->name.empty();

    qstring description;
    description.sprnt("IPP relocation %u: symbol=%s addend=%d (%s)", reloc.type,
                      has_symbol_name ? symbol->name.c_str() : "<no-symbol>", reloc.addend,
                      reloc.explicit_addend ? "RELA" : "REL");

    const uint32 addend =
        reloc.explicit_addend ? static_cast<uint32>(reloc.addend) : get_dword(reloc.offset);
    const bool is_symbol_word =
        reloc.type == RELOC_SYMBOL_WORD || reloc.type == RELOC_SYMBOL_WORD_ALTERNATE;
    const bool is_copy = reloc.type == RELOC_COPY;
    bool created_import = false;

    if ( reloc.type == RELOC_BASE_RELATIVE )
    {
        // Images are mapped at their linked virtual addresses (load bias 0).
        create_dword(reloc.offset, WORD_SIZE);
        write_address_word(reloc.offset, addend);
        description.append("; applied base-relative word (load bias 0)");
    }
    else if ( is_symbol_word && symbol != nullptr && symbol->is_defined() )
    {
        create_dword(reloc.offset, WORD_SIZE);
        write_address_word(reloc.offset, symbol->value + addend);
        description.append("; applied defined-symbol word");
    }
    else if ( (reloc.type == RELOC_PLT_SLOT || is_symbol_word || is_copy) && has_symbol_name )
    {
        record_pending_binding(reloc, *symbol, image_number, imports);
        created_import = true;
        description.append(is_copy ? "; COPY storage, external source pending"
                                   : "; dynamic binding pending");
    }
    else if ( reloc.type >= RELOC_TLS_FIRST && reloc.type <= RELOC_TLS_LAST )
    {
        description.append("; TLS runtime module/offset allocation pending");
    }
    else
    {
        description.append("; operation unresolved, original bytes retained");
    }

    append_cmt(reloc.offset, description.c_str(), true);
    return created_import;
}

//--------------------------------------------------------------------
void apply_relocations(const ipp::Image &image, unsigned image_number)
{
    netnode imports;
    imports.create();

    bool has_imports = false;
    for ( const ipp::Reloc &reloc : image.relocs() )
    {
        if ( reloc.type == RELOC_NONE || !is_word_mapped(reloc.offset) )
            continue;
        if ( apply_relocation(image, reloc, image_number, &imports) )
            has_imports = true;
    }

    if ( has_imports )
    {
        qstring module_name;
        module_name.sprnt("IPP dynamic linkage (image %u)", image_number);
        import_module(module_name.c_str(), nullptr, imports, nullptr, "freebsd");
    }
    else
    {
        imports.kill();
    }
}

} // namespace ipp::loader
