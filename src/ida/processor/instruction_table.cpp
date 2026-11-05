#include "processor/instruction_table.hpp"

#include <cstddef>
#include <string_view>

#include <ida.hpp>

#include <idp.hpp>

namespace ipp::processor
{

namespace
{

constexpr uint32 OPERAND_USE_FEATURES[] = {
    CF_USE1, CF_USE2, CF_USE3, CF_USE4, CF_USE5, CF_USE6, CF_USE7, CF_USE8,
};
constexpr uint32 OPERAND_CHANGE_FEATURES[] = {
    CF_CHG1, CF_CHG2, CF_CHG3, CF_CHG4, CF_CHG5, CF_CHG6, CF_CHG7, CF_CHG8,
};

struct instruction_tables_t
{
    std::vector<instruc_t> instructions;

    // Instruction code of the discarding variant of each form and predicate state,
    // indexed like the ordinary codes. Zero means the form has no such variant.
    std::vector<uint16> discarded_itypes;
};

} // namespace

//--------------------------------------------------------------------
static uint32 instruction_features(const ipp::Form &form, bool conditional, bool discarded)
{
    const ipp::OperandSpec *specs = ipp::operand_specs(form);

    // The predicate is appended as one more operand, and it is always read.
    uint32 features = OPERAND_USE_FEATURES[form.operand_count];
    for ( unsigned i = 0; i < form.operand_count; ++i )
    {
        if ( discarded && (specs[i].flags & ipp::DiscardSpecialDestination) != 0 )
            continue;
        if ( (specs[i].access & ipp::Read) != 0 )
            features |= OPERAND_USE_FEATURES[i];
        if ( (specs[i].access & ipp::Write) != 0 )
            features |= OPERAND_CHANGE_FEATURES[i];
    }

    if ( form.flow == ipp::Flow::Call || form.flow == ipp::Flow::Trap )
        features |= CF_CALL;
    if ( form.flow == ipp::Flow::Branch && std::string_view(form.mnemonic) != "br" )
        features |= CF_JUMP;
    if ( !conditional && (form.flow == ipp::Flow::Return || form.flow == ipp::Flow::Branch) )
        features |= CF_STOP;
    return features;
}

//--------------------------------------------------------------------
static bool can_discard_output(const ipp::Form &form)
{
    const ipp::OperandSpec *specs = ipp::operand_specs(form);
    for ( unsigned i = 0; i < form.operand_count; ++i )
    {
        if ( (specs[i].flags & ipp::DiscardSpecialDestination) != 0 )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------
static instruction_tables_t build_tables()
{
    instruction_tables_t tables;
    tables.instructions.push_back({"invalid", 0});

    const ipp::Form *forms = ipp::form_table();
    const size_t form_count = ipp::form_count();
    for ( size_t i = 0; i < form_count; ++i )
    {
        for ( bool conditional : {false, true} )
            tables.instructions.push_back(
                {forms[i].mnemonic, instruction_features(forms[i], conditional, false)});
    }

    // Append variants: existing ordinary form/predicate instruction IDs stay unchanged.
    tables.discarded_itypes.assign(2 * form_count, 0);
    for ( size_t i = 0; i < form_count; ++i )
    {
        if ( !can_discard_output(forms[i]) )
            continue;
        for ( bool conditional : {false, true} )
        {
            tables.discarded_itypes[2 * i + (conditional ? 1 : 0)] =
                static_cast<uint16>(tables.instructions.size());
            tables.instructions.push_back(
                {forms[i].mnemonic, instruction_features(forms[i], conditional, true)});
        }
    }
    return tables;
}

//--------------------------------------------------------------------
/// A function-local static: the processor_t in LPH reads this during static
/// initialization, possibly before file-scope objects of this file are constructed.
static const instruction_tables_t &tables()
{
    static const instruction_tables_t built = build_tables();
    return built;
}

//--------------------------------------------------------------------
const std::vector<instruc_t> &instruction_table()
{
    return tables().instructions;
}

//--------------------------------------------------------------------
int unconditional_itype(size_t form_index)
{
    return static_cast<int>(1 + 2 * form_index);
}

//--------------------------------------------------------------------
std::optional<uint16> select_itype(const ipp::Decoded &insn)
{
    const size_t slot =
        2 * size_t(insn.form_index) + (insn.predicate != ipp::PREDICATE_ALWAYS ? 1 : 0);
    for ( unsigned i = 0; i < insn.operand_count; ++i )
    {
        const ipp::Operand &operand = insn.ops[i];
        if ( !operand.has_flag(ipp::DiscardSpecialDestination) || operand.access != ipp::NoAccess )
            continue;

        const std::vector<uint16> &variants = tables().discarded_itypes;
        if ( slot >= variants.size() || variants[slot] == 0 )
            return std::nullopt;
        return variants[slot];
    }
    return static_cast<uint16>(1 + slot);
}

} // namespace ipp::processor
