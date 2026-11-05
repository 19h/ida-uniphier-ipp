# IDA adapters. Encoding and typed operand layouts live in ippdec; these modules
# translate them into IDA's public model and do not carry a second encoding.
ipp_add_ida_module(ipp procs
    processor/analyzer.cpp
    processor/context_decoder.cpp
    processor/emulator.cpp
    processor/function_discovery.cpp
    processor/instruction_table.cpp
    processor/output.cpp
    processor/processor.cpp
)

ipp_add_ida_module(elfipp loaders
    loader/function_symbols.cpp
    loader/image_mapping.cpp
    loader/loader.cpp
    loader/relocations.cpp
)
