# The decoder and ELF reader. No IDA types.
add_library(ippdec STATIC
    decoder/call_resolution.cpp
    decoder/decoder.cpp
    decoder/form_table.cpp
    decoder/format.cpp
    decoder/linear_decoder.cpp
    decoder/operand_program.cpp
    decoder/operand_text.cpp
    decoder/register_accesses.cpp
    decoder/registers.cpp
    decoder/stack_delta.cpp
    elf/elf_parser.cpp
    elf/image.cpp
)
target_include_directories(ippdec
    PUBLIC "${PROJECT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(ippdec PRIVATE ipp_warnings)
set_target_properties(ippdec PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(ipp-dec cli/main.cpp)
target_link_libraries(ipp-dec PRIVATE ippdec ipp_warnings)

if(IPP_IDA_SDK)
    add_subdirectory(ida)
endif()
