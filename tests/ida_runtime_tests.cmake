# Integration tests that load the built modules into disposable IDA databases.
# They copy their inputs to temporary directories and never open an existing IDB.
# IPP_IDA_ARGS in the environment can supply installation-specific IDA options.

if(NOT EXISTS "${IPP_IDA_PYTHON}" OR NOT IS_DIRECTORY "${IPP_IDA_TEST_USER}")
    message(FATAL_ERROR "Set IPP_IDA_PYTHON and an isolated licensed IPP_IDA_TEST_USER")
endif()

get_filename_component(IPP_IDA_RUNTIME_DIR "${IPP_IDA_LIBRARY}" DIRECTORY)

# ipp_add_ida_test(<test-name> <script> <timeout-seconds> [extra script args...])
# Each script writes its findings to <build>/<test-name>.json.
function(ipp_add_ida_test test_name script timeout)
    add_test(NAME ${test_name}
        COMMAND "${IPP_IDA_PYTHON}" -I "${CMAKE_CURRENT_SOURCE_DIR}/${script}" ${ARGN}
            --output "${CMAKE_BINARY_DIR}/${test_name}.json")
    set_tests_properties(${test_name} PROPERTIES
        RUN_SERIAL TRUE
        TIMEOUT ${timeout}
        ENVIRONMENT "IDADIR=${IPP_IDA_RUNTIME_DIR};IDAUSR=${IPP_IDA_TEST_USER};IPP_IDALIB_PYTHON=${IPP_IDALIB_PYTHON}")
endfunction()

# These build their own inputs, so they need no sample binaries.
ipp_add_ida_test(ida-relocations ida_loader_runtime.py 120)

foreach(entry_case normal zero unmapped nonexec)
    ipp_add_ida_test(ida-entry-${entry_case} ida_entry_runtime.py 120
        --case "${entry_case}")
endforeach()

foreach(metadata_case nameless empty extended)
    ipp_add_ida_test(ida-metadata-${metadata_case} ida_elf_metadata_runtime.py 180
        --case "${metadata_case}")
endforeach()

ipp_add_ida_test(ida-absolute-synthetic ida_absolute_call_runtime.py 180 --case synthetic)
ipp_add_ida_test(ida-far-context ida_far_context_runtime.py 180)
ipp_add_ida_test(ida-compact-memory ida_compact_memory_runtime.py 180)
ipp_add_ida_test(ida-shifts ida_shift_runtime.py 180)
ipp_add_ida_test(ida-bounds-synthetic ida_function_bounds_runtime.py 180 --image synthetic)

if(IPP_BOOT_ROM)
    ipp_add_ida_test(ida-absolute-boot ida_absolute_call_runtime.py 180
        --case boot --source "${IPP_BOOT_ROM}")
endif()

if(IPP_CORPUS)
    foreach(image libc.so.7 acodec)
        ipp_add_ida_test(ida-${image} ida_runtime.py 120
            --corpus "${IPP_CORPUS}" --image "${image}")
    endforeach()

    ipp_add_ida_test(ida-companion-symbols ida_companion_runtime.py 180
        --corpus "${IPP_CORPUS}")

    foreach(image libicui18n.so.44.1 libicuuc.so.44.1 libstdc++.so.6 libwvcdm_shared.so)
        ipp_add_ida_test(ida-bounds-${image} ida_function_bounds_runtime.py 180
            --corpus "${IPP_CORPUS}" --image "${image}")
    endforeach()
endif()
