# Standalone C++ tests. Each one links only the decoder library.
function(ipp_add_cpp_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE ippdec ipp_warnings)
endfunction()

ipp_add_cpp_test(ipp-oracle oracle.cpp)
ipp_add_cpp_test(ipp-regression regression.cpp)
ipp_add_cpp_test(ipp-elf-test elf.cpp)
ipp_add_cpp_test(ipp-corpus corpus.cpp)
ipp_add_cpp_test(ipp-effects effects.cpp)

add_test(NAME regression COMMAND ipp-regression)
add_test(NAME elf-addresses COMMAND ipp-elf-test)
if(Python3_Interpreter_FOUND)
    add_test(NAME generated-table
        COMMAND ${Python3_EXECUTABLE} -I ${PROJECT_SOURCE_DIR}/tools/gen_v8_rules.py --check)
endif()

# These hold the reference sample set to exact counts.
if(IPP_CORPUS)
    add_test(NAME oracle COMMAND ipp-oracle ${IPP_CORPUS})
    add_test(NAME corpus COMMAND ipp-corpus ${IPP_CORPUS})
    add_test(NAME effects
        COMMAND ipp-effects ${IPP_CORPUS} ${CMAKE_BINARY_DIR}/effects-corpus.json)
    if(Python3_Interpreter_FOUND)
        add_test(NAME coverage
            COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/coverage.py
                $<TARGET_FILE:ipp-dec> ${IPP_CORPUS})
    endif()
else()
    message(STATUS "IPP_CORPUS is not set: skipping tests that need the sample binaries")
endif()

if(IPP_SOURCE_MODEL_TESTS)
    include(source_model_tests.cmake)
endif()

if(IPP_IDA_SDK AND IPP_IDA_RUNTIME_TESTS)
    include(ida_runtime_tests.cmake)
endif()
