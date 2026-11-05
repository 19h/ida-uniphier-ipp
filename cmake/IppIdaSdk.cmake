# Locate the IDA SDK named by IPP_IDA_SDK and define how to build modules against it.
#
# Sets:
#   IPP_IDA_INCLUDE_DIR    the SDK's header directory
#   IPP_IDA_LIBRARY        the libida.dylib to link against
#   IPP_IDA_FIX_INCLUDE_DIR  corrected headers to search first, if any are needed
#
# Defines:
#   ipp_add_ida_module(<target> <procs|loaders> <source>...)

if(EXISTS "${IPP_IDA_SDK}/src/include/ida.hpp")
    set(IPP_IDA_INCLUDE_DIR "${IPP_IDA_SDK}/src/include")
elseif(EXISTS "${IPP_IDA_SDK}/include/sdk/ida.hpp")
    set(IPP_IDA_INCLUDE_DIR "${IPP_IDA_SDK}/include/sdk")
else()
    message(FATAL_ERROR "IPP_IDA_SDK has no ida.hpp")
endif()

if(IPP_IDA_LIB)
    set(IPP_IDA_LIBRARY "${IPP_IDA_LIB}")
elseif(EXISTS "${IPP_IDA_SDK}/src/lib/arm64_mac_clang_64/libida.dylib")
    set(IPP_IDA_LIBRARY "${IPP_IDA_SDK}/src/lib/arm64_mac_clang_64/libida.dylib")
else()
    message(FATAL_ERROR "Set IPP_IDA_LIB to libida.dylib")
endif()
if(NOT EXISTS "${IPP_IDA_LIBRARY}")
    message(FATAL_ERROR "libida.dylib not found at ${IPP_IDA_LIBRARY}")
endif()

# Some in-tree SDK copies leave IDA_SDK_VERSION as an unexpanded token. A corrected
# copy of that one header keeps the rest of the SDK untouched.
set(IPP_IDA_FIX_INCLUDE_DIR "")
file(READ "${IPP_IDA_INCLUDE_DIR}/pro.h" IPP_IDA_PRO_H)
if(IPP_IDA_PRO_H MATCHES "##VERDECIMAL##")
    string(REPLACE "##VERDECIMAL##" "960" IPP_IDA_PRO_H "${IPP_IDA_PRO_H}")
    set(IPP_IDA_FIX_INCLUDE_DIR "${CMAKE_BINARY_DIR}/ida-fix")
    file(MAKE_DIRECTORY "${IPP_IDA_FIX_INCLUDE_DIR}")
    file(WRITE "${IPP_IDA_FIX_INCLUDE_DIR}/pro.h" "${IPP_IDA_PRO_H}")
endif()

function(ipp_add_ida_module target output_dir)
    add_library(${target} MODULE ${ARGN})
    target_link_libraries(${target} PRIVATE ippdec "${IPP_IDA_LIBRARY}")
    target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    if(IPP_IDA_FIX_INCLUDE_DIR)
        target_include_directories(${target} SYSTEM BEFORE PRIVATE "${IPP_IDA_FIX_INCLUDE_DIR}")
    endif()
    target_include_directories(${target} SYSTEM PRIVATE "${IPP_IDA_INCLUDE_DIR}")
    target_compile_definitions(${target} PRIVATE __EA64__ __MAC__)
    target_compile_options(${target} PRIVATE -Wall -Wextra -fvisibility=hidden)
    set_target_properties(${target} PROPERTIES
        PREFIX ""
        SUFFIX ".dylib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/ida/${output_dir}")
endfunction()
