cmake_minimum_required(VERSION 3.20)
project(ipp LANGUAGES CXX)

# One decoder. The CLI and the oracle link it directly. The IDA loader and
# processor, when built, link the same static library. They do not carry a
# second encoding.

# C++17 is a contract, not a default: external evidence tools compile the public
# headers with -std=c++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep artifacts at the root of the build tree, where external evidence scripts
# expect to find ipp-dec and libippdec.a.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Sample binaries and evidence are not distributed with this repository. Tests that
# need them are registered only when their location is given here.
set(IPP_CORPUS "" CACHE PATH "Directory of ELF32 big-endian e_machine 0x1040 files")
set(IPP_BOOT_ROM "" CACHE FILEPATH "Raw IPP boot image for the IDA absolute-call test")
option(IPP_SOURCE_MODEL_TESTS "Run archived primary-source alignment checks" OFF)
set(IPP_EVIDENCE_DIR "" CACHE PATH "Directory of the archived source-model scripts")
set(IPP_IDA_SDK "" CACHE PATH "IDA SDK root (src/include or include/sdk)")
set(IPP_IDA_LIB "" CACHE FILEPATH "libida.dylib to link the modules against")
option(IPP_IDA_RUNTIME_TESTS "Run disposable-database IDA integration tests" OFF)
set(IPP_IDA_PYTHON "" CACHE FILEPATH "Python interpreter compatible with this IDA installation")
set(IPP_IDALIB_PYTHON "" CACHE PATH "Directory containing the idapro Python package")
set(IPP_IDA_TEST_USER "" CACHE PATH "Isolated, already licensed IDAUSR for integration tests")

add_library(ipp_warnings INTERFACE)
target_compile_options(ipp_warnings INTERFACE -Wall -Wextra -Wpedantic -Werror)

enable_testing()
find_package(Python3 COMPONENTS Interpreter QUIET)

if(IPP_IDA_SDK)
    include(IppIdaSdk)
endif()

add_subdirectory(src)
add_subdirectory(tests)
