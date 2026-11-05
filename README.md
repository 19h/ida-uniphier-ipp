# UniPhier IPP decoder and IDA modules

A disassembler and IDA Pro support for the instruction set used by ELF files with
`e_machine` 0x1040. Toolchain strings inside those files call the architecture `ipp`,
which points to the Instruction Parallel Processor in Panasonic's UniPhier system LSIs.

No public manual, compiler or disassembler for this processor has turned up, so this
decoder is a reconstruction. It is good for reading real code, but it is not a vendor
reference. [How far to trust the output](#how-far-to-trust-the-output) explains what
that means in practice.

## What you get

- **`ipp-dec`**, a command-line disassembler and coverage reporter.
- **An IDA processor module and ELF loader**, which open these binaries in IDA with
  functions, cross-references and stack tracking.
- **`ippdec`**, the C++17 library underneath both. All encoding knowledge lives there,
  in one table, so the tools cannot disagree with each other.

The sample binaries are third-party firmware and are not included. Please don't commit
them. You will need your own to do anything beyond the basic tests.

## Building

You need CMake 3.20 or newer and a C++17 compiler. Python 3 is optional and enables one
extra check.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

## Disassembling a file

Pick what to disassemble by function, section or address:

```sh
build/ipp-dec path/to/libc.so.7 --symbol memcpy
build/ipp-dec path/to/libc.so.7 --section .init
build/ipp-dec path/to/libc.so.7 --va 0x1fee4 --length 8
```

The last command prints:

```text
0001fee4  7700006f  len=4  sethi LR,13, c7  sequential
0001fee8  760126ff  len=4  brl LR,0x000f18a6, c7  call
```

Each line shows the address, raw bytes, length, instruction, and how control leaves it.
The last operand is always the predicate. C7 always reads one, so `c7` means
unconditional. In this example `brl` holds only the low half of a displacement, and the
decoder combined it with the `sethi LR` before it to work out the full target.

Bytes the decoder can't identify print as `unresolved` instead of a guess, and the scan
carries on after them. A trailing `; E=1 (raw)` marks an instruction with its E bit set,
which the section on trust covers below.

Two more commands report on the decoder itself:

```sh
build/ipp-dec --coverage path/to/file-or-directory   # decoded bytes per executable section
build/ipp-dec --forms                                # every known encoding and its evidence
```

## Opening files in IDA

This has only been built and exercised on macOS arm64. Point the build at your SDK:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DIPP_IDA_SDK=path/to/ida-sdk \
    -DIPP_IDA_LIB=path/to/libida.dylib
cmake --build build -j 4
```

That produces `build/ida/procs/ipp.dylib` and `build/ida/loaders/elfipp.dylib`. Copy them
into the `procs` and `loaders` folders of an IDA user directory. To leave your normal
setup alone, create a separate directory with your license accepted and point `IDAUSR`
at it. Then open an ELF file and choose **UniPhier IPP ELF**.

To load shared libraries into the same database, name them as absolute paths separated
by semicolons, and quote the whole argument in a shell:

```text
-Oelfipp:companions=<first library>;<second library>
```

Each image goes at its linked address with no rebasing, and an overlap fails the load.
Relocations change the database only, never your files.

After updating the modules, reanalyze existing databases. Decoding fixes do not reach
instructions that were already analyzed.

## How far to trust the output

The table holds 784 instruction forms: 758 extracted from the disassembler in a V8
JavaScript engine port found in the samples, and 26 that compiled code uses but V8's JIT
never emits. Across the 212 reference binaries, 77,050 of 98,302,772 executable bytes
remain unresolved.

**What the evidence supports:**

- **Instruction boundaries.** All 34,574 function symbols and 3,434,046 direct branch
  targets checked in the reference set land on decoded instruction boundaries.
- **Selected arithmetic.** Decoded routines were translated and run on a host against
  independently compiled source. `jpeg_idct_islow` matches the IJG code across 118,864
  input blocks, and the scalar RGB-to-YCbCr path matches libjpeg-turbo for all 16,777,216
  RGB values.
- **Some semantics** come from figures in patent US20040078549A1. It describes an earlier
  generation, so applying them to these binaries is an assumption.

**What is not established:**

- **Execution.** Nothing has run on real hardware or an emulator. Everything above is
  static analysis or a host model.
- **The E bit.** It is reported raw. What it means for parallel execution on this
  generation is unknown, so the decoder makes no claims about instruction packets.
- **FS, FD and XD aliases.** They are inferred from supplied libm code and are not a
  vendor register map.
- **Implicit effects.** Flags and system state are a supported subset, and the ABI picture
  is incomplete. Accesses that remain ambiguous are marked conservative in the library.
- **Relocation names.** The operations come from the runtime linker, but the official
  names are unknown. COPY, lazy PLT, unresolved external and TLS bindings stay pending,
  because this loader is not a dynamic linker.
- **Raw boot and microcode images.** Their load addresses and code/data boundaries are not
  known, so they don't count as validated input.

## Running more tests

With no options, `ctest` runs the tests that need nothing but this repository. Each of
these adds more:

| Configure option | What it adds |
| --- | --- |
| `-DIPP_CORPUS=<directory>` | Checks against the 212 reference binaries. They expect exact counts, so a different sample set will fail. |
| `-DIPP_IDA_RUNTIME_TESTS=ON` | Integration tests in throwaway IDA databases. Needs the SDK options above, plus `IPP_IDA_PYTHON`, `IPP_IDALIB_PYTHON` and `IPP_IDA_TEST_USER`. |
| `-DIPP_BOOT_ROM=<file>` | One more IDA test, on a raw boot image. |
| `-DIPP_SOURCE_MODEL_TESTS=ON` | The host comparisons described above. Needs `IPP_EVIDENCE_DIR`, the evidence archive that holds those models, which is not part of this repository. |

The IDA tests copy their inputs and never open an existing database. Set `IPP_IDA_ARGS` in
the environment to pass installation-specific options such as a license flag.

## Changing the code

- **The form table is generated.** Edit the rules in `tools/` and run
  `python3 -I tools/gen_v8_rules.py`. The `--check` flag, which is also a test, confirms
  the generated file is up to date.
- **Some values live in existing databases.** Register numbers, instruction codes and
  netnode names are stored in IDBs, so only ever append to them.
- **Other tools build against this one.** External evidence tools compile `ipp/decode.hpp`
  and `ipp/elf.hpp` as C++17 with warnings as errors, and expect `ipp-dec` and
  `libippdec.a` at the top of the build directory. That is why public names stay as they
  are, and why some results use output pointers.
- **Formatting is automatic.** `.clang-format` holds the rules and needs a recent
  clang-format:

  ```sh
  find include src tests \( -name '*.cpp' -o -name '*.hpp' \) | xargs clang-format -i
  ```
