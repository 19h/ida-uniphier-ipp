// ELF32 on-disk layout: the constants and field offsets this reader relies on.

#pragma once

#include <cstddef>
#include <cstdint>

namespace ipp::elf
{

constexpr uint16_t MACHINE_IPP = 0x1040;

// e_ident
constexpr uint8_t CLASS_32 = 1;
constexpr uint8_t DATA_BIG_ENDIAN = 2;

// sh_type
constexpr uint32_t SHT_NULL = 0;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_REL = 9;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint32_t SHT_SYMTAB_SHNDX = 18;

// Special section indexes
constexpr uint32_t SHN_UNDEF = 0;
constexpr uint32_t SHN_LORESERVE = 0xff00;
constexpr uint32_t SHN_XINDEX = 0xffff;

// Record sizes
constexpr size_t FILE_HEADER_SIZE = 52;
constexpr size_t PROGRAM_HEADER_SIZE = 32;
constexpr size_t SECTION_HEADER_SIZE = 40;
constexpr size_t SYMBOL_SIZE = 16;
constexpr uint32_t REL_SIZE = 8;
constexpr uint32_t RELA_SIZE = 12;

// Elf32_Ehdr
constexpr size_t EH_TYPE = 16;
constexpr size_t EH_MACHINE = 18;
constexpr size_t EH_ENTRY = 24;
constexpr size_t EH_PHOFF = 28;
constexpr size_t EH_SHOFF = 32;
constexpr size_t EH_FLAGS = 36;
constexpr size_t EH_PHENTSIZE = 42;
constexpr size_t EH_PHNUM = 44;
constexpr size_t EH_SHENTSIZE = 46;
constexpr size_t EH_SHNUM = 48;
constexpr size_t EH_SHSTRNDX = 50;

// Elf32_Phdr
constexpr size_t PH_TYPE = 0;
constexpr size_t PH_OFFSET = 4;
constexpr size_t PH_VADDR = 8;
constexpr size_t PH_FILESZ = 16;
constexpr size_t PH_MEMSZ = 20;
constexpr size_t PH_FLAGS = 24;

// Elf32_Shdr
constexpr size_t SH_NAME = 0;
constexpr size_t SH_TYPE = 4;
constexpr size_t SH_FLAGS = 8;
constexpr size_t SH_ADDR = 12;
constexpr size_t SH_OFFSET = 16;
constexpr size_t SH_SIZE = 20;
constexpr size_t SH_LINK = 24;
constexpr size_t SH_ENTSIZE = 36;

// Elf32_Sym
constexpr size_t ST_NAME = 0;
constexpr size_t ST_VALUE = 4;
constexpr size_t ST_SIZE = 8;
constexpr size_t ST_INFO = 12;
constexpr size_t ST_SHNDX = 14;

// Elf32_Rel, Elf32_Rela
constexpr size_t R_OFFSET = 0;
constexpr size_t R_INFO = 4;
constexpr size_t R_ADDEND = 8;

} // namespace ipp::elf
