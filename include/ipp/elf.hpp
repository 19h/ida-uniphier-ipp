// ELF32 big-endian reader for e_machine 0x1040.
//
// Structural facts (section sizes, dynsym extents, RELA types, PT_LOAD) are
// computed from the file. Nothing here is an instruction decoder.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ipp
{

struct Section
{
    std::string name;
    uint32_t type = 0;
    uint32_t flags = 0;
    uint32_t addr = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
    uint32_t link = 0;
    uint32_t entsize = 0;

    /// SHF_WRITE
    [[nodiscard]] bool is_writable() const { return (flags & 1) != 0; }
    /// SHF_ALLOC
    [[nodiscard]] bool is_allocated() const { return (flags & 2) != 0; }
    /// SHF_EXECINSTR
    [[nodiscard]] bool is_executable() const { return (flags & 4) != 0; }
    /// SHT_NOBITS: occupies memory but has no bytes in the file.
    [[nodiscard]] bool is_nobits() const { return type == 8; }
    /// An executable section with at least one file-backed byte to decode.
    [[nodiscard]] bool has_code() const { return is_executable() && !is_nobits() && size != 0; }
};

struct Segment
{
    uint32_t type = 0;
    uint32_t flags = 0;
    uint32_t offset = 0;
    uint32_t va = 0;
    uint32_t filesz = 0;
    uint32_t memsz = 0;

    /// PT_LOAD
    [[nodiscard]] bool is_load() const { return type == 1; }
    /// PF_X
    [[nodiscard]] bool is_executable() const { return (flags & 1) != 0; }
};

struct Symbol
{
    std::string name;
    uint32_t value = 0;
    uint32_t size = 0;
    uint8_t info = 0;
    uint32_t shndx = 0; // resolved SHT_SYMTAB_SHNDX value, or a direct ELF index
    bool from_dynsym = false;
    uint32_t table_section = 0;
    uint32_t index = 0;

    /// Bound to a section, rather than SHN_UNDEF.
    [[nodiscard]] bool is_defined() const { return shndx != 0; }
    /// STT_OBJECT
    [[nodiscard]] bool is_object() const { return (info & 0xf) == 1; }
    /// STT_FUNC
    [[nodiscard]] bool is_function() const { return (info & 0xf) == 2; }
};

struct Reloc
{
    std::string section;
    uint32_t offset = 0;
    uint32_t type = 0;
    uint32_t sym = 0;
    int32_t addend = 0;
    uint32_t symbol_table = 0;
    bool explicit_addend = true;
};

/// Everything parsed out of an ELF file's headers and tables.
struct ImageMetadata
{
    uint16_t machine = 0;
    uint16_t type = 0;
    uint32_t entry = 0;
    uint32_t flags = 0;
    std::vector<Section> sections;
    std::vector<Segment> segments;
    std::vector<Symbol> symbols;
    std::vector<Reloc> relocs;
};

/// One ELF file held in memory. Reusable: each load discards the previous state,
/// and a failed load leaves no metadata behind.
class Image
{
public:
    [[nodiscard]] bool load_file(const std::string &path);
    [[nodiscard]] bool load_bytes(const uint8_t *data, size_t size, const std::string &label);

    [[nodiscard]] const std::string &label() const { return label_; }
    [[nodiscard]] const std::string &error() const { return error_; }
    [[nodiscard]] const std::vector<uint8_t> &bytes() const { return bytes_; }

    [[nodiscard]] uint16_t machine() const { return metadata_.machine; }
    [[nodiscard]] uint16_t type() const { return metadata_.type; }
    [[nodiscard]] uint32_t entry() const { return metadata_.entry; }
    [[nodiscard]] uint32_t flags() const { return metadata_.flags; }

    [[nodiscard]] const std::vector<Section> &sections() const { return metadata_.sections; }
    [[nodiscard]] const std::vector<Segment> &segments() const { return metadata_.segments; }
    [[nodiscard]] const std::vector<Symbol> &symbols() const { return metadata_.symbols; }
    [[nodiscard]] const std::vector<Reloc> &relocs() const { return metadata_.relocs; }

    /// \return the first section called NAME, or nullptr.
    [[nodiscard]] const Section *section(std::string_view name) const;

    /// \return the sized, defined function called NAME, preferring dynsym, or nullptr.
    [[nodiscard]] const Symbol *function(std::string_view name) const;

    /// \return the symbol that RELOC refers to, or nullptr.
    [[nodiscard]] const Symbol *reloc_symbol(const Reloc &reloc) const;

    /// Only allocated executable sections describe runtime code; PT_LOAD
    /// permissions are the fallback when no such sections are present.
    [[nodiscard]] bool executable_va(uint32_t va, uint32_t length = 1) const;

    /// Read file-backed virtual bytes from allocated sections or PT_LOAD.
    /// Nonallocated metadata is never addressed through its conventional zero
    /// sh_addr. SHT_NOBITS and zero-filled load tails supply no file bytes.
    /// OUT is cleared on failure.
    [[nodiscard]] bool read_va(uint32_t va, uint32_t length, std::vector<uint8_t> *out) const;

    /// Find a NUL-terminated byte sequence; a nonterminated substring is not
    /// evidence that the complete requested C string exists in the file.
    [[nodiscard]] bool contains_cstring(std::string_view text) const;

    /// Null unless the number is tied to a name the file actually contains.
    /// R_IPP_COPY is present as a string in ld-elf.so.1; its number is not.
    [[nodiscard]] static const char *reloc_name(uint32_t type);

private:
    /// Forget any previous file, starting a load of LABEL.
    void reset(const std::string &label);

    /// Parse bytes_, leaving no metadata behind on failure.
    bool parse();

    std::string label_;
    std::string error_;
    std::vector<uint8_t> bytes_;
    ImageMetadata metadata_;
};

} // namespace ipp
