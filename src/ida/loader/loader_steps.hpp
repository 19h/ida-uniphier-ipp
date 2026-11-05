// The stages of loading one ELF image into a database. Image number 0 is the primary
// input; companion images are numbered from 1, and their names carry that number.

#pragma once

#include <string>

#include <ida.hpp>

#include <diskio.hpp>

#include "ipp/elf.hpp"

namespace ipp::loader
{

/// \return NAME as it should appear in the database for image IMAGE_NUMBER.
[[nodiscard]] std::string database_name(unsigned image_number, const std::string &name);

/// Create segments and load the bytes of each PT_LOAD at its linked address, with load
/// bias zero. Overlap with anything already mapped is a load error.
void map_image(const ipp::Image &image, linput_t *input, unsigned image_number);

/// Apply the relocations whose effect is known, and record the rest on their targets.
void apply_relocations(const ipp::Image &image, unsigned image_number);

/// Name the image's symbols, and create functions with their declared extents.
void define_symbols(const ipp::Image &image, unsigned image_number);

} // namespace ipp::loader
