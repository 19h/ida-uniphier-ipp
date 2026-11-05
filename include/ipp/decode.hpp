// Convenience header for the whole decoder API.
//
// External evidence tools include this path, so it must keep compiling as C++17
// with -Wall -Wextra -Werror. New code can include just what it needs.

#pragma once

#include "ipp/decoder.hpp"
#include "ipp/format.hpp"
#include "ipp/instruction.hpp"
#include "ipp/registers.hpp"
#include "ipp/semantics.hpp"
