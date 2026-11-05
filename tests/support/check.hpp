// Minimal assertion support for the standalone test executables.
//
// A failed CHECK reports its location and lets the test carry on, so one run shows
// every failure. Tests exit nonzero when failure_count is nonzero.

#pragma once

#include <cstdio>
#include <string_view>

namespace ipp::test
{

inline int failure_count = 0;

inline void report_failure(const char *expression, const char *file, int line)
{
    std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
    ++failure_count;
}

/// True if TEXT is a non-null C string equal to EXPECTED.
[[nodiscard]] inline bool text_equals(const char *text, std::string_view expected)
{
    return text != nullptr && expected == text;
}

} // namespace ipp::test

#define CHECK(...)                                                                                 \
    do                                                                                             \
    {                                                                                              \
        if ( !static_cast<bool>(__VA_ARGS__) )                                                     \
            ipp::test::report_failure(#__VA_ARGS__, __FILE__, __LINE__);                           \
    } while ( false )
