// Export production alias metadata for independent source-model checks.

#include <cstdio>

#include "ipp/registers.hpp"

int main()
{
    std::puts("register\tstorage\tbit_offset\tbit_count");
    for ( unsigned reg = ipp::FS0; reg <= ipp::XD63; ++reg )
    {
        const ipp::RegisterSlice slice = ipp::register_slice(static_cast<uint16_t>(reg));
        std::printf("%s\t%s\t%u\t%u\n", ipp::register_name(static_cast<uint16_t>(reg)),
                    ipp::register_name(slice.reg), slice.bit_offset, slice.bit_count);
    }
    return 0;
}
