#include "EndianHandler.h"

const bool Endianness::bigEndian = Endianness::isSystemBigEndian();

bool Endianness::isBigEndian()
{
    return bigEndian;
}

bool Endianness::isSystemBigEndian()
{
    // 2 byte values
    uint16_t test = 1;
    return reinterpret_cast<const byte*>(&test)[0] == 0;
}
