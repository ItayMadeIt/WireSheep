#include "EndianHandler.h"

const bool EndiannessHandler::bigEndian = EndiannessHandler::isSystemBigEndian();

bool EndiannessHandler::isBigEndian()
{
    return bigEndian;
}

bool EndiannessHandler::isSystemBigEndian()
{
    // 2 byte values
    uint16_t test = 1;
    return reinterpret_cast<const char*>(&test)[0] == 0;
}
