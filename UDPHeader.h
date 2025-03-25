#pragma once

#include "WireDefs.h"

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct UDPHeader
{
	byte2 src;
	byte2 dst;
	byte2 length;
	byte2 checksum;
};

#pragma pack(pop)