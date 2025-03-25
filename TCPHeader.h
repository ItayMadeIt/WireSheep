#pragma once

#include "WireDefs.h"

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct TCPHeader
{
	byte2 src;
	byte2 dst;
	byte4 seq;
	byte4 ack;
	byte  dataOffset;
	byte  flags;
	byte2 window;
	byte2 checksum;
	byte2 urgPtr;
};

#pragma pack(pop)