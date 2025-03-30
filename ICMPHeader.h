#pragma once

#include "WireDefs.h"

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct ICMPHeader
{
	byte type;
	byte code;
	byte2 checksum;
	byte4 content; // additional header data

	// payload... 
};

#pragma pack(pop)