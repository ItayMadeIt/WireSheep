#pragma once

#include "WireDefs.h"

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct UDPHeader
{
	byte2 m_src;
	byte2 m_dst;
	byte2 m_length;
	byte2 m_checksum;
};

#pragma pack(pop)