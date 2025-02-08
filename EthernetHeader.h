#pragma once

#include "Address.h"

using namespace address;

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct EthernetHeader
{
	AddrMac m_dst;
	AddrMac m_src;
	byte2 m_etherType;
};

#pragma pack(pop)