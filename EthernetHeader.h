#pragma once

#include "Address.h"

using namespace address;

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct EthernetHeader
{
	AddrMac dst;
	AddrMac src;
	byte2 etherType;
};

#pragma pack(pop)