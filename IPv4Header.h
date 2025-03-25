#pragma once

#include "Address.h"

using namespace address;

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct IPv4Header
{
	byte     version_ihl;
	byte     dscp_ecn;
	byte2    totalLength;
	byte2    identification;
	byte2    flags_framentOffset;
	byte     ttl;
	byte     protocol;
	byte2    checksum;
	AddrIPv4 src;
	AddrIPv4 dst;
};

#pragma pack(pop)