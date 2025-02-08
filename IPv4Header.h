#pragma once

#include "Address.h"

using namespace address;

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct IPv4Header
{
	byte m_versionIhl;
	byte m_dscpEcn;
	byte2 m_totalLength;
	byte2 m_identification;
	byte2 m_flags_framentoffset;
	byte m_ttl;
	byte m_protocol;
	byte2 m_checksum;
	AddrIPv4 m_src;
	AddrIPv4 m_dst;
};

#pragma pack(pop)