#pragma once

#include "Address.h"

using namespace address;

#pragma pack(push)

struct EthernetHeader
{
	AddrMac m_src;
	AddrMac m_dst;
	byte2 m_etherType;
};

#pragma pack(pop)