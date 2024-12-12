#pragma once

#include <cstdint>

using byte  = uint8_t;
using byte2 = uint16_t;
using byte4 = uint32_t;
using byte8 = uint64_t;

enum class ProtocolTypes : byte
{
	Invalid = -1,
	Ethernet = 0,
	IPv4 = 1,
	IPv6 = 2,
	UDP = 3,
	TCP = 4,
	DNS = 5,
	HTTP = 6,
};
