#pragma once

#include <cstdint>
#include <bitset>
#include <unordered_set>
#include <unordered_map>

using byte  = uint8_t;
using byte2 = uint16_t;
using byte4 = uint32_t;
using byte8 = uint64_t;

enum class ProvidedProtocols : byte
{
	Invalid = -1,
	Raw = 0,
	Ethernet = 1,
	IPv4 = 2,
	IPv6 = 3,
	UDP = 4,
	TCP = 5,
	DNS = 6,
	HTTP = 7, 
	ARP = 8,
};
