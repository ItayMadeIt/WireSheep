#pragma once

#include <cstdint>
#include <bitset>
#include <unordered_set>
#include <unordered_map>

using byte  = uint8_t;
using byte2 = uint16_t;
using byte4 = uint32_t;
using byte8 = uint64_t;

// Can add as many protoocls
enum class ProvidedProtocols : byte4
{
	Invalid  =  0,
	Ethernet =  1,
	IPv4     =  2,
	IPv6     =  3, // not implemneted
	UDP      =  4,
	TCP      =  5, // not fully implemneted
	DNS      =  6,
	HTTP     =  7, // not implemneted
	ARP      =  8,
	ICMP     =  9,
	Raw      = 10,
};
