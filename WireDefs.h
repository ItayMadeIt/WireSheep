#pragma once

#include <cstdint>
#include <bitset>
#include <unordered_set>
#include <unordered_map>

using byte  = uint8_t;
using byte2 = uint16_t;
using byte4 = uint32_t;
using byte8 = uint64_t;

// Can add as many protocols
enum class ProvidedProtocols : byte4
{
	Invalid  =  0xFFFFFFFF,
	None =  0,
	Ethernet =  1,
	IPv4     =  2, // not fully implemented (options)
	IPv6     =  3, // not implemented
	UDP      =  4,
	TCP      =  5, // not fully implemented (options)
	DNS      =  6,
	HTTP     =  7, // not implemented
	ARP      =  8,
	ICMP     =  9, 
	Raw      = 10,
};
