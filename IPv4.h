#pragma once

#include "EndianHandler.h"
#include "Address.h"
#include "Protocol.h"

using namespace address;

class IPv4 : public Protocol
{
public:
	enum class IPProtocols : byte
	{
		ICMP = 1,      // Internet Control Message Protocol (ICMP)
		IGMP = 2,      // Internet Group Management Protocol (IGMP)
		TCP = 6,	   // Transmission Control Protocol (TCP)
		UDP = 17,	   // User Datagram Protocol (UDP)
		ENCAP = 41,	   // IPv6 Encapsulation (ENCAP)
		OSPF = 89,	   // Open Shortest Path First (OSPF)
		SCTP = 132,	   // Stream Control Transmission Protocol (SCTP)
	};

public:
	IPv4(const addrIPv4 srcAddr, const addrIPv4 dstAddr);
	IPv4(const addrIPv4 srcAddr, const addrIPv4 dstAddr, std::unique_ptr<Protocol> nextProtocol);
	IPv4(IPv4&& other);
	IPv4(const IPv4& other);

	// Protocol override functions
	void serializeArr(byte* ptr) const override;
	void deserializeArr(const byte* ptr) override;

	void serialize(std::vector<byte>& buffer) const override;

	size_t getSize() const override;

	void serialize(std::vector<byte>& buffer, const size_t offset) const override;

	void version(const byte value) { m_version = value; }
	byte version() const { return m_version; };

	void dscp(const byte value) { m_dscp = value; }
	byte dscp() const { return m_dscp; }

	void ecn(const byte value) { m_ecn = value; };
	byte ecn() const { return m_ecn; };

	void identifcation(const byte2 value) { m_identification = value; }
	byte2 identification() const { return m_identification; }

	void flags(const byte value) { m_flags = value; }
	byte flags() const { return m_flags; }

	void fragmentOffset(const byte2 value) { m_fragmentOffset = value; }
	byte2  fragmentOffset() const { return m_fragmentOffset; }

	void ttl(const byte value) { m_ttl = value; }
	byte ttl() const { return m_ttl; }

	void protocol(const IPProtocols value) { m_protocol = (byte)value; }
	void protocol(const byte value) { m_protocol = value; }
	IPProtocols protocol() const { return (IPProtocols)m_protocol; }

public:
	const static size_t Size = 14;

protected: // So people can make their own IPv4 and modify those vars

	// in IPv4 setup has to be the value 4 (but you physically can modify it) | 4 bits
	byte m_version = 4; 
	
	// IHL the length (internet header length => ihl * 8 MUST BE AT LEAST 5) | 4 bits
	byte m_ihl;
	
	// https://en.wikipedia.org/wiki/Differentiated_services DSCP (ToS) specification | 6 bits
	byte m_dscp;

	// https://en.wikipedia.org/wiki/Explicit_Congestion_Notification ECN, useful for handling congestion | 2 bits
	byte m_ecn;

	// Total packet size from IP layer (including header) | 16 bits
	byte2 m_totalLength;

	// Identification | 16 bits
	byte2 m_identification;

	// Flags (Reserved, Dont-Fragment, More-Fragments) | 3 bits
	byte m_flags;

	// Fragment offset (Relative to the beginning in multiples of 8) | 13 bits
	byte2 m_fragmentOffset;

	// TTL (Time To Live) | 8 bits
	byte m_ttl;
	
	// Protocol (Transport layer protocol) https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers | 8 bits
	byte m_protocol;

	// Checksum used for error checking | 16 bits
	byte2 m_checksum;

	// Options list: https://en.wikipedia.org/wiki/Internet_Protocol_Options | 0 - 320 bits (IHL > 5)
	byte4 m_options[5];

	// addresses
	addrIPv4 m_src; // source address | 32 bits
	addrIPv4 m_dst;	// dest address | 32 bits

	const byte IHL_MIN_SIZE = 5;
};

