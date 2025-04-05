#pragma once

#include "EndianHandler.h"
#include "Address.h"
#include "Protocol.h"
#include <optional>
#include "IPv4Header.h"
#include "MutablePacket.h"

using namespace address;

class IPv4 : public Protocol
{
public:
	// All IPv4 Flags (3 bits but reserved is no explicitly used)
	enum class Flags : byte
	{
		NONE  = 0b000,
		MF    = 0b001,
		DF    = 0b010,
		MF_DF = 0b011,
	};

	// All IPv4 protocols
	enum class Protocols : byte
	{
		ICMP = 1,      // Internet Control Message Protocol (ICMP)
		IGMP = 2,      // Internet Group Management Protocol (IGMP)
		TCP = 6,	   // Transmission Control Protocol (TCP)
		UDP = 17,	   // User Datagram Protocol (UDP)
		ENCAP = 41,	   // IPv6 Encapsulation (ENCAP)
		OSPF = 89,	   // Open Shortest Path First (OSPF)
		SCTP = 132,	   // Stream Control Transmission Protocol (SCTP)
	};

	// All Services (for DSCP)
	enum class Services
	{
		// low latency data
		AF21 = 18,
		AF22 = 20,
		AF23 = 22,

		// High throughput data
		AF11 = 10,
		AF12 = 12,
		AF13 = 14,

		// Network Control
		CS0 = 0,
		
		CS1 = 8,

		// OAM
		CS2 = 16,

		// Broadcast video
		CS3 = 24,
		
		// Real Time Interactive
		CS4 = 32,
		
		// Signaling
		CS5 = 40,
		
		CS6 = 48,
		
		CS7 = 56,

		// Telphony
		EF = 46,

		// Multimedia conferencing
		AF41 = 34,
		AF42 = 36,
		AF43 = 38,

		// Multimedia streaming
		AF31 = 26,
		AF32 = 28,
		AF33 = 30,

		// Standard
		DF = 0,

		// Lower Effort
		LE = 1
	};

public:
	IPv4(IPv4&& other);
	IPv4(const IPv4& other);
	IPv4(byte* data);
	IPv4(byte* data, AddrIPv4 src, AddrIPv4 dst);

public:
	IPv4& src(const AddrIPv4 value);
	AddrIPv4 src() const;

	IPv4& dst(const AddrIPv4 value);
	AddrIPv4 dst() const;

	IPv4& version(const byte value);
	byte version() const;

	IPv4& ihl(const byte value);
	byte ihl() const;

	IPv4& dscp(const byte value);
	byte dscp() const;

	IPv4& ecn(const byte value);
	byte ecn() const;

	IPv4& identification(const byte2 value);
	byte2 identification() const;

	IPv4& flags(const byte value);
	IPv4& flags(const Flags value);
	byte flags() const;

	IPv4& fragmentOffset(const byte2 value);
	byte2 fragmentOffset() const;

	IPv4& ttl(const byte value);
	byte ttl() const;

	IPv4& protocol(const Protocols value);
	IPv4& protocol(const byte value);
	byte protocol() const;

	IPv4& totalLength(const byte2 value); 
	byte2 totalLength() const;

	IPv4& checksum(const byte2 value);
	byte2 checksum() const;

	virtual size_t getSize() const override;
	
	virtual void addr(byte* address) override;
	virtual byte* addr() const override;
	
	virtual ProvidedProtocols protType() const;

	virtual void encodePre(MutablePacket& packet, const size_t index) override;
	virtual void encodePost(MutablePacket& packet, const size_t index) override;

	friend std::ostream& operator<<(std::ostream& os, const IPv4& ipv4);

public:
	static constexpr ProvidedProtocols ID = ProvidedProtocols::IPv4;
	static constexpr size_t BASE_SIZE = sizeof(IPv4Header);

protected:
	const static byte IHL_MIN_SIZE = 5;

protected:
	IPv4Header* m_data;
};
