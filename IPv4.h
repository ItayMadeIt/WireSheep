#pragma once

#include "EndianHandler.h"
#include "Address.h"
#include "Protocol.h"
#include <optional>

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
	IPv4();
	IPv4(const addrIPv4 src, const addrIPv4 dst);
	IPv4(const std::string& src, const std::string& dst);
	IPv4(IPv4&& other);
	IPv4(const IPv4& other);

	void writeToBuffer(byte* ptr) const override;
	void readFromBuffer(const byte* ptr) override;

	void encodeLayer(std::vector<byte>& buffer) override;
	void encodeLayer(std::vector<byte>& buffer, const size_t offset) override;

	void encodeLayerRaw(std::vector<byte>& buffer) const override;
	void encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const override;


	size_t getSize() const override;


	IPv4& src(const addrIPv4 value) { m_src = value; return *this; }
	addrIPv4 src() const { return m_src; }

	IPv4& dst(const addrIPv4 value) { m_dst = value;return *this; }
	addrIPv4 dst() const { return m_dst; }

	IPv4& version(const byte value) { m_version = value; return *this;}
	byte version() const { return m_version; };

	IPv4& dscp(const byte value) { m_dscp = value; return *this;}
	byte dscp() const { return m_dscp; }

	IPv4& ecn(const byte value) { m_ecn = value; return *this;};
	byte ecn() const { return m_ecn; };

	IPv4& identifcation(const byte2 value) { m_identification = value; return *this;}
	byte2 identification() const { return m_identification; }

	IPv4& flags(const byte value) { m_flags = value; return *this; }
	IPv4& flags(const Flags value) { m_flags = (byte)value; return *this; }
	byte flags() const { return m_flags; }

	IPv4& fragmentOffset(const byte2 value) { m_fragmentOffset = value; return *this;}
	byte2  fragmentOffset() const { return m_fragmentOffset; }

	IPv4& ttl(const byte value) { m_ttl = value; return *this; }
	byte ttl() const { return m_ttl; }

	IPv4& protocol(const Protocols value) { m_protocol = (byte)value; return *this;}
	IPv4& protocol(const byte value) { m_protocol = value; return *this; }
	Protocols protocol() const { return (Protocols)m_protocol; }

	IPv4& checksum(const byte2 value) { m_checksum = value; return *this; }
	byte2 checksum() const { return m_checksum; }

	/// <summary>
	/// Calculates and updates checksum based on the IP fields
	/// </summary>
	void calcChecksum();

	IPv4& totalLength(const byte2 value) { m_totalLength = value; return *this; }
	byte2 totalLength() const { return m_totalLength; }

public:
	const static size_t SIZE = 20; // min size of 20 bytes

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

