#pragma once

#include "Protocol.h"
#include "ICMPHeader.h"
#include "MutablePacket.h"

namespace ICMPMesssages
{
	struct EchoRequest
	{
		byte2 identifier;
		byte2 sequence;

		const byte* optionalDataPtr;
		size_t optionalDataLength;

		EchoRequest(byte2 id, byte2 seq, const byte* data = nullptr, size_t len = 0)
			: identifier(id), sequence(seq), optionalDataPtr(data), optionalDataLength(len) {}
	};

	struct EchoReply
	{
		EchoReply() = default;
		
		byte2 identifier;
		byte2 sequence;

		const byte* optionalDataPtr;
		size_t optionalDataLength;

		EchoReply(byte2 id, byte2 seq, const byte* data = nullptr, size_t len = 0)
			: identifier(id), sequence(seq), optionalDataPtr(data), optionalDataLength(len) {}
	};

	struct DestinationUnreachable
	{
		DestinationUnreachable() = default;

		byte code;
		byte length;
		byte nextHopMTU;

		// ptr to IPv4 in original packet
		const byte* originalPacketPtr;
		// length from IPv4 until the end
		byte2 originalPacketLength; 

		DestinationUnreachable(byte code, byte length, byte nextHopMTU,
			const byte* originalPacketPtr = nullptr, byte2 originalPacketLength = 0)
			: code(code),
			length(length),
			nextHopMTU(nextHopMTU),
			originalPacketPtr(originalPacketPtr),
			originalPacketLength(originalPacketLength)
		{}
	};

	struct TimeExceeded
	{
		byte code;

		// ptr to IPv4 in original packet 
		// assumes it can contains IPv4 header + 8 bytes (UDP/TCP)
		const byte* originalPacketPtr;
	
		TimeExceeded(byte code, const byte* originalPacketPtr = nullptr)
			: code(code), originalPacketPtr(originalPacketPtr)
		{}
	};
}

class ICMP : public Protocol
{
	enum class ControlType : byte
	{
		EchoReply = 0,
		DestUnreachable = 3,
		EchoRequest = 8,
		TimeExceeded = 11,
	};
	enum class ControlCode : byte
	{
		// EchoReply (Type 0) and EchoRequest (Type 8)
		EchoReply = 0,
		EchoRequest = 0,

		// Destination Unreachable (Type 3)
		DestNetworkUnreachable = 0,
		DestHostUnreachable = 1,
		DestProtocolUnreachable = 2,
		DestPortUnreachable = 3,
		DestFragmentationDF = 4, // Fragmentation needed and DF set
		DestSourceRouteFailed = 5,
		DestNetworkUnknown = 6,
		DestHostUnknown = 7,
		DestSourceHostIsolated = 8,
		DestNetworkProhibited = 9,
		DestHostProhibited = 10,
		NetworkUnreachableForTOS = 11,
		HostUnreachableForTOS = 12,
		CommAdminProhibited = 13,
		HostPrecedenceViolation = 14,
		PrecedenceCutoffInEffect = 15,

		// Time Exceeded (Type 11)
		TTLExpired = 0,
		FragmentReassemblyExceeded = 1,
	};

public:
	ICMP(byte* data);
	ICMP(byte* data, MutablePacket& packet, ICMPMesssages::EchoReply msg);
	ICMP(byte* data, MutablePacket& packet, ICMPMesssages::EchoRequest msg);
	ICMP(byte* data, MutablePacket& packet, ICMPMesssages::DestinationUnreachable msg);
	ICMP(byte* data, MutablePacket& packet, ICMPMesssages::TimeExceeded msg);
	virtual ~ICMP() = default;

	ICMP& type(const byte value);
	ICMP& type(const ControlType value);
	byte type() const;

	ICMP& code(const byte value);
	ICMP& code(const ControlCode value);
	byte code() const;

	ICMP& checksum(const byte2 value);
	byte2 checksum();

	// Simple content access
	ICMP& content(const byte4 value);
	byte4 content();

	ICMP& setPayload(MutablePacket& packet, const byte* payload, const byte2 length);
	byte* getPayloadPtr();
	byte2 getPayloadLength();


	virtual size_t getSize() const override;
	virtual void addr(byte* address) override;
	virtual byte* addr() const override;
	virtual ProvidedProtocols protType() const override;

	void encodePre(MutablePacket& packet, const size_t index);
	void encodePost(MutablePacket& packet, const size_t index);

public:
	constexpr static size_t BASE_SIZE = sizeof(ICMPHeader);

protected:
	

protected:
	ICMPHeader* m_data;

	byte2 m_payloadLength;
};


