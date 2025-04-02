#pragma once

#include "Packet.h"
#include "pcap/pcap.h"

struct IMMutableProtocolEntry
{
	size_t dataOffset;
	size_t objectOffset;
};

class IMMutablePacket : public Packet
{
public:
	IMMutablePacket(const byte* data, const byte4 length);
	IMMutablePacket(const byte* data, const byte4 length, struct timeval timestamp);


	// Inherited via Packet
	const byte* buffer() const override;
	const byte4 size() const override;

private:
	struct timeval m_timestamp;
	const byte* m_buffer;
	byte4 m_size;

};

