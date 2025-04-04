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
	IMMutablePacket(byte* data, const byte4 length);
	IMMutablePacket(byte* data, const byte4 length, struct timeval timestamp);


	// Inherited via Packet
	const byte* buffer() const override;
	const byte4 size() const override;

	byte* buffer();
	byte4 size();

private:
	struct timeval m_timestamp;
	byte* m_buffer;
	byte4 m_size;

};

