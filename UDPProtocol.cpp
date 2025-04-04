#include "UDPProtocol.h"

#include "IPv4Protocol.h"

UDP::UDP(byte* data)
	: m_data(reinterpret_cast<UDPHeader*>(data))
{}

UDP::UDP(byte* data, const byte2 src, const byte2 dst)
	: m_data(reinterpret_cast<UDPHeader*>(data))
{
	this->src(src);
	this->dst(dst);
}

UDP& UDP::src(const byte2 value)
{
	m_data->src = Endianness::toNetwork(value);
	return *this;
}
byte2 UDP::src() const
{
	return Endianness::fromNetwork(m_data->src);
}
UDP& UDP::dst(const byte2 value)
{
	m_data->dst = Endianness::toNetwork(value);
	return *this;
}
byte2 UDP::dst() const
{
	return Endianness::fromNetwork(m_data->dst);
}
UDP& UDP::length(const byte2 value)
{
	m_data->length = Endianness::toNetwork(value);
	return *this;
}
byte2 UDP::length() const
{
	return Endianness::fromNetwork(m_data->length);
}
UDP& UDP::checksum(const byte2 value)
{
	m_data->checksum = Endianness::toNetwork(value);
	return *this;
}
byte2 UDP::checksum() const
{
	return Endianness::fromNetwork(m_data->checksum);
}

void UDP::addr(byte* address)
{
	m_data = reinterpret_cast<UDPHeader*>(address);
}

byte* UDP::addr() const
{
	return reinterpret_cast<byte*>(m_data);
}

void UDP::calculateChecksum(MutablePacket& packet, const size_t index)
{
	byte4 checksumVal = 0;

	// Size of the packet from UDP
	byte2 fromProtocolSize = ((byte*)packet.getBuffer()  + packet.getSize()) - (byte*)m_data;

	// Calculate checksum
	byte2* iter = (byte2*)(m_data);
	byte2* end = (byte2*)((byte*)m_data + fromProtocolSize);

	Protocol* lastProtocol = packet.getPtr<Protocol>(index-1);
	
	if (lastProtocol == nullptr)
	{
		throw std::runtime_error("Couldn't calculate checksum, UDP first layer.");
	}
	
	if (lastProtocol->protType() == ProvidedProtocols::IPv4)
	{
		const IPv4* ipv4 = packet.getPtr<IPv4>(index - 1);
		const size_t IPV4_PSESUDO_SIZE = 12;
		byte pseudoArr[IPV4_PSESUDO_SIZE] = { 0 };

		auto srcAddr = ipv4->src();
		std::memcpy(pseudoArr, &srcAddr, sizeof(ipv4->src()));
		auto dstAddr = ipv4->dst();
		std::memcpy(pseudoArr + 4, &dstAddr, sizeof(ipv4->dst()));
		pseudoArr[8] = 0;
		pseudoArr[9] = (byte)ipv4->protocol();
		
		// Set length
		std::memcpy(&pseudoArr[10], &m_data->length, sizeof(m_data->length));

		for (size_t i = 0; i < IPV4_PSESUDO_SIZE; i += 2)
		{
			checksumVal += Endianness::fromNetwork(
				*reinterpret_cast<byte2*>(&pseudoArr[i])
			);
		}
	}
	else
	{
		throw std::runtime_error("Couldn't calculate checksum, no transport layer found.");
	}

	int isOdd = (fromProtocolSize & 1) ? 1 : 0;

	while (iter + isOdd < end)
	{
		checksumVal += Endianness::fromNetwork(*iter);

		iter++;
	}

	if (isOdd)
	{
		byte lastByte = *((byte*)iter);
		checksumVal += (lastByte << 8);
	}

	while (checksumVal & 0xFFFF0000)
	{
		checksumVal = (checksumVal >> 16) + (checksumVal & 0xFFFF);
	}

	// one complement
	checksum(~checksumVal);
}

size_t UDP::getSize() const
{
	return UDP::BASE_SIZE;
}

ProvidedProtocols UDP::protType() const
{
	return ProvidedProtocols::UDP;
}

void UDP::encodePre(MutablePacket& packet, const size_t index)
{
	byte2 startOffset = (byte*)m_data - (byte*)packet.getBuffer();
	byte2 endOffset = packet.getSize();

	length(endOffset - startOffset);

	checksum(0);
}


void UDP::encodePost(MutablePacket& packet, const size_t index)
{
	calculateChecksum(packet, index);
}