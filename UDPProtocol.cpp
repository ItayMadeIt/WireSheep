#include "UDPProtocol.h"

#include "IPv4Protocol.h"

UDP::UDP(byte* data)
	: m_data(reinterpret_cast<UDPHeader*>(data))
{
	checksum(0);
	length(getSize());
}

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

void UDP::calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol)
{
	if (!protocol)
	{
		// Will throw exception
		return;
	}

	byte4 checksumVal = 0;

	if (const IPv4* ipv4 = dynamic_cast<const IPv4*>(protocol))
	{
		size_t ipv4Offset = offset - ipv4->getSize();

		// Add psuedo header
		checksumVal += length();
		AddrIPv4 addr = ipv4->src();
		checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data)));     // First 16-bit word
		checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data + 2))); // Second 16-bit word

		addr = ipv4->dst(); 
		checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data)));     // First 16-bit word
		checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data + 2))); // Second 16-bit word

		checksumVal += (byte2)(ipv4->protocol());

		// Add UDP header
		checksumVal += src();
		checksumVal += dst();

		checksumVal += length();

		bool isOdd = (length() - UDP::BASE_SIZE) % 2 != 0;

		// Iterate through 16-bit words
		byte2* iter = reinterpret_cast<byte2*>(buffer.data() + offset + UDP::BASE_SIZE);
		byte2* end = reinterpret_cast<byte2*>(buffer.data() + offset + length() - (isOdd ? 1 : 0));

		for (; iter < end; iter++)
		{
			checksumVal += Endianness::fromNetwork(*iter);
		}

		// Handle the last leftover byte if the payload length is odd
		if (isOdd)
		{
			// Get the last byte
			byte lastByte = *(buffer.data() + offset + length() - 1);
			byte2 paddedWord = (lastByte << 8); 
			checksumVal += paddedWord;
		}
	}
	/*else if (const IPv6* ipv6 = dynamic_cast<const IPv6*>(protocol))
	{
		// Assume it will work
		// const IPv6* ipv6 = dynamic_cast<const IPv6*>(protocol);

		// Not implemented yet
	}*/
	else
	{
		return;
	}

	while (checksumVal >> 16)
	{
		checksumVal = (checksumVal & 0xFFFF) + ((checksumVal >> 16) & 0xFFFF);
	}
	checksum( ~checksumVal );
}

size_t UDP::getSize() const
{
	return UDP::BASE_SIZE;
}

void UDP::encodePre(MutablePacket& packet, const size_t index)
{
	size_t startOffset = (byte*)m_data - (byte*)packet.m_buffer;
	size_t endOffset = packet.m_curSize;

	length(endOffset - startOffset);

	checksum(0);
}


void UDP::encodePost(MutablePacket& packet, const size_t index)
{
	byte4 checksumVal = 0;

	// Size of the packet from UDP
	byte2 fromProtocolSize = ((byte*)packet.m_buffer + packet.m_curSize) - (byte*)m_data;

	// Calculate checksum
	byte2* iter = (byte2*)(m_data);
	byte2* end = (byte2*)((byte*)m_data  + fromProtocolSize);

	if (const IPv4* ipv4 = packet.getPtr<IPv4>(index-1))
	{
		const size_t IPV4_PSESUDO_SIZE = 12;
		byte pseudoArr[IPV4_PSESUDO_SIZE] = { 0 };

		auto srcAddr = ipv4->src();
		std::memcpy(pseudoArr, &srcAddr, sizeof(ipv4->src()));
		auto dstAddr = ipv4->dst();
		std::memcpy(pseudoArr + 4, &dstAddr, sizeof(ipv4->dst()));
		pseudoArr[8] = 0;
		pseudoArr[9] = (byte)ipv4->protocol();
		pseudoArr[10] = length() >> 8;
		pseudoArr[11] = length() & 0xFF;


		for (size_t i = 0; i < IPV4_PSESUDO_SIZE; i += 2)
		{
			byte2 word = (pseudoArr[i] << 8) + pseudoArr[i + 1];
			checksumVal += word;
		}
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
	checksum(~checksumVal & 0xFFFF);
}