#include "UDPProtocol.h"

#include "IPv4Protocol.h"

UDP::UDP() 
	: Protocol(AllProtocols::UDP),
	m_src(0), m_dst(0), m_length(8), m_checksum(0)
{}

UDP::UDP(const byte2 src, const byte2 dst)
	: Protocol(AllProtocols::UDP),
	m_src(src), m_dst(dst), m_length(8), m_checksum(0)
{}

void UDP::calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol)
{
	if (!protocol)
	{
		// Will throw exception
		return;
	}

	byte4 checksumVal = 0;

	if (protocol->getProtocol() == AllProtocols::IPv4)
	{
		// Assume it will work
		const IPv4* ipv4 = dynamic_cast<const IPv4*>(protocol);


		size_t ipv4Offset = offset - ipv4->getSize();

		// Add psuedo header
		checksumVal += m_length;
		AddrIPv4 addr = ipv4->src();
		checksumVal += EndiannessHandler::fromNetworkEndian(*(reinterpret_cast<byte2*>(addr.m_data)));    // First 16-bit word
		checksumVal += EndiannessHandler::fromNetworkEndian(*(reinterpret_cast<byte2*>(addr.m_data + 2))); // Second 16-bit word

		addr = ipv4->dst(); 
		checksumVal += EndiannessHandler::fromNetworkEndian(*(reinterpret_cast<byte2*>(addr.m_data)));    // First 16-bit word
		checksumVal += EndiannessHandler::fromNetworkEndian(*(reinterpret_cast<byte2*>(addr.m_data + 2))); // Second 16-bit word

		checksumVal += (byte2)(ipv4->protocol());

		// Add UDP header
		checksumVal += m_src;
		checksumVal += m_dst;

		checksumVal += m_length;

		bool isOdd = (m_length - UDP::Size) % 2 != 0;

		// Iterate through 16-bit words
		byte2* iter = reinterpret_cast<byte2*>(buffer.data() + offset + UDP::Size);
		byte2* end = reinterpret_cast<byte2*>(buffer.data() + offset + m_length - (isOdd ? 1 : 0));

		for (; iter < end; iter++)
		{
			checksumVal += EndiannessHandler::fromNetworkEndian(*iter);
		}

		// Handle the last leftover byte if the payload length is odd
		if (isOdd)
		{
			// Get the last byte
			byte lastByte = *(buffer.data() + offset + m_length - 1); 
			byte2 paddedWord = (lastByte << 8); 
			checksumVal += paddedWord;
		}
	}
	else if (protocol->getProtocol() == AllProtocols::IPv6)
	{
		// Assume it will work
		// const IPv6* ipv6 = dynamic_cast<const IPv6*>(protocol);

		// Not implemented yet
	}
	else
	{
		return;
	}

	while (checksumVal >> 16)
	{
		checksumVal = (checksumVal & 0xFFFF) + (checksumVal >> 16);
	}
	m_checksum = ~checksumVal;

	byte2 networkChecksum = EndiannessHandler::toNetworkEndian(m_checksum);

	size_t headerChecksumOffset = offset + 6; // 6 = header checksum position relative to UDP start of the packet
	byte* checksumPtr = buffer.data() + headerChecksumOffset;

	std::memcpy(checksumPtr, &networkChecksum, sizeof(networkChecksum));
}


void UDP::writeToBuffer(byte* buffer) const
{
	// Input ports
	byte2 val = EndiannessHandler::toNetworkEndian(m_src);
	memcpy(buffer, &val, sizeof(byte2));
	buffer += sizeof(byte2);

	val = EndiannessHandler::toNetworkEndian(m_dst);
	memcpy(buffer, &val, sizeof(byte2));
	buffer += sizeof(byte2);

	// Put length
	val = EndiannessHandler::toNetworkEndian(m_length);
	memcpy(buffer, &val, sizeof(byte2));
	buffer += sizeof(byte2);

	// Put Checksum
	val = EndiannessHandler::toNetworkEndian(m_checksum);
	memcpy(buffer, &val, sizeof(byte2));
}

void UDP::readFromBuffer(const byte* buffer, const size_t size)
{
	// Will be implemented in the future
}

void UDP::encodeLayer(std::vector<byte>& buffer, const size_t offset)
{
	// Get the amount of bytes we have left to input
	m_length = buffer.capacity() - offset;
	m_checksum = 0;

	// Add UDP data to the array
	buffer.resize(buffer.size() + UDP::Size);
	writeToBuffer(buffer.data() + offset);
}

void UDP::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
	// Add UDP data to the array
	buffer.resize(buffer.size() + UDP::Size);
	writeToBuffer(buffer.data() + offset);
}


size_t UDP::getSize() const
{
	return UDP::Size;
}
