#include "UDP.h"
#include "IPv4.h"

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
