#include "UDP.h"

UDP::UDP() 
	: Protocol(ProtocolTypes::UDP),
	m_src(0), m_dst(0), m_length(8), m_checksum(0)
{}

UDP::UDP(const byte2 src, const byte2 dst)
	: Protocol(ProtocolTypes::UDP),
	m_src(src), m_dst(dst), m_length(8), m_checksum(0)
{}

void UDP::serializeArr(byte * ptr) const
{
	// Input ports
	byte2 val = EndiannessHandler::toNetworkEndian(m_src);
	memcpy(ptr, &val, sizeof(byte2));
	ptr += sizeof(byte2);

	val = EndiannessHandler::toNetworkEndian(m_dst);
	memcpy(ptr, &val, sizeof(byte2));
	ptr += sizeof(byte2);

	// Put length
	val = EndiannessHandler::toNetworkEndian(m_length);
	memcpy(ptr, &val, sizeof(byte2));
	ptr += sizeof(byte2);

	// Put Checksum
	val = EndiannessHandler::toNetworkEndian(m_checksum);
	memcpy(ptr, &val, sizeof(byte2));
}

void UDP::deserializeArr(const byte* ptr)
{
	// Will be implemented in the future
}

void UDP::serialize(std::vector<byte>& buffer) const
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);

	// Add ethernet data to the array
	buffer.resize(buffer.size() + UDP::Size);
	serializeArr(buffer.data());

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, UDP::Size);
	}
}

size_t UDP::getSize() const
{
	return UDP::Size;
}

void UDP::serialize(std::vector<byte>& buffer, const size_t offset) const
{
	// Add ethernet data to the array
	buffer.resize(buffer.size() + UDP::Size);
	serializeArr(buffer.data() + offset);

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, offset + UDP::Size);
	}
}
