#include "UDP.h"

UDP::UDP() 
	: Protocol(AllProtocols::UDP),
	m_src(0), m_dst(0), m_length(8), m_checksum(0)
{}

UDP::UDP(const byte2 src, const byte2 dst)
	: Protocol(AllProtocols::UDP),
	m_src(src), m_dst(dst), m_length(8), m_checksum(0)
{}

void UDP::calcChecksum()
{
	std::vector<byte> curData(getSize());

	writeToBuffer(curData.data());

	byte4 checksumVal = 0;

	byte2* iter = (byte2*)(curData.data());
	byte2* end = (byte2*)(curData.data() + curData.size());
	for (; iter < end; iter++)
	{
		checksumVal += EndiannessHandler::fromNetworkEndian(*iter);
	}
	byte2 checksumCarry = (checksumVal & 0xFFFF0000) >> 16;
	m_checksum = ~((checksumVal & 0xFFFF) + checksumCarry);
}


void UDP::writeToBuffer(byte * ptr) const
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

void UDP::readFromBuffer(const byte* ptr)
{
	// Will be implemented in the future
}

void UDP::encodeLayer(std::vector<byte>& buffer)
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);
	
	// Get the amount of bytes we have left to input
	m_length = buffer.capacity() - buffer.size();

	// Add ethernet data to the array
	buffer.resize(buffer.size() + UDP::Size);
	writeToBuffer(buffer.data());

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->encodeLayerRaw(buffer, UDP::Size);
	}
}

void UDP::encodeLayerRaw(std::vector<byte>& buffer) const
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);

	// Add ethernet data to the array
	buffer.resize(buffer.size() + UDP::Size);
	writeToBuffer(buffer.data());

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->encodeLayerRaw(buffer, UDP::Size);
	}
}

void UDP::encodeLayer(std::vector<byte>& buffer, const size_t offset)
{
	// Get the amount of bytes we have left to input
	m_length = buffer.capacity() - buffer.size();

	// Add UDP data to the array
	buffer.resize(buffer.size() + UDP::Size);
	writeToBuffer(buffer.data() + offset);

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->encodeLayer(buffer, offset + UDP::Size);
	}
}

void UDP::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
	// Add UDP data to the array
	buffer.resize(buffer.size() + UDP::Size);
	writeToBuffer(buffer.data() + offset);

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->encodeLayer(buffer, offset + UDP::Size);
	}
}


size_t UDP::getSize() const
{
	return UDP::Size;
}
