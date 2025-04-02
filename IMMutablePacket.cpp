#include "IMMutablePacket.h"

IMMutablePacket::IMMutablePacket(const byte* data, const byte4 length)
	: m_timestamp({ 0, 0 }), m_size(length), m_buffer(data)
{}

IMMutablePacket::IMMutablePacket(const byte* data, const byte4 length, timeval timestamp)
	: m_timestamp(timestamp), m_size(length), m_buffer(data)
{
}

const byte* IMMutablePacket::buffer() const
{
	return m_buffer;
}

const byte4 IMMutablePacket::size() const
{
	return m_size;
}
