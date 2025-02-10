#include "MutablePacket.h"

MutablePacket::MutablePacket() :
    Packet(), m_protocolCount(0), m_protocolObjectSize(0)
{}

void MutablePacket::compile()
{
	prePass();

	postPass();
}

byte* MutablePacket::getPtrAtProtocol(size_t index)
{
	return m_buffer + m_protocolEntries[index].m_offset;
}

void MutablePacket::shiftFromOffset(size_t index, size_t amount)
{
	if (index >= m_curSize)
	{
		throw std::exception("Couldn't shift, index >= curSize");
	}
	
	if (amount + m_curSize > MAX_PACKET_SIZE)
	{
		throw std::exception("Couldn't shift, shifting would cause an overflow");
	}

	size_t shiftSize = m_curSize - index;

	// Will copy all bytes to the next `amount` bytes. (using memmove will do it backwards)
	std::memmove(&m_buffer[index + amount], &m_buffer[index], shiftSize);

	m_curSize += amount;
}

void MutablePacket::insertBytes(byte value, size_t amount)
{
	if (amount == 0)
	{
		return;
	}

	std::size_t offset = m_curSize;
	
	std::memcpy(m_buffer + offset, m_buffer + offset + amount - 1, amount);

	m_curSize += amount;
}

size_t MutablePacket::protocolCount() const
{
	return m_protocolCount;
}

void MutablePacket::prePass()
{
	for (size_t i = 0; i < m_protocolCount; i++)
	{
		size_t offset = m_protocolEntries[i].m_offset;
		Protocol& proto = *reinterpret_cast<Protocol*>(m_protocolObjects.data() + i * sizeof(Protocol));
		proto.encodePre(*this, i);
	}
}

void MutablePacket::postPass()
{
	for (signed long i = m_protocolCount - 1; i >= 0; i--)
	{
		size_t offset = m_protocolEntries[i].m_offset;
		Protocol& proto = *reinterpret_cast<Protocol*>(m_protocolObjects.data() + i * sizeof(Protocol));
		proto.encodePre(*this, i);
	}
}

