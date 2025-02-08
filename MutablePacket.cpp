#include "MutablePacket.h"

MutablePacket::MutablePacket() :
    Packet()
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

void MutablePacket::prePass()
{
	for (size_t i = 0; i < m_protocolCount; i++)
	{
		m_protocolEntries[i].m_prePass(*this, i);
	}
}

void MutablePacket::postPass()
{
	for (signed long i = m_protocolCount - 1; i >= 0; i--)
	{
		m_protocolEntries[i].m_postPass(*this, i);
	}
}

