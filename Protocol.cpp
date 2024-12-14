#include "Protocol.h"

Protocol::Protocol(const ProtocolTypes protocol, const size_t size, std::unique_ptr<Protocol> nextProtocol)
	: m_protocolType(protocol), m_size(size), m_nextProtocol(std::move(nextProtocol))
{ }

ProtocolTypes Protocol::getProtocol() const
{
	return m_protocolType;
}

size_t Protocol::getLayersSize() const
{
	size_t size = getSize();
	if (m_nextProtocol)
	{
		size += m_nextProtocol->getLayersSize();
	}
	return size;
}
