#include "Protocol.h"

Protocol::Protocol(const ProtocolTypes protocol, std::unique_ptr<Protocol> nextProtocol)
	: m_protocolType(protocol), m_nextProtocol(std::move(nextProtocol))
{ }

Protocol::Protocol(Protocol&& other) = default;

ProtocolTypes Protocol::getProtocol() const
{
	return m_protocolType;
}

void Protocol::setNextProtocol(std::unique_ptr<Protocol> next)
{
	m_nextProtocol = std::move(next);
}

Protocol* Protocol::getNextProtocol()
{
	return m_nextProtocol.get();
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
