#include "Protocol.h"

Protocol::Protocol(const AllProtocols protocol)
	: m_protocolType(protocol)
{
	switch (m_protocolType)
	{
	case AllProtocols::IPv4:
		m_includesChecksum = true;
		break;
	case AllProtocols::IPv6:
		m_includesChecksum = true;
		break;
	case AllProtocols::TCP:
		m_includesChecksum = true;
		break;
	default:
		m_includesChecksum = false;
		break;
	}
}

Protocol::Protocol(const Protocol& other) = default;

Protocol::Protocol(Protocol&& other) = default;

// Invalid implementation
void Protocol::calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol)
{
	throw std::exception("Cannot calculate checksum for this protocol.");
}

// Will do nothing unless overridden
void Protocol::encodeLayerPost   (std::vector<byte>& buffer, const size_t offset) {};

// Will do nothing unless overridden
void Protocol::encodeLayerPostRaw(std::vector<byte>& buffer, const size_t offset) const {};

AllProtocols Protocol::getProtocol() const
{
	return m_protocolType;
}

bool Protocol::includesChecksum() const
{
	return m_includesChecksum;
}
