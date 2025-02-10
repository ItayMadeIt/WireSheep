#include "Protocol.h"

Protocol::Protocol(const AllProtocols protocol)
	: m_protocolType(protocol)
{
	m_includesChecksum = false; // will be removed
}


Protocol::Protocol(const Protocol& other) = default;

Protocol::Protocol(Protocol&& other) = default;

// Will be removed | Invalid implementation
void Protocol::calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol)
{
	throw std::exception("Cannot calculate checksum for this protocol.");
}

// Will be removed
void Protocol::encodeLayerPre(std::vector<byte>& buffer, const size_t offset) {}

// Will be removed
void Protocol::encodeLayerPost   (std::vector<byte>& buffer, const size_t offset) {};

// Will be removed
void Protocol::encodeLayerPostRaw(std::vector<byte>& buffer, const size_t offset) const {}

// Will be removed
bool Protocol::includesChecksum() const
{
	return m_includesChecksum;
}


void Protocol::encodePre(MutablePacket& packet, size_t protocolIndex)
{
	// Empty implementation
}
void Protocol::encodePost(MutablePacket& packet, size_t protocolIndex)
{
	// Empty implementation
}

AllProtocols Protocol::getProtocol() const
{
	return m_protocolType;
}
