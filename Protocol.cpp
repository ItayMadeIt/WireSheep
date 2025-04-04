#include "Protocol.h"

Protocol::Protocol()
{
}

Protocol::Protocol(const Protocol& other) = default;

Protocol::Protocol(Protocol&& other) = default;

void Protocol::encodePre(MutablePacket& packet, size_t protocolIndex)
{
	// Empty implementation
}
void Protocol::encodePost(MutablePacket& packet, size_t protocolIndex)
{
	// Empty implementation
}

bool Protocol::syncFields(byte4 remainingSize)
{
	return true;
}