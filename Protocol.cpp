#include "Protocol.h"

Protocol::Protocol(ProtocolTypes protocol) : m_protocol(protocol)
{ }

ProtocolTypes Protocol::getProtocol()
{
	return m_protocol;
}
