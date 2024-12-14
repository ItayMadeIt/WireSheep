#include "Protocol.h"

Protocol::Protocol(ProtocolTypes protocol, size_t size) 
	: m_protocol(protocol), m_size(size)
{ }

ProtocolTypes Protocol::getProtocol()
{
	return m_protocol;
}