#include "ClassifiedPacket.h"

ClassifiedPacket::ClassifiedPacket(const IMMutablePacket rawPacket)
	: m_rawPacket(rawPacket), m_protocolsPtr(), m_protocolStorage(), m_rawLastIndex(0)
{

}

ClassifiedPacket::ClassifiedPacket(const byte* data, const byte4 length, timeval timestamp)
	: m_rawPacket(data, length, timestamp), m_rawLastIndex(0), m_protocolsPtr(), m_protocolStorage()
{}
