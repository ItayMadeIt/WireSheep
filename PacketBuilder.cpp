#include "PacketBuilder.h"

PacketBuilder::PacketBuilder() : m_protocolList(nullptr)
{
	
}

Packet PacketBuilder::buildRaw()
{
	reset();

	Packet pack = Packet(std::move(m_protocolList));

	pack.compileRaw();

	return pack;
}

Packet PacketBuilder::build()
{
	std::unique_ptr<ProtocolNode> layer = std::move(m_protocolList);

	reset();

	Packet pack = Packet(std::move(layer));
	
	pack.compile();
	
	return pack;
}

void PacketBuilder::reset()
{
	m_protocolList = nullptr;
}
