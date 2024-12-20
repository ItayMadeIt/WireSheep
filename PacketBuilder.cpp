#include "PacketBuilder.h"

Packet PacketBuilder::buildRaw()
{
	std::unique_ptr<Protocol> layer = std::move(firstProtocol);

	reset();

	Packet pack = Packet(std::move(layer));

	pack.compileRaw();

	return pack;
}

Packet PacketBuilder::build()
{
	std::unique_ptr<Protocol> layer = std::move(firstProtocol);

	reset();

	Packet pack = Packet(std::move(layer));
	
	pack.compile();
	
	return pack;
}

void PacketBuilder::reset()
{
	firstProtocol = nullptr;
	curProtocol = nullptr;
}
