#pragma once

#include "Protocol.h"
#include "Packet.h"

class PacketBuilder
{
public:
	PacketBuilder() = default;
	~PacketBuilder() = default;

	template<typename Layer, typename... Args>
	PacketBuilder& push(Args&&... args);

	Packet build();
	void reset();

private:
	std::unique_ptr<Protocol> firstProtocol;
	Protocol* curProtocol;

};

template<typename Layer, typename ...Args>
inline PacketBuilder& PacketBuilder::push(Args && ...args)
{
	// Create protocol instance
	std::unique_ptr<Layer> newProtocol =
		std::make_unique<Layer>(std::forward<Args>(args)...);

	// Set next protocol 
	if (curProtocol)
	{
		curProtocol->setNextProtocol(std::move(newProtocol));
		curProtocol = curProtocol->getNextProtocol();
	}
	else
	{
		firstProtocol = std::move(newProtocol);
		curProtocol = firstProtocol.get();
	}

	return *this;
}