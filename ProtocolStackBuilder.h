#pragma once

#include "Protocol.h"

class ProtocolStackBuilder
{
public:
	ProtocolStackBuilder() = default;
	~ProtocolStackBuilder() = default;

	template<typename Layer, typename... Args>
	ProtocolStackBuilder& push(Args&&... args);

	std::unique_ptr<Protocol> first();

private:
	std::unique_ptr<Protocol> firstProtocol;
	Protocol* curProtocol;

};

template<typename Layer, typename ...Args>
inline ProtocolStackBuilder& ProtocolStackBuilder::push(Args && ...args)
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