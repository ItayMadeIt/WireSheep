#include "ProtocolStackBuilder.h"

std::unique_ptr<Protocol> ProtocolStackBuilder::first()
{
	std::unique_ptr<Protocol> result = std::move(firstProtocol);

	firstProtocol = nullptr;
	curProtocol = nullptr;

	return result;
}