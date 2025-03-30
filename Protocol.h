#pragma once

#include <memory>
#include <vector>
#include "WireDefs.h"

// forward decleration 
class MutablePacket;

class Protocol
{
public:
	Protocol();
	Protocol(const Protocol& other);
	virtual ~Protocol() = default;
	Protocol(Protocol&& other);

	virtual void encodePre(MutablePacket& packet, const size_t protocolIndex);
	virtual void encodePost(MutablePacket& packet, const  size_t protocolIndex);

	virtual size_t getSize() const = 0;

	virtual void addr(byte* address) = 0;
	virtual byte* addr() const = 0;
	
	virtual ProvidedProtocols protType() const = 0;
};
