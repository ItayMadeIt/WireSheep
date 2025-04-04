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

	/// <summary>
	/// Syncs the fields of the protocol and it's attachment
	/// It will return true if it was successful, false otherwise.
	/// If it wasn't successful then the protocol's fields may be invalid.
	/// </summary>
	/// <param name="remainingSize">Remaining size in the packet</param>
	/// <returns>Is successful</returns>
	virtual bool syncFields(byte4 remainingSize);
	
	virtual ProvidedProtocols protType() const = 0;
};
