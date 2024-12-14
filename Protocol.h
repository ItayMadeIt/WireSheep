#pragma once

#include <memory>
#include "WireDefs.h"

class Protocol
{
public:
	Protocol(ProtocolTypes protocol, size_t size);
	virtual ~Protocol() = default;
	
	/// <summary>
	/// Serialize protocol data from the class into the array (ptr)
	/// </summary>
	/// <param name="ptr">data start position</param>
	virtual void serialize(byte* ptr) const = 0;

	/// <summary>
	/// Deserialize protocol data from the array (ptr) into the class.
	/// This does not modify the original array.
	/// </summary>
	/// <param name="ptr">data start position</param>
	virtual void deserialize(const byte* ptr) = 0;

	ProtocolTypes getProtocol();
	virtual size_t getSize() const = 0;

private:
	ProtocolTypes m_protocol;
	size_t m_size;
};

