#pragma once

#include <memory>
#include <vector>
#include "WireDefs.h"

class Protocol
{
public:
	Protocol(const ProtocolTypes protocol, const size_t size, std::unique_ptr<Protocol> nextProtocol);
	virtual ~Protocol() = default;

	/// <summary>
	/// Serialize protocol data from the class into the array (ptr)
	/// </summary>
	/// <param name="ptr">data start position</param>
	virtual void serializeArr(byte* ptr) const = 0;

	/// <summary>
	/// Deserialize protocol data from the array (ptr) into the class.
	/// This does not modify the original array.
	/// </summary>
	/// <param name="ptr">data start position</param>
	virtual void deserializeArr(const byte* ptr) = 0;

	virtual void serialize   (std::vector<byte>& buffer) const = 0;

	ProtocolTypes getProtocol() const;
	virtual size_t getSize() const = 0;

	void setNextProtocol(std::unique_ptr<Protocol> next);
	Protocol* getNextProtocol();

	virtual void serialize(std::vector<byte>& buffer, const size_t offset) const = 0;

protected:
	size_t getLayersSize() const;

	std::unique_ptr<Protocol> m_nextProtocol; // Next protocol (shared list): Ether -> IPv4 -> TCP -> HTTP (example)

private:
	ProtocolTypes m_protocolType;
	size_t m_size;
};

