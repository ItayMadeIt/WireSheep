#pragma once

#include "Protocol.h"

class Packet
{
public:
	
	Packet(std::unique_ptr<Protocol> firstLayer);

	Protocol* getFirstLayer() const;

	Protocol* operator[](size_t index);

	Protocol* operator[](ProtocolTypes protocolType);

	/// <summary>
	/// Turns the packet layers into a binary vector and returns
	/// a reference to it
	/// </summary>
	/// <returns>A const reference to the compiled bytes vector</returns>
	const std::vector<byte>& compile();

	operator const std::vector<byte>&() const ;
	operator std::vector<byte>() const ;

private:
	std::unique_ptr<Protocol> m_firstLayer;
	std::vector<byte> m_bytes;
};

