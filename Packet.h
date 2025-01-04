#pragma once

#include "Protocol.h"

class Packet
{
public:
	
	Packet(std::unique_ptr<Protocol> firstLayer);

	Protocol* getFirstLayer() const;

	Protocol* operator[](size_t index);

	Protocol* operator[](AllProtocols protocolType);

	/// <summary>
	/// Turns the packet layers into a binary vector and returns
	/// a reference to it.
	/// 
	/// Automatically calculates field like checksum, length, padding etc..
	/// Also known as the safe option. If you want more control use `compileRaw()`
	/// </summary>
	/// <returns>A const reference to the compiled bytes vector</returns>
	const std::vector<byte>& compile();

	/// <summary>
	/// Turns the packet layers into a binary vector and returns
	/// a reference to it.
	/// 
	/// Uses serializeRaw (meaning it does not modify properties like
	/// checksum, length etc.. ) I.E won't enforce protocol rules if the 
	/// user didn't explicitly write the packets that way.
	/// (~advanced users feature~)
	/// </summary>
	/// <returns>A const reference to the compiled bytes vector</returns>
	const std::vector<byte>& compileRaw();

	operator const std::vector<byte>&() const ;
	operator std::vector<byte>() const ;

private:
	std::unique_ptr<Protocol> m_firstLayer;
	std::vector<byte> m_bytes;
};

