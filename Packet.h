#pragma once

#include "Protocol.h"
#include "ProtocolNode.h"
#include <unordered_map>

class Packet
{
public:
	Packet(std::unique_ptr<ProtocolNode> firstLayer);

	Protocol* operator[](const size_t index);

	Protocol* operator[](const AllProtocols protocolType);

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
	std::unique_ptr<ProtocolNode> m_head; // first layer
	ProtocolNode* m_tail; // last layer 

	std::unordered_map<AllProtocols, short> m_protocolsAmount;

	std::vector<byte> m_buffer;
};

