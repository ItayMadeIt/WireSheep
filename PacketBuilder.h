#pragma once

#include <type_traits>
#include "Protocol.h"
#include "Packet.h"

class PacketBuilder
{
public:
	PacketBuilder() = default;
	~PacketBuilder() = default;

	template<typename Layer, typename... Args>
	PacketBuilder& push(Args&&... args);
	
	template<typename Layer>
	PacketBuilder& push(const Layer& layer);

	template<typename Layer>
	PacketBuilder& operator<<(const Layer& layer);


	/// <summary>
	/// Builds the packet by turning the protocol linked list
	/// into a byte array and then into a packet.
	/// 
	/// This build doesnt modify any properties like length, checksum and other properties.
	/// Everything depends on the user who created each layer, for a function that calculates
	/// properties that depend on other layers use `build()`
	/// </summary>
	/// <returns>A new packet based on the protocols</returns>
	Packet buildRaw();

	/// <summary>
	/// Builds the packet by turning the protocol linked list
	/// into a byte array and then into a packet.
	/// 
	/// This build modifies properties like length, checksum and other properties
	/// that depend on the other protocols, for a raw option use `buildRaw()`.
	/// </summary>
	/// <returns>A new packet based on the protocols</returns>
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

template<typename Layer>
PacketBuilder& PacketBuilder::push(const Layer& layer)
{
	static_assert(std::is_copy_constructible<Layer>::value, 
		"Pushed layer must be copy constructible!");

	// Create protocol instance
	std::unique_ptr<Layer> newProtocol = std::make_unique<Layer>(layer);

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

template<typename Layer>
inline PacketBuilder& PacketBuilder::operator<<(const Layer& layer)
{
	push<Layer>(layer);
	return *this;
}
