#pragma once

#include "Protocol.h"
#include <unordered_map>

constexpr int MAX_PACKET_SIZE = 1526;
constexpr size_t MAX_PROTOCOLS = 7;

class Packet
{
public:
	/// <summary>
	/// Get the packet's buffer byte pointer
	/// </summary>
	/// <returns>buffer byte pointer</returns>
	virtual const byte* buffer() const = 0;

	/// <summary>
	/// Get the packet's buffer size
	/// </summary>
	/// <returns>buffer size</returns>
	virtual const byte4 size() const = 0;


	friend std::ostream& operator<<(std::ostream& os, const Packet& packet);
};

