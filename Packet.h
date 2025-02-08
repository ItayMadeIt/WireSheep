#pragma once

#include "Protocol.h"
#include "ProtocolNode.h"
#include <unordered_map>

constexpr int MAX_PACKET_SIZE = 1500;

class Packet
{
public:
	Packet();

	/// <summary>
	/// Get the packet's buffer byte pointer
	/// </summary>
	/// <returns>buffer byte pointer</returns>
	const byte* buffer() const;

	/// <summary>
	/// Get the packet's buffer size
	/// </summary>
	/// <returns>buffer size</returns>
	const size_t size() const;

protected:
	byte m_buffer[MAX_PACKET_SIZE];
	size_t m_curSize;
};

