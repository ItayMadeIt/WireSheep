#pragma once

#include "Protocol.h"
#include <unordered_map>

constexpr int MAX_PACKET_SIZE = 1500;
constexpr size_t MAX_PROTOCOLS = 7;

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

	// Print string to output stream
	friend std::ostream& operator<<(std::ostream& os, Packet& packet);

public:
	byte m_buffer[MAX_PACKET_SIZE];
	size_t m_curSize;
};

