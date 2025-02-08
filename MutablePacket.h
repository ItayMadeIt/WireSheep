#pragma once

#include "Packet.h"
#include <functional>
#include <array>

class MutablePacket;

struct MutableProtocolEntry
{
	size_t m_offset;

	std::function<void(MutablePacket&, size_t)> m_prePass;
	std::function<void(MutablePacket&, size_t)> m_postPass;
};

constexpr size_t MAX_PROTOCOLS = 7;

class MutablePacket : public Packet
{
public:
	MutablePacket();

	template<typename Protocol>
	Protocol attach();

	void compile();

	byte* getPtrAtProtocol(size_t index);

private:
	void prePass();
	void postPass();

private:
	std::array<MutableProtocolEntry, MAX_PROTOCOLS> m_protocolEntries;
	size_t m_protocolCount;
};

template<typename Protocol>
inline Protocol MutablePacket::attach()
{
	if (m_curSize + Protocol::BaseSize > MAX_PACKET_SIZE)
	{
		throw std::exception("Packet size exceeded!");
	}
	if (m_protocolCount >= MAX_PROTOCOLS)
	{
		throw std::exception("Exceeded protocols amount!");
	}

	size_t protocolOffset = m_curSize;
	Protocol protocol(m_buffer + m_curSize);
	m_curSize += protocol.getSize();

	protocol[m_protocolCount++] = {
		protocolOffset,
		Protocol::prePass,
		Protocol::prePost
	};
}