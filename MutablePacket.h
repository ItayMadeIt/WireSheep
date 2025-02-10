#pragma once

#include "Packet.h"
#include <functional>
#include <array>

constexpr size_t MAX_PROTOCOL_OBJECTS_SIZE = 128;

class MutablePacket;

struct MutableProtocolEntry
{
	size_t m_offset;
};

constexpr int PROTOCOLS_BUFFER_SIZE = 128;

class MutablePacket : public Packet
{
public:
	MutablePacket();

	template<typename Protocol, typename... Args>
	Protocol& attach(Args&&... args);

	void compile();

	byte* getPtrAtProtocol(size_t index);

	void shiftFromOffset(size_t index, size_t amount);
	void insertBytes(byte value, size_t amount);

	size_t protocolCount() const;

private:
	void prePass();
	void postPass();

private:
	std::array<MutableProtocolEntry, MAX_PROTOCOLS> m_protocolEntries;
	size_t m_protocolCount;

	std::array<byte, PROTOCOLS_BUFFER_SIZE> m_protocolObjects;
	size_t m_protocolObjectSize;
};

template<typename Protocol, typename ...Args>
inline Protocol& MutablePacket::attach(Args&&... args)
{
	if (m_curSize + Protocol::BASE_SIZE > MAX_PACKET_SIZE)
	{
		throw std::exception("Packet size exceeded!");
	}
	if (m_protocolCount >= MAX_PROTOCOLS)
	{
		throw std::exception("Exceeded protocols amount!");
	}

	size_t protocolOffset = m_curSize;
	
	Protocol* protocolObj = new (m_protocolObjects.data() + m_protocolObjectSize)
		Protocol(m_buffer + protocolOffset, std::forward<Args>(args)...);
	
	m_curSize += protocolObj->getSize();

	m_protocolObjectSize += sizeof(Protocol);

	m_protocolEntries[m_protocolCount++] = {
		protocolOffset
	};

	return *protocolObj;
}
