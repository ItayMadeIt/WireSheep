#pragma once

#include "Packet.h"
#include <functional>
#include <array>

class MutablePacket;

struct MutableProtocolEntry
{
	size_t m_dataOffset;
	size_t m_objectOffset;
};

constexpr size_t PROTOCOLS_BUFFER_SIZE = 256;

class MutablePacket : public Packet
{
public:
	MutablePacket();

	template<typename ProtocolClass, typename... Args>
	ProtocolClass& attach(Args&&... args);


	template<typename ProtocolClass>
	ProtocolClass& get(size_t index);

	template<typename ProtocolClass>
	ProtocolClass* getPtr(size_t index);

	void compile();

	byte* getPtrAtProtocol(size_t index);

	void shiftFromOffset(size_t index, size_t amount);
	void shiftFromAddr(byte* addr, size_t amount);
	void shrinkFromOffset(size_t index, size_t amount);
	void shrinkFromAddr(byte* addr, size_t amount);
	void replaceFromOffset(size_t index, size_t deleteAmount, const byte* dataPtr, size_t dataAmount);
	void replaceFromAddr(byte* addr, size_t deleteAmount, const byte* dataPtr, size_t dataAmount);
	void insertBytes(const byte value, size_t amount);
	void insertByteArr(const byte* byteArr, size_t amount);

	size_t protocolCount() const;

public:
	std::array<MutableProtocolEntry, MAX_PROTOCOLS> m_protocolEntries;
	size_t m_protocolCount;

	std::array<byte, PROTOCOLS_BUFFER_SIZE> m_protocolObjects;

	/// <summary>
	/// Offset from the start of the buffer where the new protocol should be placed
	/// </summary>
	size_t m_protocolEndOffset;
private:
	void prePass();
	void postPass();
};

template<typename ProtocolClass, typename ...Args>
inline ProtocolClass& MutablePacket::attach(Args&&... args)
{
	if (m_curSize + ProtocolClass::BASE_SIZE > MAX_PACKET_SIZE)
	{
		throw std::exception("Packet size exceeded!");
	}
	if (m_protocolCount >= MAX_PROTOCOLS)
	{
		throw std::exception("Exceeded protocols amount!");
	}

	size_t protocolDataOffset = m_curSize;
	size_t protocolClassOffset = m_protocolEndOffset;
	
	// Instantiate protocol into the protocols buffer
	size_t alignment = alignof(Protocol);
	void* alignedPtr = static_cast<void*>(m_protocolObjects.data() + protocolClassOffset);
	size_t remainingSize = PROTOCOLS_BUFFER_SIZE - protocolClassOffset;
	if (!std::align(alignment, sizeof(ProtocolClass), alignedPtr, remainingSize))
	{
		throw std::exception("Not enough space for alignment!");
	}

	// Add base size of protocol to buffer size
	// If more specifciation is needed, modify Packet using helper functions.
	m_curSize += ProtocolClass::BASE_SIZE;

	ProtocolClass* protocolObj = new (alignedPtr) ProtocolClass(m_buffer + protocolDataOffset, std::forward<Args>(args)...);

	// Modify to the alligned offset value
	protocolClassOffset = static_cast<byte*>(alignedPtr) - m_protocolObjects.data();

	// Add the alligned size
	m_protocolEndOffset += protocolClassOffset + sizeof(ProtocolClass);

	// Add to the protocol entires
	m_protocolEntries[m_protocolCount++] = {
		protocolDataOffset,
		protocolClassOffset
	};

	return *protocolObj;
}

template<typename ProtocolClass>
inline ProtocolClass& MutablePacket::get(size_t index)
{
	if (m_protocolCount <= index)
	{
		throw std::exception("Index is invalid.");
	}

	return *reinterpret_cast<Protocol*>(
		static_cast<void*>(&m_protocolObjects[m_protocolEntries[index].m_objectOffset])
	);
}

template<typename ProtocolClass>
inline ProtocolClass* MutablePacket::getPtr(size_t index)
{
	if (m_protocolCount <= index)
	{
		throw std::exception("Index is invalid.");
	}

	return dynamic_cast<ProtocolClass*>(reinterpret_cast<Protocol*>(
		static_cast<void*>(&m_protocolObjects[m_protocolEntries[index].m_objectOffset])
	));
}
