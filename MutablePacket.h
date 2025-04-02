#pragma once

#include "Packet.h"
#include <functional>
#include <array>

struct MutableProtocolEntry
{
	byte4 dataOffset;
	byte4 objectOffset;
};

constexpr byte4 PROTOCOLS_BUFFER_SIZE = 256;

class MutablePacket : public Packet
{
public:
	MutablePacket();

	template<typename ProtocolClass, typename... Args>
	ProtocolClass& attach(Args&&... args);

	byte* getBuffer();
	byte4 getSize();

	template<typename ProtocolClass>
	ProtocolClass& get(byte4 index);

	template<typename ProtocolClass>
	ProtocolClass* getPtr(byte4 index);

	void compile();

	byte* getPtrAtProtocol(byte4 index);

	void shiftFromOffset(byte4 index, byte4 amount);
	void shiftFromAddr(byte* addr, byte4 amount);
	void shrinkFromOffset(byte4 index, byte4 amount);
	void shrinkFromAddr(byte* addr, byte4 amount);
	void replaceFromOffset(byte4 index, byte4 deleteAmount, const byte* dataPtr, byte4 dataAmount);
	void replaceFromAddr(byte* addr, byte4 deleteAmount, const byte* dataPtr, byte4 dataAmount);
	void insertBytes(const byte value, byte4 amount);
	void insertByteArr(const byte* byteArr, byte4 amount);

	byte4 protocolCount() const;

protected:
	byte m_buffer[MAX_PACKET_SIZE];
	byte4 m_size;

	std::array<MutableProtocolEntry, MAX_PROTOCOLS> m_protocolEntries;
	byte4 m_protocolCount;

	std::array<byte, PROTOCOLS_BUFFER_SIZE> m_protocolObjects;

	/// <summary>
	/// Offset from the start of the buffer where the new protocol should be placed
	/// </summary>
	byte4 m_protocolEndOffset;

protected:
	void prePass();
	void postPass();

	// Inherited via Packet
	virtual const byte* buffer() const override;
	virtual const byte4 size() const override;
};

template<typename ProtocolClass, typename ...Args>
inline ProtocolClass& MutablePacket::attach(Args&&... args)
{
	if (m_size + ProtocolClass::BASE_SIZE > MAX_PACKET_SIZE)
	{
		throw std::exception("Packet size exceeded!");
	}
	if (m_protocolCount >= MAX_PROTOCOLS)
	{
		throw std::exception("Exceeded protocols amount!");
	}

	byte4 protocolDataOffset = m_size;
	byte4 protocolClassOffset = m_protocolEndOffset;
	
	// Instantiate protocol into the protocols buffer
	byte4 alignment = alignof(Protocol);
	void* alignedPtr = static_cast<void*>(m_protocolObjects.data() + protocolClassOffset);
	byte4 remainingSize = PROTOCOLS_BUFFER_SIZE - protocolClassOffset;
	if (!std::align(alignment, sizeof(ProtocolClass), alignedPtr, remainingSize))
	{
		throw std::exception("Not enough space for alignment!");
	}

	// Add base size of protocol to buffer size
	// If more specifciation is needed, modify Packet using helper functions.
	m_size += ProtocolClass::BASE_SIZE;

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
inline ProtocolClass& MutablePacket::get(byte4 index)
{
	if (m_protocolCount <= index)
	{
		throw std::exception("Index is invalid.");
	}

	return *reinterpret_cast<Protocol*>(
		static_cast<void*>(&m_protocolObjects[m_protocolEntries[index].objectOffset])
	);
}

template<typename ProtocolClass>
inline ProtocolClass* MutablePacket::getPtr(byte4 index)
{
	if (m_protocolCount <= index)
	{
		throw std::exception("Index is invalid.");
	}

	return dynamic_cast<ProtocolClass*>(reinterpret_cast<Protocol*>(
		static_cast<void*>(&m_protocolObjects[m_protocolEntries[index].objectOffset])
	));
}
