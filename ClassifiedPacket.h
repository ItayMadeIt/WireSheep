#pragma once

#include "StaticVector.hpp"
#include "WireDefs.h"
#include "IMMutablePacket.h"

class ClassifiedPacket
{
public:
	constexpr static const byte4 MAX_PROTOCOLS_AMOUNT = 256;

	ClassifiedPacket(const IMMutablePacket rawPacket);
	ClassifiedPacket(const byte* data, const byte4 length, struct timeval timestamp);
	ClassifiedPacket(const ClassifiedPacket& other) = default;

	template<typename T>
	T& add();

	template<typename T>
	T& get(const byte4 index);

	void pop();

private:
	StaticVector<Protocol*, MAX_PROTOCOLS * sizeof(Protocol*)> m_protocolsPtr;
	IMMutablePacket m_rawPacket;
	
	/// Saves the last index that is documented by a protocol
	byte4 m_rawLastIndex;

	StaticVector<byte, MAX_PROTOCOLS_AMOUNT> m_protocolStorage;
};

template<typename T>
inline T& ClassifiedPacket::add()
{
	static_assert(std::is_base_of<Protocol, T>::value, "T must inherit from Protocol");

	byte* ptr = m_protocolStorage.begin() + m_protocolStorage.size();
	m_protocolsPtr.push_back(reinterpret_cast<const  Protocol*>(ptr));

	Protocol& protocol = new (ptr) T(m_rawPacket.buffer() + m_rawLastIndex);
	
	m_rawLastIndex += protocol.getSize();

	return protocol;
}

template<typename T>
inline T& ClassifiedPacket::get(const byte4 index)
{
	return *reinterpret_cast<T*>(m_protocolsPtr[index]);
}

inline void ClassifiedPacket::pop()
{
	if (m_protocolsPtr.empty())
	{
		throw std::runtime_error("Cant pop from empty list");
	}

	m_rawLastIndex -= get<Protocol>(m_protocolsPtr.count() - 1).getSize();
	m_protocolsPtr.pop_back();
}
