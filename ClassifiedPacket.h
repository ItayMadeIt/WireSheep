#pragma once

#include "StaticVector.hpp"
#include "WireDefs.h"
#include "IMMutablePacket.h"

class ClassifiedPacket
{
public:
	constexpr static const byte4 MAX_PROTOCOLS_AMOUNT = 256;

	ClassifiedPacket(const IMMutablePacket rawPacket);
	ClassifiedPacket(byte* data, const byte4 length, struct timeval timestamp);
	ClassifiedPacket(const ClassifiedPacket& other) = default;

	template<typename T>
	T& add();

	template<typename T>
	T& get(const byte4 index);

	template<typename T>
	T& get();

	template<typename T>
	bool tryGet(T*& output);

	bool contains(ProvidedProtocols protocol);
	byte4 find(ProvidedProtocols protocol);

	void pop();

	byte4 protocolsCount();

	IMMutablePacket& getRaw();

	bool isFull();

	const byte* endPtr();
	
	byte4 unidentifiedPacketSize() const;

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

	// Add to protocol storage the size
	byte* ptr = m_protocolStorage.end();
	m_protocolStorage.resize(m_protocolStorage.size() + sizeof(T));

	// Add ptr to the list
	m_protocolsPtr.push_back(reinterpret_cast<Protocol*>(ptr));

	// Get protocol ptr
	Protocol* protocol = new (ptr) T(m_rawPacket.buffer() + m_rawLastIndex);
	
	m_rawLastIndex += protocol->getSize();

	return *reinterpret_cast<T*>(protocol);
}

template<typename T>
inline T& ClassifiedPacket::get(const byte4 index)
{
	return *reinterpret_cast<T*>(m_protocolsPtr[index]);
}

template<typename T>
inline T& ClassifiedPacket::get()
{
	static_assert(std::is_base_of<Protocol, T>::value, "T must inherit from Protocol");

	byte4 protocolIndex = find(T::ID);

	return *static_cast<T*>(m_protocolsPtr[protocolIndex]);
}

template<typename T>
inline bool ClassifiedPacket::tryGet(T*& output)
{
	static_assert(std::is_base_of<Protocol, T>::value, "T must inherit from Protocol");

	byte4 protocolIndex = find(T::ID);

	if (protocolIndex == -1)
	{
		output = nullptr;
		return false;
	}

	output = static_cast<T*>(m_protocolsPtr[protocolIndex]);
	return true;
}

inline bool ClassifiedPacket::contains(ProvidedProtocols protocol)
{
	for (byte4 i = 0; i < m_protocolsPtr.count(); i++)
	{
		ProvidedProtocols curProtocol = m_protocolsPtr[i]->protType();
		if (curProtocol == protocol)
		{
			return true;
		}
	}
	return false;
}

inline byte4 ClassifiedPacket::find(ProvidedProtocols protocol)
{
	for (byte4 i = 0; i < m_protocolsPtr.count(); i++)
	{
		if (m_protocolsPtr[i]->protType() == protocol)
		{
			return i;
		}
	}

	return -1;
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

inline byte4 ClassifiedPacket::protocolsCount()
{
	return m_protocolsPtr.count();
}

inline IMMutablePacket& ClassifiedPacket::getRaw()
{
	return m_rawPacket;
}

inline bool ClassifiedPacket::isFull()
{
	return m_rawLastIndex == m_rawPacket.size();
}

inline const byte* ClassifiedPacket::endPtr()
{
	return m_rawPacket.buffer() + m_rawLastIndex;
}

inline byte4 ClassifiedPacket::unidentifiedPacketSize() const
{
	return m_rawPacket.size() - m_rawLastIndex;
}
