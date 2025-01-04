#include "Ethernet.h"

Ethernet::Ethernet() : Protocol(AllProtocols::Ethernet, nullptr)
{ }

Ethernet::Ethernet(const addrMac src, const addrMac dst, const byte2 type)
	: Protocol(AllProtocols::Ethernet, nullptr), m_src(src), m_dst(dst), m_type(type)
{ }

Ethernet::Ethernet(const std::string & src, const std::string & dst, const byte2 type) 
	: Protocol(AllProtocols::Ethernet, nullptr), m_src(src), m_dst(dst), m_type(type)
{ }

Ethernet::Ethernet(std::unique_ptr<Protocol> nextProtocol) 
	: Protocol(AllProtocols::Ethernet, std::move(nextProtocol))
{ }

Ethernet::Ethernet(const addrMac src, const addrMac dst, const byte2 type, std::unique_ptr<Protocol> nextProtocol)
	: Protocol(AllProtocols::Ethernet, std::move(nextProtocol)),
		m_src(src), m_dst(dst), m_type(type)
{ }

Ethernet::Ethernet(const std::string & src, const std::string & dst, const byte2 type, std::unique_ptr<Protocol> nextProtocol)
	: Protocol(AllProtocols::Ethernet, std::move(nextProtocol)),
	m_src(src), m_dst(dst), m_type(type)
{ }

Ethernet::~Ethernet() = default;

Ethernet& Ethernet::dst(const addrMac value)
{
	m_dst = value;
	return *this;
}
addrMac Ethernet::dst() const
{
	return m_dst;
}
Ethernet& Ethernet::src(const addrMac value)
{
	m_src = value;
	return *this;

}
addrMac Ethernet::src() const
{
	return m_src;
}

Ethernet& Ethernet::type(const byte2 value)
{
	m_type = value;
	return *this;
}

Ethernet& Ethernet::type(const ProtocolTypes value)
{
	m_type = (byte2)value;
	return *this;
}

byte2 Ethernet::type() const
{
	return m_type;
}

void Ethernet::serializeArr(byte* ptr) const
{
	memcpy(ptr, &m_dst , ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	memcpy(ptr, &m_src , ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	byte2 netType = EndiannessHandler::toNetworkEndian(m_type);
	memcpy(ptr, &netType, ETHER_LEN_TYPE);
}

void Ethernet::deserializeArr(const byte* ptr)
{
	memcpy(&m_dst, ptr, ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	memcpy(&m_src, ptr, ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	memcpy(&m_type, ptr, ETHER_LEN_TYPE);
	m_type = EndiannessHandler::fromNetworkEndian(m_type);
}

size_t Ethernet::getSize() const
{
	return Ethernet::Size;
}

void Ethernet::serialize(std::vector<byte>& buffer) 
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);

	// Add ethernet data to the array
	buffer.resize(buffer.size() + Ethernet::Size);
	serializeArr(buffer.data());

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, Ethernet::Size);
	}

	// Ensure there are at minimum 60 bytes (12 for both MACs, 2 for the length/type and at minimum 42 bytes of data) 
	if (buffer.size() < Ethernet::MinimumSize)
	{
		buffer.resize(Ethernet::MinimumSize);
	}
}

void Ethernet::serialize(std::vector<byte>& buffer, const size_t offset) 
{
	// Add ethernet data to the array
	buffer.resize(buffer.size() + Ethernet::Size);
	serializeArr(buffer.data() + offset);

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, offset + Ethernet::Size);
	}
}

void Ethernet::serializeRaw(std::vector<byte>& buffer) const
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);

	// Add ethernet data to the array
	buffer.resize(buffer.size() + Ethernet::Size);
	serializeArr(buffer.data());

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serializeRaw(buffer, Ethernet::Size);
	}
}

void Ethernet::serializeRaw(std::vector<byte>& buffer, const size_t offset) const
{
	// Add ethernet data to the array
	buffer.resize(buffer.size() + Ethernet::Size);
	serializeArr(buffer.data() + offset);

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serializeRaw(buffer, offset + Ethernet::Size);
	}
}

std::ostream& operator<<(std::ostream& os, const Ethernet& ether)
{
	os << "[Ethernet]" << std::endl;

	// Output source and destination
	os << "Src : " << ether.m_src  << std::endl;
	os << "Dst : " << ether.m_dst  << std::endl;

	// Output type as dec and hex
	os << "Type: " << std::setfill(' ') << std::setw(5) << std::dec << ether.m_type;
	os << " | 0x" << std::setfill('0') << std::setw(4) << std::hex << ether.m_type << std::endl << std::dec;

	return os;
}
