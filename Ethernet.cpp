#include "Ethernet.h"

Ethernet::Ethernet() : Protocol(ProtocolTypes::Ethernet, Ethernet::Size, nullptr)
{ }

Ethernet::Ethernet(const addrMac srcAddr, const addrMac dstAddr, const byte2 type)
	: Protocol(ProtocolTypes::Ethernet, Ethernet::Size, nullptr), m_src(srcAddr), m_dst(dstAddr), m_type(type)
{ }

Ethernet::Ethernet(std::unique_ptr<Protocol> nextProtocol) 
	: Protocol(ProtocolTypes::Ethernet, Ethernet::Size, std::move(nextProtocol))
{ }

Ethernet::Ethernet(const addrMac srcAddr, const addrMac dstAddr, const byte2 type, std::unique_ptr<Protocol> nextProtocol)
	: Protocol(ProtocolTypes::Ethernet, Ethernet::Size, std::move(nextProtocol)),
		m_src(srcAddr), m_dst(dstAddr), m_type(type)
{ }

Ethernet::~Ethernet() = default;

void Ethernet::dst(const addrMac value)
{
	m_dst = value;
}
addrMac Ethernet::dst() const
{
	return m_dst;
}
void Ethernet::src(const addrMac value)
{
	m_src = value;
}
addrMac Ethernet::src() const
{
	return m_src;
}

void Ethernet::type(const byte2 value)
{
	m_type = value;
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

void Ethernet::serialize(std::vector<byte>& buffer) const
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

	// Ensure there are at minimum 60 bytes (12 for both MACs, 2 for the length/type and at minimum 46 bytes of data) 
	if (buffer.size() < Ethernet::MinimumSize)
	{
		buffer.resize(Ethernet::MinimumSize);
	}
}

void Ethernet::serialize(std::vector<byte>& buffer, const size_t offset) const
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
