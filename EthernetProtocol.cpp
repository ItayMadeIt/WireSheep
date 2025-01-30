#include "EthernetProtocol.h"

Ethernet::Ethernet() : Protocol(AllProtocols::Ethernet)
{ }

Ethernet::Ethernet(const AddrMac src, const AddrMac dst, const byte2 type)
	: Protocol(AllProtocols::Ethernet), m_src(src), m_dst(dst), m_type(type)
{ }

Ethernet::Ethernet(const std::string & src, const std::string & dst, const byte2 type) 
	: Protocol(AllProtocols::Ethernet), m_src(src), m_dst(dst), m_type(type)
{ }

Ethernet::~Ethernet() = default;

Ethernet& Ethernet::dst(const AddrMac value)
{
	m_dst = value;
	return *this;
}
AddrMac Ethernet::dst() const
{
	return m_dst;
}
Ethernet& Ethernet::src(const AddrMac value)
{
	m_src = value;
	return *this;

}
AddrMac Ethernet::src() const
{
	return m_src;
}

Ethernet& Ethernet::type(const byte2 value)
{
	m_type = value;
	return *this;
}

Ethernet& Ethernet::type(const Protocols value)
{
	m_type = (byte2)value;
	return *this;
}

byte2 Ethernet::type() const
{
	return m_type;
}

void Ethernet::writeToBuffer(byte* buffer) const
{
	memcpy(buffer, &m_dst , ADDR_MAC_BYTES);
	buffer += ADDR_MAC_BYTES;

	memcpy(buffer, &m_src , ADDR_MAC_BYTES);
	buffer += ADDR_MAC_BYTES;

	byte2 netType = EndiannessHandler::toNetworkEndian(m_type);
	memcpy(buffer, &netType, ETHER_LEN_TYPE);
}

void Ethernet::readFromBuffer(const byte* buffer, const size_t size)
{
	memcpy(&m_dst, buffer, ADDR_MAC_BYTES);
	buffer += ADDR_MAC_BYTES;

	memcpy(&m_src, buffer, ADDR_MAC_BYTES);
	buffer += ADDR_MAC_BYTES;

	memcpy(&m_type, buffer, ETHER_LEN_TYPE);
	m_type = EndiannessHandler::fromNetworkEndian(m_type);
}

size_t Ethernet::getSize() const
{
	return Ethernet::SIZE;
}

void Ethernet::encodeLayer(std::vector<byte>& buffer, const size_t offset) 
{
	// Add ethernet data to the array
	buffer.resize(buffer.size() + Ethernet::SIZE);
	writeToBuffer(buffer.data() + offset);
}

void Ethernet::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
	// Add ethernet data to the array
	buffer.resize(buffer.size() + Ethernet::SIZE);
	writeToBuffer(buffer.data() + offset);
}

void Ethernet::encodeLayerPost(std::vector<byte>& buffer, const size_t offset)
{
	// Ensure there are at minimum 60 bytes (12 for both MACs, 2 for the length/type and at minimum 42 bytes of data) 
	if (buffer.size() < Ethernet::MIN_SIZE)
	{
		buffer.resize(Ethernet::MIN_SIZE);
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
