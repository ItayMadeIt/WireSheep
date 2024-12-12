#include "Ethernet.h"

Ethernet::Ethernet() : Protocol(ProtocolTypes::Ethernet)
{ }

Ethernet::Ethernet(const addrMac srcAddr, const addrMac dstAddr, const byte2 type)
	: Protocol(ProtocolTypes::Ethernet), m_src(srcAddr), m_dst(dstAddr), m_type(type)
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

void Ethernet::serialize(byte* ptr) const
{
	memcpy(ptr, &m_dst , ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	memcpy(ptr, &m_src , ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	byte2 netType = EndiannessHandler::toNetworkEndian(m_type);
	memcpy(ptr, &netType, ETHER_LEN_TYPE);
}

void Ethernet::deserialize(const byte* ptr)
{
	memcpy(&m_dst, ptr, ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	memcpy(&m_src, ptr, ADDR_MAC_BYTES);
	ptr += ADDR_MAC_BYTES;

	memcpy(&m_type, ptr, ETHER_LEN_TYPE);
	m_type = EndiannessHandler::fromNetworkEndian(m_type);
}

std::ostream& operator<<(std::ostream& os, const Ethernet ether)
{
	os << "[Ethernet]" << std::endl;
	os << "Src : " << ether.m_src  << std::endl;
	os << "Dst : " << ether.m_dst  << std::endl;
	os << "Type: " << ether.m_type << std::endl;
	return os;
}
