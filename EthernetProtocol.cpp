#include "EthernetProtocol.h"
#include "MutablePacket.h"

Ethernet::Ethernet(byte* data)
	: Protocol(AllProtocols::Ethernet), 
	m_data(reinterpret_cast<EthernetHeader*>(data))
{ }

Ethernet::~Ethernet() = default;

Ethernet& Ethernet::dst(const AddrMac value)
{
	m_data->m_dst = value;
	return *this;
}
AddrMac Ethernet::dst() const
{
	return m_data->m_dst;
}
Ethernet& Ethernet::src(const AddrMac value)
{
	m_data->m_src = value;
	return *this;

}
AddrMac Ethernet::src() const
{
	return m_data->m_src;
}

Ethernet& Ethernet::type(const byte2 value)
{
	m_data->m_etherType = EndiannessHandler::toNetworkEndian(value);
	return *this;
}

Ethernet& Ethernet::type(const Protocols value)
{
	m_data->m_etherType = EndiannessHandler::toNetworkEndian((byte2)value);
	return *this;
}

byte2 Ethernet::type() const
{
	return m_data->m_etherType;
}

void Ethernet::encodePost(MutablePacket& packet, size_t protocolIndex)
{
	if (packet.size() < MIN_SIZE)
	{
		size_t offset = (packet.size() > 0) ? packet.size() - 1 : 0;
		packet.insertBytes(NULL, MIN_SIZE - packet.size());
	}
}

size_t Ethernet::getSize() const
{
	return Ethernet::BASE_SIZE;
}

std::ostream& operator<<(std::ostream& os, const Ethernet& ether)
{
	os << "[Ethernet]" << std::endl;

	// Output source and destination
	os << "Src : " << ether.src() << std::endl;
	os << "Dst : " << ether.dst() << std::endl;

	// Output type as dec and hex
	os << "Type: 0x" << std::setfill('0') << std::setw(4) << std::hex << (byte)ether.getProtocol() << std::endl;

	return os;
}
