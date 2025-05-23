#include "EthernetProtocol.h"
#include "MutablePacket.h"

Ethernet::Ethernet(byte* data)
	: m_data(reinterpret_cast<EthernetHeader*>(data))
{}

Ethernet::~Ethernet() = default;

Ethernet& Ethernet::dst(const AddrMac value)
{
	m_data->dst = value;
	return *this;
}
AddrMac Ethernet::dst() const
{
	return m_data->dst;
}
Ethernet& Ethernet::src(const AddrMac value)
{
	m_data->src = value;
	return *this;

}
AddrMac Ethernet::src() const
{
	return m_data->src;
}

Ethernet& Ethernet::type(const byte2 value)
{
	m_data->etherType = Endianness::toNetwork(value);
	return *this;
}

Ethernet& Ethernet::type(const Protocols value)
{
	m_data->etherType = Endianness::toNetwork((byte2)value);
	return *this;
}

byte2 Ethernet::type() const
{
	return Endianness::fromNetwork(m_data->etherType);
}

void Ethernet::encodePost(MutablePacket& packet, size_t protocolIndex)
{
	if (packet.getSize() < MIN_SIZE)
	{
		size_t offset = (packet.getSize() > 0) ? packet.getSize() - 1 : 0;
		packet.insertBytes(0, MIN_SIZE - packet.getSize());
	}
}

void Ethernet::addr(byte* address)
{
	m_data = reinterpret_cast<EthernetHeader*>(address);
}

byte* Ethernet::addr() const
{
	return reinterpret_cast<byte*>(m_data);
}

ProvidedProtocols Ethernet::protType() const
{
	return ID;
}

size_t Ethernet::getSize() const
{
	return Ethernet::BASE_SIZE;
}

std::ostream& operator<<(std::ostream& os, const Ethernet& ether)
{
	os << "[Ethernet]" << std::endl;

	// Output source and destination
	os << "\tSrc:  " << ether.src() << std::endl;
	os << "\tDst:  " << ether.dst() << std::endl;

	// Output type as hex
	os << "\tType: " << std::setfill('0') << std::setw(4) << std::hex << ether.type() << std::endl;

	return os;
}
