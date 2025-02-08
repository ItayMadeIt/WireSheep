#include "EthernetProtocol.h"

Ethernet::Ethernet(EthernetHeader* data)
	: Protocol(AllProtocols::Ethernet), m_data(data)
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

void Ethernet::writeToBuffer(byte* buffer) const
{
	// No need for an implementation, the buffer already has that data
}

void Ethernet::readFromBuffer(const byte* buffer, const size_t size)
{
	// No need for an implementation, the buffer already has that data
}

size_t Ethernet::getSize() const
{
	return Ethernet::SIZE;
}

// No need for an implementation, the buffer already has that data
// Might include special cases 
void Ethernet::encodeLayer(std::vector<byte>& buffer, const size_t offset) 
{
}

// No need for an implementation, the buffer already has that data
void Ethernet::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
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
	os << "Src : " << ether.src() << std::endl;
	os << "Dst : " << ether.dst() << std::endl;

	// Output type as dec and hex
	os << "Type: " << std::setfill(' ') << std::setw(5) << std::dec << (byte)ether.getProtocol();
	os << " | 0x" << std::setfill('0') << std::setw(4) << std::hex << (byte)ether.getProtocol() << std::endl << std::dec;

	return os;
}
