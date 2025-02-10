#include "ARPProtocol.h"
#include "EndianHandler.h"
#include <string>
ARP::ARP(byte* data) : Protocol(AllProtocols::ARP), m_data(reinterpret_cast<ARPHeader*>(data))
{}

ARP::ARP(byte* data, HardwareType hardwareType, Ethernet::Protocols protocolType)
	: Protocol(AllProtocols::ARP), m_data(reinterpret_cast<ARPHeader*>(data))
{
	m_size = ARP::BASE_SIZE;

	switch (hardwareType)
	{
	case ARP::HardwareType::Ether:
		m_size += sizeof(AddrMac) * 2;
		break;
	default:
		throw std::exception(("Hardware type " + std::to_string((byte2)hardwareType) + " isn't defined").c_str());
	}

	switch (protocolType)
	{
	case Ethernet::Protocols::IPv4:
		m_size += sizeof(AddrIPv4) * 2;
		break;
	default:
		throw std::exception(("Protocol type " + std::to_string((byte2)protocolType) + " isn't defined").c_str());
	}
}


void ARP::writeToBuffer(byte* buffer) const
{
	// Not implemented
}

void ARP::readFromBuffer(const byte* buffer, const size_t size)
{
	// No implementation
}

byte* ARP::targetProtocolAddr() const
{
	return reinterpret_cast<byte*>(m_data) +
		BASE_SIZE +
		hardwareLength() +
		protocolLength() +
		hardwareLength();
}

byte* ARP::senderProtocolAddr() const
{
	return reinterpret_cast<byte*>(m_data) +
		BASE_SIZE +
		hardwareLength();
}

byte* ARP::targetHardwareAddr() const
{
	return reinterpret_cast<byte*>(m_data) +
		BASE_SIZE +
		hardwareLength() +
		protocolLength();
}

byte* ARP::senderHardwareAddr() const
{
	return reinterpret_cast<byte*>(m_data) +
		BASE_SIZE;
}


size_t ARP::getSize() const
{
	return m_size;
}

ARP& ARP::opcode(const byte2 value)
{
	m_data->m_operation = EndiannessHandler::toNetworkEndian(value);

	return *this;
}

ARP& ARP::opcode(const OperationCode value)
{
	m_data->m_operation = EndiannessHandler::toNetworkEndian((byte2)value);

	return *this;
}

byte2 ARP::opcode() const
{
	return EndiannessHandler::fromNetworkEndian(m_data->m_operation);
}

ARP& ARP::hardwareType(const byte2 value)
{
	m_data->m_hardwareType = EndiannessHandler::toNetworkEndian(value);

	return *this;
}

ARP& ARP::hardwareType(const HardwareType value)
{
	switch (value)
	{
	case HardwareType::Ether:
		hardwareLength(sizeof(AddrMac));
		break;
	default:
		break;
	}
	m_data->m_hardwareType = EndiannessHandler::toNetworkEndian((byte2)value);

	return *this;
}

byte2 ARP::hardwareType() const
{
	return EndiannessHandler::fromNetworkEndian(m_data->m_hardwareType);
}

ARP& ARP::protocol(const byte2 value)
{
	m_data->m_protocolType = value;

	return *this;
}

ARP& ARP::protocol(const Ethernet::Protocols value)
{
	switch (value)
	{
	case Ethernet::Protocols::IPv4:
		protocolLength(sizeof(AddrIPv4));
		break;
	case Ethernet::Protocols::IPv6:
		protocolLength(sizeof(AddrIPv6));
		break;
	default:
		break;
	}

	m_data->m_protocolType = EndiannessHandler::toNetworkEndian((byte2)value);

	return *this;
}

byte2 ARP::protocol() const
{
	return EndiannessHandler::fromNetworkEndian(m_data->m_protocolType);
}

ARP& ARP::hardwareLength(const byte value)
{
	m_data->m_hardwareLength = EndiannessHandler::toNetworkEndian(value);

	return *this;
}

byte ARP::hardwareLength() const
{
	return EndiannessHandler::fromNetworkEndian(m_data->m_hardwareLength);
}

ARP& ARP::protocolLength(const byte value)
{
	m_data->m_protocolLength = EndiannessHandler::toNetworkEndian(value);

	return *this;
}

byte ARP::protocolLength() const
{
	return EndiannessHandler::fromNetworkEndian(m_data->m_protocolLength);
}

ARP& ARP::senderHardwareAddr(const address::AddrMac mac)
{
	std::memcpy(senderHardwareAddr(), &mac, sizeof(mac));
	
	return *this;
}

ARP& ARP::senderHardwareAddr(const byte* addr)
{
	std::memcpy(senderHardwareAddr(), addr, hardwareLength());

	return *this;
}

ARP& ARP::senderProtocolAddr(const address::AddrIPv4 ipv4)
{
	std::memcpy(senderProtocolAddr(), &ipv4, sizeof(ipv4));

	return *this;
}

ARP& ARP::senderProtocolAddr(const byte* addr)
{
	std::memcpy(senderProtocolAddr(), addr, protocolLength());

	return *this;
}

ARP& ARP::targetHardwareAddr(const address::AddrMac mac)
{
	std::memcpy(targetHardwareAddr(), &mac, sizeof(mac));

	return *this;
}

ARP& ARP::targetHardwareAddr(const byte* addr)
{
	std::memcpy(targetHardwareAddr(), addr, hardwareLength());

	return *this;
}

ARP& ARP::targetProtocolAddr(const address::AddrIPv4 ipv4)
{
	std::memcpy(targetProtocolAddr(), &ipv4, sizeof(ipv4));

	return *this;
}

ARP& ARP::targetProtocolAddr(const byte* addr)
{
	std::memcpy(targetProtocolAddr(), addr, protocolLength());

	return *this;
}
