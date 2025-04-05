#include "ARPProtocol.h"
#include "EndianHandler.h"
#include <string>
ARP::ARP(byte* data) : Protocol(), m_data(reinterpret_cast<ARPHeader*>(data))
{}

ARP::ARP(byte* data, HardwareType hardwareType, Ethernet::Protocols protocolType)
	: Protocol(), m_data(reinterpret_cast<ARPHeader*>(data))
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

void ARP::addr(byte* address)
{
	m_data = reinterpret_cast<ARPHeader*>(address);
}

byte* ARP::addr() const
{
	return reinterpret_cast<byte*>(m_data);
}

ProvidedProtocols ARP::protType() const
{
	return ID;
}

ARP& ARP::opcode(const byte2 value)
{
	m_data->operation = Endianness::toNetwork(value);

	return *this;
}

ARP& ARP::opcode(const OperationCode value)
{
	m_data->operation = Endianness::toNetwork((byte2)value);

	return *this;
}

byte2 ARP::opcode() const
{
	return Endianness::fromNetwork(m_data->operation);
}

ARP& ARP::hardwareType(const byte2 value)
{
	m_data->hardwareType = Endianness::toNetwork(value);

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
	m_data->hardwareType = Endianness::toNetwork((byte2)value);

	return *this;
}

byte2 ARP::hardwareType() const
{
	return Endianness::fromNetwork(m_data->hardwareType);
}

ARP& ARP::protocol(const byte2 value)
{
	m_data->protocolType = value;

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

	m_data->protocolType = Endianness::toNetwork((byte2)value);

	return *this;
}

byte2 ARP::protocol() const
{
	return Endianness::fromNetwork(m_data->protocolType);
}

ARP& ARP::hardwareLength(const byte value)
{
	m_data->hardwareLength = Endianness::toNetwork(value);

	return *this;
}

byte ARP::hardwareLength() const
{
	return Endianness::fromNetwork(m_data->hardwareLength);
}

ARP& ARP::protocolLength(const byte value)
{
	m_data->protocolLength = Endianness::toNetwork(value);

	return *this;
}

byte ARP::protocolLength() const
{
	return Endianness::fromNetwork(m_data->protocolLength);
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

std::ostream& operator<<(std::ostream& os, const ARP& arp)
{
	using namespace address;

	constexpr size_t hwLen = ADDR_MAC_BYTES;
	constexpr size_t protoLen = ADDR_IP4_BYTES;

	os << "[ARP]" << std::endl;

	if (arp.hardwareLength() == hwLen && arp.protocolLength() == protoLen)
	{
		AddrMac senderMac(arp.senderHardwareAddr());
		AddrIPv4 senderIP(arp.senderProtocolAddr());
		AddrMac targetMac(arp.targetHardwareAddr());
		AddrIPv4 targetIP(arp.targetProtocolAddr());

		os << "\tSender MAC:  " << senderMac << std::endl;
		os << "\tSender IP:   " << senderIP << std::endl;
		os << "\tTarget MAC:  " << targetMac << std::endl;
		os << "\tTarget IP:   " << targetIP << std::endl;
	}
	else
	{
		os << "\t[!] Unknown address sizes:" << std::endl;
		os << "\t    Hardware size: " << static_cast<int>(arp.hardwareLength()) << std::endl;
		os << "\t    Protocol size: " << static_cast<int>(arp.protocolLength()) << std::endl;
	}

	return os;
}
