#include "ARPProtocol.h"

#include "EndianHandler.h"

void ARP::writeToBuffer(byte* buffer) const
{
	byte2 var = EndiannessHandler::toNetworkEndian(m_hardwareType);
	std::memcpy(buffer, &var, sizeof(var));
	buffer += sizeof(var);

	var = EndiannessHandler::toNetworkEndian(m_protocolType);
	std::memcpy(buffer, &var, sizeof(var));
	buffer += sizeof(var);

	std::memcpy(buffer, &m_hardwareLength, sizeof(m_hardwareLength));
	buffer += sizeof(m_hardwareLength);

	std::memcpy(buffer, &m_protocolLength, sizeof(m_protocolLength));
	buffer += sizeof(m_protocolLength);

	var = EndiannessHandler::toNetworkEndian(m_operation);
	std::memcpy(buffer, &var, sizeof(var));
	buffer += sizeof(var);


	std::memcpy(buffer, m_senderHardwareAddr.data(), m_senderHardwareAddr.size());
	buffer += m_senderHardwareAddr.size();

	std::memcpy(buffer, m_senderProtocolAddr.data(), m_senderProtocolAddr.size());
	buffer += m_senderProtocolAddr.size();

	std::memcpy(buffer, m_targetHardwareAddr.data(), m_targetHardwareAddr.size());
	buffer += m_targetHardwareAddr.size();

	std::memcpy(buffer, m_targetProtocolAddr.data(), m_targetProtocolAddr.size());
	buffer += m_targetProtocolAddr.size();
}

void ARP::readFromBuffer(const byte* buffer, const size_t size)
{
	// No implementation
}

void ARP::encodeLayer(std::vector<byte>& buffer, const size_t offset)
{
	// verify addresses are the same size/type
	if (m_senderHardwareAddr.size() != m_targetHardwareAddr.size())
	{
		// (Will later throw exception)
		std::cerr << "Unmatched sizes for sender and target hardware addresses (using sender for length)" << std::endl;
	}
	if (m_senderProtocolAddr.size() != m_targetProtocolAddr.size())
	{
		// (Will later throw exception)
		std::cerr << "Unmatched sizes for sender and target protocol addresses (using sender for length)" << std::endl;
	}

	// set lengths
	m_hardwareLength = m_senderHardwareAddr.size();
	m_protocolLength = m_senderProtocolAddr.size();

	// Add ARP data to the buffer
	buffer.resize(buffer.size() + getSize());
	writeToBuffer(buffer.data() + offset);
}

void ARP::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
	// Add ARP data to the buffer
	buffer.resize(buffer.size() + getSize());
	writeToBuffer(buffer.data() + offset);
}

size_t ARP::getSize() const
{
	size_t size = ARP::SIZE_NO_ADDR; // header

	size += m_senderHardwareAddr.size();

	size += m_senderProtocolAddr.size();

	size += m_targetHardwareAddr.size();

	size += m_targetProtocolAddr.size();

	return size;
}

ARP::ARP() : Protocol(AllProtocols::ARP)
{
}

ARP& ARP::opcode(const byte2 value)
{
	m_operation = value;

	return *this;
}

ARP& ARP::opcode(const OperationCode value)
{
	m_operation = (byte2)value;

	return *this;
}

byte2 ARP::opcode() const
{
	return m_operation;
}

ARP& ARP::hardwareType(const byte2 value)
{
	m_hardwareType = value;

	return *this;
}

ARP& ARP::hardwareType(const HardwareType value)
{
	m_hardwareType = (byte2)value;

	return *this;
}

byte2 ARP::hardwareType() const
{
	return m_hardwareType;
}

ARP& ARP::protocol(const byte2 value)
{
	m_protocolType = value;

	return *this;
}

ARP& ARP::protocol(const Ethernet::Protocols value)
{
	m_protocolType = (byte2)value;

	return *this;
}

byte2 ARP::protocol() const
{
	return m_protocolType;
}

ARP& ARP::hardwareLength(const byte value)
{
	m_hardwareLength = value;

	return *this;
}

byte ARP::hardwareLength() const
{
	return m_hardwareLength;
}

ARP& ARP::protocolLength(const byte value)
{
	m_protocolLength = value;

	return *this;
}

byte ARP::protocolLength() const
{
	return m_protocolLength;
}

ARP& ARP::senderHardwareAddr(const address::AddrMac mac)
{
	// Copy bytes from the mac address to the send hardware address
	m_senderHardwareAddr.resize(sizeof(mac));
	std::memcpy(m_senderHardwareAddr.data(), &mac, sizeof(mac));

	return *this;
}

ARP& ARP::senderHardwareAddr(const std::vector<byte> addr)
{
	m_senderHardwareAddr = addr;

	return *this;
}

std::vector<byte> ARP::senderHardwareAddr() const
{
	return m_senderHardwareAddr;
}

ARP& ARP::senderProtocolAddr(const address::AddrIPv4 ipv4)
{
	// Copy bytes from the ipv4 address to the fit the protocol address
	m_senderProtocolAddr.resize(sizeof(ipv4));
	std::memcpy(m_senderProtocolAddr.data(), &ipv4, sizeof(ipv4));

	return *this;
}

ARP& ARP::senderProtocolAddr(const std::vector<byte> addr) 
{
	m_senderProtocolAddr = addr;

	return *this;
}

std::vector<byte> ARP::senderProtocolAddr() const
{
	return m_senderProtocolAddr;
}

ARP& ARP::targetHardwareAddr(const address::AddrMac mac)
{
	// Copy bytes from the mac address to the target hardware address
	m_targetHardwareAddr.resize(sizeof(mac));
	std::memcpy(m_targetHardwareAddr.data(), &mac, sizeof(mac));

	return *this;
}

ARP& ARP::targetHardwareAddr(const std::vector<byte> addr) 
{
	m_targetHardwareAddr = addr;

	return *this;
}

std::vector<byte> ARP::targetHardwareAddr() const
{
	return m_targetHardwareAddr;
}

ARP& ARP::targetProtocolAddr(const address::AddrIPv4 ipv4)
{
	// Copy bytes from the ipv4 address to the fit the protocol address
	m_targetProtocolAddr.resize(sizeof(ipv4));
	std::memcpy(m_targetProtocolAddr.data(), &ipv4, sizeof(ipv4));

	return *this;
}

ARP& ARP::targetProtocolAddr(const std::vector<byte> addr)
{
	m_targetProtocolAddr = addr;

	return *this;
}

std::vector<byte> ARP::targetProtocolAddr() const
{
	return m_targetProtocolAddr;
}
