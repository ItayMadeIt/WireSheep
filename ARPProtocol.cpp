#include "ARPProtocol.h"

#include "EndianHandler.h"

void ARP::writeToBuffer(byte* buffer) const
{

	//byte2 var = endiannesshandler::tonetworkendian(m_hardwaretype);
	//std::memcpy(buffer, &var, sizeof(var));
	//buffer += sizeof(var);

	//var = endiannesshandler::tonetworkendian(m_protocoltype);
	//std::memcpy(buffer, &var, sizeof(var));
	//buffer += sizeof(var);

	//std::memcpy(buffer, &m_hardwarelength, sizeof(m_hardwarelength));
	//buffer += sizeof(m_hardwarelength);

	//std::memcpy(buffer, &m_protocollength, sizeof(m_protocollength));
	//buffer += sizeof(m_protocollength);

	//var = endiannesshandler::tonetworkendian(m_operation);
	//std::memcpy(buffer, &var, sizeof(var));
	//buffer += sizeof(var);


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
	hardwareLength(m_senderHardwareAddr.size());
	protocolLength(m_senderProtocolAddr.size());

	byte* addrPtr = reinterpret_cast<byte*>(m_data) + sizeof(ARPHeader);

	std::memcpy(addrPtr, m_senderHardwareAddr.data(), m_senderHardwareAddr.size());
	addrPtr += m_senderHardwareAddr.size();

	std::memcpy(addrPtr, m_senderProtocolAddr.data(), m_senderProtocolAddr.size());
	addrPtr += m_senderProtocolAddr.size();

	std::memcpy(addrPtr, m_targetHardwareAddr.data(), m_targetHardwareAddr.size());
	addrPtr += m_targetHardwareAddr.size();

	std::memcpy(addrPtr, m_targetProtocolAddr.data(), m_targetProtocolAddr.size());
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

ARP::ARP(ARPHeader* data) : Protocol(AllProtocols::ARP), m_data(data)
{}

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
