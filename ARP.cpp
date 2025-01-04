#include "ARP.h"
#include "EndianHandler.h"
void ARP::serializeArr(byte* ptr) const
{
	byte2 var = EndiannessHandler::toNetworkEndian(m_hardwareType);
	std::memcpy(ptr, &var, sizeof(var));
	ptr += sizeof(var);

	var = EndiannessHandler::toNetworkEndian(m_protocolType);
	std::memcpy(ptr, &var, sizeof(var));
	ptr += sizeof(var);

	std::memcpy(ptr, &m_hardwareLength, sizeof(m_hardwareLength));
	ptr += sizeof(m_hardwareLength);

	std::memcpy(ptr, &m_protocolLength, sizeof(m_protocolLength));
	ptr += sizeof(m_protocolLength);

	var = EndiannessHandler::toNetworkEndian(m_operation);
	std::memcpy(ptr, &var, sizeof(var));
	ptr += sizeof(var);


	std::memcpy(ptr, m_senderHardwareAddr.data(), m_senderHardwareAddr.size());
	ptr += m_senderHardwareAddr.size();

	std::memcpy(ptr, m_senderProtocolAddr.data(), m_senderProtocolAddr.size());
	ptr += m_senderProtocolAddr.size();

	std::memcpy(ptr, m_targetHardwareAddr.data(), m_targetHardwareAddr.size());
	ptr += m_targetHardwareAddr.size();

	std::memcpy(ptr, m_targetProtocolAddr.data(), m_targetProtocolAddr.size());
	ptr += m_targetProtocolAddr.size();


}

void ARP::deserializeArr(const byte* ptr)
{
}

void ARP::serialize(std::vector<byte>& buffer)
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);

	// Add ethernet data to the array
	buffer.resize(buffer.size() + getSize());
	serializeArr(buffer.data());

	// Specific to ARP
	if (m_senderHardwareAddr.size() != m_targetHardwareAddr.size())
	{
		std::cerr << "Unmatched sizes for sender and target hardware addresses (using sender for length)" << std::endl;
	}
	m_hardwareLength = m_senderHardwareAddr.size();

	if (m_senderProtocolAddr.size() != m_targetProtocolAddr.size())
	{
		std::cerr << "Unmatched sizes for sender and target protocol addresses (using sender for length)" << std::endl;
	}
	m_hardwareLength = m_senderProtocolAddr.size();

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, getSize());
	}
}

void ARP::serializeRaw(std::vector<byte>& buffer) const
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);

	// Add ethernet data to the array
	buffer.resize(buffer.size() + getSize());
	serializeArr(buffer.data());

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, getSize());
	}
}

size_t ARP::getSize() const
{
	size_t size = 0;
	size += sizeof(byte4) * 2; // header

	size += m_senderHardwareAddr.size();

	size += m_senderProtocolAddr.size();

	size += m_targetHardwareAddr.size();

	size += m_targetProtocolAddr.size();

	return size;
}

void ARP::serialize(std::vector<byte>& buffer, const size_t offset)
{
	// Get the amount of bytes we have left to input
	size_t bytesAmount = buffer.capacity() - buffer.size();

	// Specific to ARP
	if (m_senderHardwareAddr.size() != m_targetHardwareAddr.size())
	{
		std::cerr << "Unmatched sizes for sender and target hardware addresses (using sender for length)" << std::endl;
	}
	m_hardwareLength = m_senderHardwareAddr.size();

	if (m_senderProtocolAddr.size() != m_targetProtocolAddr.size())
	{
		std::cerr << "Unmatched sizes for sender and target protocol addresses (using sender for length)" << std::endl;
	}
	m_protocolLength = m_senderProtocolAddr.size();

	// Add data to the array
	buffer.resize(buffer.size() + getSize());
	serializeArr(buffer.data() + offset);
	
	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, offset + getSize());
	}
}

void ARP::serializeRaw(std::vector<byte>& buffer, const size_t offset) const
{
	// Reserve the size
	size_t size = getLayersSize();
	buffer.reserve(size);

	// Add ethernet data to the array
	buffer.resize(buffer.size() + getSize());
	serializeArr(buffer.data());

	// Continue to serialize the data for the following protocols
	if (m_nextProtocol)
	{
		m_nextProtocol->serialize(buffer, getSize());
	}
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

byte2 ARP::opcode()
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

byte2 ARP::hardwareType()
{
	return m_hardwareType;
}

ARP& ARP::protocolType(const byte2 value)
{
	m_protocolType = value;

	return *this;
}

ARP& ARP::protocolType(const Ethernet::ProtocolTypes value)
{
	m_protocolType = (byte2)value;

	return *this;
}

byte2 ARP::protocolType()
{
	return m_protocolType;
}

ARP& ARP::hardwareLength(const byte value)
{
	m_hardwareLength = value;

	return *this;
}

byte ARP::hardwareLength()
{
	return m_hardwareLength;
}

ARP& ARP::protocolLength(const byte value)
{
	m_protocolLength = value;

	return *this;
}

byte ARP::protocolLength()
{
	return m_protocolLength;
}

ARP& ARP::senderHardwareAddr(const address::addrMac mac)
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

std::vector<byte> ARP::senderHardwareAddr()
{
	return m_senderHardwareAddr;
}

ARP& ARP::senderProtocolAddr(const address::addrIPv4 ipv4)
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

std::vector<byte> ARP::senderProtocolAddr()
{
	return m_senderProtocolAddr;
}

ARP& ARP::targetHardwareAddr(const address::addrMac mac)
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

std::vector<byte> ARP::targetHardwareAddr()
{
	return m_targetHardwareAddr;
}

ARP& ARP::targetProtocolAddr(const address::addrIPv4 ipv4)
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

std::vector<byte> ARP::targetProtocolAddr()
{
	return m_targetProtocolAddr;
}
