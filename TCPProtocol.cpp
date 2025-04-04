#include "TCPProtocol.h"

#include "EndianHandler.h"
#include "EthernetProtocol.h"
#include "IPv4Protocol.h"

void TCP::addr(byte* address)
{
    m_data = reinterpret_cast<TCPHeader*>(address);
}

byte* TCP::addr() const
{
    return reinterpret_cast<byte*>(m_data);
}

size_t TCP::getSize() const
{
    return TCP::BASE_SIZE + ((getOptionsSize() + 3) & ~3);
}

void TCP::addOptionsPadding(byte* ptr) const
{
    // If option size % 4 == 0, it's invalid, meaning no padding
    if (getOptionsSize() % 4 == 0)
    {
        return;
    }

    byte2 paddingLength = (4 - getOptionsSize() % 4);

    std::memset(ptr, 0, paddingLength);
}

size_t TCP::getOptionsSize() const
{
	return m_optionsEndLoc - BASE_SIZE;
}


TCP::TCP(byte* data)
    : m_data(reinterpret_cast<TCPHeader*>(data)), m_optionsEndLoc(BASE_SIZE)
{}

void TCP::calculateChecksum(MutablePacket& packet, const size_t index)
{
	byte4 checksumVal = 0;

	// Size of the packet from UDP
	byte2 fromProtocolSize = ((byte*)packet.getBuffer() + packet.getSize()) - (byte*)m_data;

	// Calculate checksum
	byte2* iter = (byte2*)(m_data);
	byte2* end = (byte2*)((byte*)m_data + fromProtocolSize);

	Protocol* lastProtocol = packet.getPtr<Protocol>(index - 1);

	if (lastProtocol == nullptr)
	{
		throw std::runtime_error("Couldn't calculate checksum, UDP first layer.");
	}

	if (lastProtocol->protType() == ProvidedProtocols::IPv4)
	{
		const IPv4* ipv4 = packet.getPtr<IPv4>(index - 1);
		const size_t IPV4_PSESUDO_SIZE = 12;
		byte pseudoArr[IPV4_PSESUDO_SIZE] = { 0 };

		auto srcAddr = ipv4->src();
		std::memcpy(pseudoArr, &srcAddr, sizeof(ipv4->src()));
		auto dstAddr = ipv4->dst();
		std::memcpy(pseudoArr + 4, &dstAddr, sizeof(ipv4->dst()));
		pseudoArr[8] = 0;
		pseudoArr[9] = (byte)ipv4->protocol();

		// Set length
		byte2 netLength = Endianness::toNetwork(fromProtocolSize);
		std::memcpy(&pseudoArr[10], &netLength, sizeof(netLength));

		for (size_t i = 0; i < IPV4_PSESUDO_SIZE; i += 2)
		{
			checksumVal += Endianness::fromNetwork(
				*reinterpret_cast<byte2*>(&pseudoArr[i])
			);
		}
	}
	else
	{
		throw std::runtime_error("Couldn't calculate checksum, no transport layer found.");
	}

	int isOdd = (fromProtocolSize & 1) ? 1 : 0;

	while (iter + isOdd < end)
	{
		checksumVal += Endianness::fromNetwork(*iter);

		iter++;
	}

	if (isOdd)
	{
		byte lastByte = *((byte*)iter);
		checksumVal += (lastByte << 8);
	}

	while (checksumVal & 0xFFFF0000)
	{
		checksumVal = (checksumVal >> 16) + (checksumVal & 0xFFFF);
	}

	// one complement
	checksum(~checksumVal);
}

ProvidedProtocols TCP::protType() const
{
	return ID;
}

void TCP::encodePre(MutablePacket& packet, const size_t index)
{
	size_t startOffset = (byte*)m_data - (byte*)packet.getBuffer();
	size_t endOffset = packet.getSize();

	dataOffset(getOptionsSize() / 4 + 5); 

	checksum(0);
}

void TCP::encodePost(MutablePacket& packet, const size_t index)
{
	calculateChecksum(packet, index);
}

TCP& TCP::src(const byte2 value)
{
    m_data->src = Endianness::toNetwork(value);

    return *this;
}

byte2 TCP::src() const
{
    return Endianness::fromNetwork(m_data->src);
}

TCP& TCP::dst(const byte2 value)
{
    m_data->dst = Endianness::toNetwork(value);

    return *this;
}

byte2 TCP::dst() const
{
    return Endianness::fromNetwork(m_data->dst);
}

TCP& TCP::seq(const byte4 value)
{
    m_data->seq = Endianness::toNetwork(value);

    return *this;
}

byte4 TCP::seq() const
{
    return Endianness::fromNetwork(m_data->seq);
}

TCP& TCP::ack(const byte4 value)
{
    m_data->ack = Endianness::toNetwork(value);

    return *this;
}

byte4 TCP::ack() const
{
    return Endianness::fromNetwork(m_data->ack);
}

TCP& TCP::dataOffset(const byte value)
{
	int a = (value << 4) & 0xF0;
    m_data->dataOffset = ((value << 4) & 0xF0) | (m_data->dataOffset & 0x0F);

    return *this;
}

byte TCP::dataOffset() const
{
    // get last 4 msb bits
    return Endianness::fromNetwork(m_data->dataOffset) >> 4;
}

TCP& TCP::reserved(const byte value)
{
    // one byte value, no need for endianness
    m_data->dataOffset = (m_data->dataOffset & 0xF0) | (value & 0x0F); 
    
    return *this;
}

byte TCP::reserved() const
{
    return Endianness::fromNetwork(m_data->dataOffset & 0xF); // 4 bits
}

TCP& TCP::window(const byte2 value)
{
    m_data->window = Endianness::toNetwork(value);

    return *this;
}

byte2 TCP::window() const
{
    return Endianness::fromNetwork(m_data->window);
}

TCP& TCP::checksum(const byte2 value)
{
    m_data->checksum = Endianness::toNetwork(value);

    return *this;
}

byte2 TCP::checksum() const
{
    return Endianness::fromNetwork(m_data->checksum);
}

TCP& TCP::urgentPtr(const byte2 value)
{
    m_data->urgPtr = Endianness::toNetwork(value);

    return *this;
}

byte2 TCP::urgentPtr() const
{
    return Endianness::fromNetwork(m_data->urgPtr);
}

TCP& TCP::flags(const byte value)
{
    m_data->flags = Endianness::toNetwork(value);

    return *this;
}

byte TCP::flags()
{
    return Endianness::fromNetwork(m_data->flags);
}





constexpr TCP::Flags operator|(TCP::Flags a, TCP::Flags b)
{
    using T = std::underlying_type_t<TCP::Flags>;
    return static_cast<TCP::Flags>(static_cast<T>(a) | static_cast<T>(b));
}

constexpr TCP::Flags operator&(TCP::Flags a, TCP::Flags b)
{
    using T = std::underlying_type_t<TCP::Flags>;
    return static_cast<TCP::Flags>(static_cast<T>(a) & static_cast<T>(b));
}

// OPTIONS

TCP::OptionBase::OptionBase(byte* addr, MutablePacket* packet)
    : m_data(addr), m_packet(packet) 
{}

bool TCP::OptionBase::isReadOnly()
{
    return m_packet == nullptr;
}
