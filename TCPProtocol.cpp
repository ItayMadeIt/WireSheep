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
    return TCP::BASE_SIZE + ((m_optionsSize + 3) & ~3);
}

void TCP::addOptionsPadding(byte* ptr) const
{
    // If option size % 4 == 0, it's invalid, meaning no padding
    if (m_optionsSize % 4 == 0)
    {
        return;
    }

    byte2 paddingLength = (4 - m_optionsSize % 4);

    std::memset(ptr, 0, paddingLength);
}


TCP::TCP(byte* data)
    : m_data(reinterpret_cast<TCPHeader*>(data))
{
    std::memset(data, 0, BASE_SIZE);
}

void TCP::calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol)
{
    if (!protocol)
    {
        // Will throw exception
        return;
    }

    byte4 checksumVal = 0;

    byte2 tcpLength = buffer.size() - offset;
    checksumVal += tcpLength;

    if (const IPv4* ipv4 = dynamic_cast<const IPv4*>(protocol))
    {
        size_t ipv4Offset = offset - ipv4->getSize();

        // Add psuedo header

        AddrIPv4 addr = ipv4->src();
        checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data)));    // First 16-bit word
        checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data + 2))); // Second 16-bit word

        addr = ipv4->dst();
        checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data)));    // First 16-bit word
        checksumVal += Endianness::fromNetwork(*(reinterpret_cast<byte2*>(addr.m_data + 2))); // Second 16-bit word

        checksumVal += (byte2)(ipv4->protocol());

    }/*
    else if (const IPv6* ipv4 = dynamic_cast<const IPv4*>(protocol))
    {
        // Assume it will work
        // const IPv6* ipv6 = dynamic_cast<const IPv6*>(protocol);

        // Not implemented yet
    }*/
    else
    {
        return;
    }

    bool isOdd = (tcpLength - getSize()) % 2 != 0;

    // Iterate through 16-bit words
    byte2* iter = reinterpret_cast<byte2*>(buffer.data() + offset);
    byte2* end = reinterpret_cast<byte2*>(buffer.data() + offset + tcpLength - (isOdd ? 1 : 0));

    for (; iter < end; iter++)
    {
        checksumVal += Endianness::fromNetwork(*iter);
    }

    // Handle the last leftover byte if the payload length is odd
    if (isOdd)
    {
        // Get the last byte
        byte lastByte = *(buffer.data() + offset + tcpLength - 1);
        byte2 paddedWord = (lastByte << 8);
        checksumVal += paddedWord;
    }

    while (checksumVal >> 16)
    {
        checksumVal = (checksumVal & 0xFFFF) + (checksumVal >> 16);
    }
    checksum(~checksumVal);

    byte2 networkChecksum = Endianness::toNetwork(m_checksum);

    size_t headerChecksumOffset = offset + 16; // 6 = header checksum position relative to UDP start of the packet
    byte* checksumPtr = buffer.data() + headerChecksumOffset;

    std::memcpy(checksumPtr, &networkChecksum, sizeof(networkChecksum));
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
    m_data->dataOffset = Endianness::toNetwork(value & 0xF0) | (m_data->dataOffset & 0x0F);

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
