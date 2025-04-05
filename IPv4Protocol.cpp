#include "IPv4Protocol.h"

IPv4::IPv4(IPv4&& other) = default;

IPv4::IPv4(const IPv4& other) = default;

IPv4::IPv4(byte * data)
    : m_data(reinterpret_cast<IPv4Header*>(data))
{
    /*
    version(4);
    ihl(5);
    dscp((byte)IPv4::Services::CS0); // default
    ecn(0b10);
    ttl(64);*/
}

IPv4::IPv4(byte* data, AddrIPv4 src, AddrIPv4 dst)
    : m_data(reinterpret_cast<IPv4Header*>(data))
{
    m_data->src = src;
    m_data->dst = dst;
}

IPv4& IPv4::src(const AddrIPv4 value) 
{
    m_data->src = value;
    return *this;
}

AddrIPv4 IPv4::src() const 
{
    return m_data->src;
}

IPv4& IPv4::dst(const AddrIPv4 value) 
{
    m_data->dst = value;
    return *this;
}

AddrIPv4 IPv4::dst() const 
{
    return m_data->dst;
}

IPv4& IPv4::version(const byte value) 
{
    m_data->version_ihl = Endianness::toNetwork((byte)((value << 4) | (Endianness::fromNetwork(m_data->version_ihl) & 0xF)));
    return *this;
}

byte IPv4::version() const 
{
    return Endianness::fromNetwork(m_data->version_ihl) >> 4;
}

IPv4& IPv4::ihl(const byte value) 
{
    m_data->version_ihl = Endianness::toNetwork((byte)((Endianness::fromNetwork(m_data->version_ihl) & 0xF0) | value));
    return *this;
}

byte IPv4::ihl() const 
{
    return Endianness::fromNetwork(m_data->version_ihl) & 0xF;
}

IPv4& IPv4::dscp(const byte value) 
{
    m_data->dscp_ecn = Endianness::toNetwork( (value << 2) | (Endianness::fromNetwork(m_data->dscp_ecn) & 0b11) );
    return *this;
}

byte IPv4::dscp() const 
{
    return Endianness::fromNetwork(m_data->dscp_ecn) >> 2;
}

IPv4& IPv4::ecn(const byte value) 
{
    m_data->dscp_ecn = Endianness::toNetwork( (Endianness::fromNetwork(m_data->dscp_ecn) & 0xFC) | value );
    return *this;
}

byte IPv4::ecn() const 
{
    return Endianness::fromNetwork(m_data->dscp_ecn) & 0b11;
}

IPv4& IPv4::identification(const byte2 value) 
{
    m_data->identification = Endianness::toNetwork(value);
    return *this;
}

byte2 IPv4::identification() const
{
    return Endianness::fromNetwork(m_data->identification);
}

IPv4& IPv4::flags(const byte value) 
{
    m_data->flags_framentOffset = Endianness::fromNetwork((byte2)value << 13) | (Endianness::toNetwork(m_data->flags_framentOffset) & 0b1111111111111);
    return *this;
}

IPv4& IPv4::flags(const Flags value) 
{
    m_data->flags_framentOffset = Endianness::fromNetwork((byte2)value << 13) | (Endianness::toNetwork(m_data->flags_framentOffset) & 0b1111111111111);
    return *this;
}

byte IPv4::flags() const 
{
    return Endianness::toNetwork(m_data->flags_framentOffset) >> 13;
}

IPv4& IPv4::fragmentOffset(const byte2 value) 
{
    byte2 fragmentOffset = Endianness::fromNetwork(value) & 0x1FFF;
    m_data->flags_framentOffset = Endianness::toNetwork ((Endianness::fromNetwork(m_data->flags_framentOffset) & 0b1110000000000000) | fragmentOffset);
    return *this;
}

byte2 IPv4::fragmentOffset() const 
{
    return Endianness::fromNetwork(m_data->flags_framentOffset) & 0x1FFF;
}

IPv4& IPv4::ttl(const byte value) 
{
    m_data->ttl = value;
    return *this;
}

byte IPv4::ttl() const 
{
    return m_data->ttl;
}

IPv4& IPv4::protocol(const Protocols value) 
{
    m_data->protocol = static_cast<byte>(value);
    return *this;
}

IPv4& IPv4::protocol(const byte value) 
{
    m_data->protocol = value;
    return *this;
}

byte IPv4::protocol() const 
{
    return m_data->protocol;
}

IPv4& IPv4::totalLength(const byte2 value) 
{
    m_data->totalLength = Endianness::toNetwork(value);
    return *this;
}

byte2 IPv4::totalLength() const 
{
    return Endianness::fromNetwork(m_data->totalLength);
}

IPv4& IPv4::checksum(const byte2 value) 
{
    m_data->checksum = Endianness::toNetwork(value);
    return *this;
}

byte2 IPv4::checksum() const 
{
    return Endianness::fromNetwork(m_data->checksum);
}

size_t IPv4::getSize() const
{
    // ihl is the amount of 4 bytes words (4 first bits of m_version_ihl)
    return ihl() * 4;
}

void IPv4::addr(byte* address)
{
    m_data = reinterpret_cast<IPv4Header*>(address);
}

byte* IPv4::addr() const
{
    return reinterpret_cast<byte*>(m_data);
}

void IPv4::encodePre(MutablePacket& packet, const size_t index)
{
    size_t startOffset = (byte*)m_data - (byte*)packet.getBuffer();
    size_t endOffset = packet.getSize();

    totalLength(endOffset - startOffset);

    checksum(0);
}

void IPv4::encodePost(MutablePacket& packet, const size_t index)
{
    byte4 checksumVal = 0;

    // Calculate checksum
    byte2* iter = (byte2*)(m_data);
    byte2* end = (byte2*)((byte*)m_data + getSize());

    while (iter < end)
    {
        checksumVal += Endianness::fromNetwork(*iter);
        iter++;
    }
    std::cout << std::dec;

    while (checksumVal & 0xFFFF0000)
    {
        checksumVal = (checksumVal >> 16) + (checksumVal & 0xFFFF);
    }

    // one complement
    checksum(~checksumVal & 0xFFFF);
}

ProvidedProtocols IPv4::protType() const
{
    return ID;
}

std::ostream& operator<<(std::ostream& os, const IPv4& ipv4)
{
    os << "[IPv4]" << std::endl;
    os << "\tSrc:      " << ipv4.src() << std::endl;
    os << "\tDst:      " << ipv4.dst() << std::endl;
    os << "\tProtocol: " << (byte2)ipv4.protocol() << std::endl;
    os << "\tFlags:    " << (byte2)ipv4.flags() << std::endl;
    os << "\tId:       " << ipv4.identification() << std::endl;
    os << "\tTTL:      " << (byte2)ipv4.ttl() << std::endl;
    os << "\tFrag Off: " << ipv4.fragmentOffset() << std::endl;

    return os;
}
