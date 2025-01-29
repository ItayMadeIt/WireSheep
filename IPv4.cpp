#include "IPv4.h"


IPv4::IPv4()
    : Protocol(AllProtocols::IPv4), m_src("0.0.0.0"), m_dst("0.0.0.0"), m_version(4), m_ihl(5), m_dscp(0), m_ecn(0b00),
    m_totalLength(20), m_identification(0), m_flags(0), m_fragmentOffset(0), m_ttl(64), m_protocol(0), m_checksum(0), m_options{0}
{ }

IPv4::IPv4(const addrIPv4 src, const addrIPv4 dst)
    : Protocol(AllProtocols::IPv4), m_src(src), m_dst(dst), m_version(4), m_ihl(5), m_dscp(0), m_ecn(0b00),
    m_totalLength(20), m_identification(0), m_flags(0), m_fragmentOffset(0), m_ttl(64), m_protocol(0), m_checksum(0), m_options{ 0 }
{ }

IPv4::IPv4(const std::string& src, const std::string& dst)
    : Protocol(AllProtocols::IPv4), m_src(src), m_dst(dst), m_version(4), m_ihl(5), m_dscp(0), m_ecn(0b00),
    m_totalLength(20), m_identification(0), m_flags(0), m_fragmentOffset(0), m_ttl(64), m_protocol(0), m_checksum(0), m_options{ 0 }
{ }

IPv4::IPv4(IPv4&& other) = default;

IPv4::IPv4(const IPv4& other) = default;

size_t IPv4::getSize() const
{
    return m_ihl * 4;
}

void IPv4::writeToBuffer(byte* buffer) const
{
    byte4 word = 0;

    // first 32 bits
    word = EndiannessHandler::toNetworkEndian(
        ((m_version & 0xF) << 28)       |    // Version      (4 bits)
        ((m_ihl & 0xF) << 24)           |    // IHL          (4 bits)
        ((m_dscp & 0x3F) << 18)         |    // DSCP         (6 bits)
        ((m_ecn & 0x3) << 16)           |    // ECN          (3 bits)
        ((m_totalLength& 0xFFFF))            // Total Length (16 bits)
    );
    memcpy(buffer, &word, sizeof(byte4));
    buffer += sizeof(byte4);


    // second 32 bits
    word = EndiannessHandler::toNetworkEndian(
        ((m_identification & 0xFFFF) << 16) | // Identification (16 bits)
        ((m_flags & 0x7) << 13)             | // Flags (3 bits)
        (m_fragmentOffset & 0x1FFF)           // Fragment Offset (13 bits)
    );         
    memcpy(buffer, &word, sizeof(byte4));
    buffer += sizeof(byte4);

    // third 32 bits
    word = EndiannessHandler::toNetworkEndian(
        ((m_ttl & 0xFF) << 24)      | // TTL (8 bits)
        ((m_protocol & 0xFF) << 16) | // Protocol (8 bits)
        (m_checksum & 0xFFFF)         // Header checksum (16 bits)
    );
    memcpy(buffer, &word, sizeof(byte4));
    buffer += sizeof(byte4);

    // Addresses
    memcpy(buffer, &m_src, sizeof(byte4));
    buffer += sizeof(byte4);
    memcpy(buffer, &m_dst, sizeof(byte4));
}

void IPv4::readFromBuffer(const byte* buffer, const size_t size)
{
    // Not implemented
}

void IPv4::encodeLayer(std::vector<byte>& buffer, const size_t offset) 
{
    // Calculate IPv4 checksum
    // calculateChecksum();
    m_totalLength = buffer.capacity() - offset;
    m_version = 4;
    m_checksum = 0;

    // Add ipv4 data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);
}

void IPv4::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
    // Add ipv4 data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);
}


void IPv4::calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol)
{
    // (Will ignore protocol, it doesn't depend on anything...)

    byte4 checksumVal = 0;

    // Calculate checksum
    byte2* iter = (byte2*)(buffer.data() + offset);
    byte2* end = (byte2*)(buffer.data() + offset + getSize());

    for (; iter < end; iter++)
    {
        checksumVal += EndiannessHandler::fromNetworkEndian(*iter);
    }

    byte2 checksumCarry = (checksumVal & 0xFFFF0000) >> 16;
    m_checksum = ~((checksumVal & 0xFFFF) + checksumCarry);

    // Get it in the correct endianness
    byte2 networkChecksum = EndiannessHandler::toNetworkEndian(m_checksum);
    
    // Copy the new checksum value to the network buffer
    size_t headerChecksumOffset = offset + 10; // 10 = header checksum position relative to IPv4 start of the packet
    byte* checksumPtr = buffer.data() + headerChecksumOffset;

    std::memcpy(checksumPtr, &networkChecksum, sizeof(networkChecksum));
}