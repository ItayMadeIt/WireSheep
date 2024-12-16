#include "IPv4.h"


IPv4::IPv4()
    : Protocol(ProtocolTypes::IPv4), m_src("0.0.0.0"), m_dst("0.0.0.0"), m_version(4), m_ihl(5), m_dscp(0), m_ecn(0b10),
    m_totalLength(20), m_identification(0), m_flags(0), m_fragmentOffset(0), m_ttl(64), m_protocol(0), m_checksum(0), m_options{0}
{ }

IPv4::IPv4(const addrIPv4 src, const addrIPv4 dst)
    : Protocol(ProtocolTypes::IPv4), m_src(src), m_dst(dst), m_version(4), m_ihl(5), m_dscp(0), m_ecn(0b10),
    m_totalLength(20), m_identification(0), m_flags(0), m_fragmentOffset(0), m_ttl(64), m_protocol(0), m_checksum(0), m_options{ 0 }
{ }

IPv4::IPv4(const std::string& src, const std::string& dst)
    : Protocol(ProtocolTypes::IPv4), m_src(src), m_dst(dst), m_version(4), m_ihl(5), m_dscp(0), m_ecn(0b10),
    m_totalLength(20), m_identification(0), m_flags(0), m_fragmentOffset(0), m_ttl(64), m_protocol(0), m_checksum(0), m_options{ 0 }
{ }

IPv4::IPv4(IPv4&& other) = default;

IPv4::IPv4(const IPv4& other) = default;

void IPv4::serializeArr(byte* ptr) const
{
    byte4 word = 0;

    // first 32 bits
    word = EndiannessHandler::toNetworkEndian(
        ((m_version & 0xF) << 28)       |    // Version      (4 bits)
        ((m_ihl & 0xF) << 24)           |    // IHL          (4 bits)
        ((m_dscp & 0x3F) << 18)         |    // DSCP         (6 bits)
        ((m_ecn & 0x3) << 16)           |    // ECN          (3 bits)
        ((m_totalLength& 0xFFFF) << 28)      // Total Length (16 bits)
    );
    memcpy(ptr, &word, sizeof(byte4));
    ptr += sizeof(byte4);


    // second 32 bits
    word = EndiannessHandler::toNetworkEndian(
        ((m_identification & 0xFFFF) << 16) | // Identification (16 bits)
        ((m_flags & 0x7) << 13)             | // Flags (3 bits)
        (m_fragmentOffset & 0x1FFF)           // Fragment Offset (13 bits)
    );         
    memcpy(ptr, &word, sizeof(byte4));
    ptr += sizeof(byte4);

    // third 32 bits
    word = EndiannessHandler::toNetworkEndian(
        ((m_ttl & 0xFF) << 24)      | // TTL (8 bits)
        ((m_protocol & 0xFF) << 16) | // Protocol (8 bits)
        (m_checksum & 0xFFFF)         // Header checksum (16 bits)
    );
    memcpy(ptr, &word, sizeof(byte4));
    ptr += sizeof(byte4);

    // Addresses
    memcpy(ptr, &m_src, sizeof(byte4));
    ptr += sizeof(byte4);
    memcpy(ptr, &m_dst, sizeof(byte4));
}

void IPv4::deserializeArr(const byte* ptr)
{
}

void IPv4::serialize(std::vector<byte>& buffer) const
{
}

size_t IPv4::getSize() const
{
    return m_ihl * 4;
}

void IPv4::serialize(std::vector<byte>& buffer, const size_t offset) const
{
    // Add ipv4 data to the array
    buffer.resize(buffer.size() + getSize());
    serializeArr(buffer.data() + offset);

    // Continue to serialize the data for the following protocols
    if (m_nextProtocol)
    {
        m_nextProtocol->serialize(buffer, offset + getSize());
    }
}
