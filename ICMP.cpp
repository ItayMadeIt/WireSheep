#include "ICMP.h"
#include "EndianHandler.h"
#include "IPv4Header.h"

ICMP::ICMP(byte* data)
    : m_data(reinterpret_cast<ICMPHeader*>(data)), m_payloadLength(0)
{
    std::memset(data, 0, BASE_SIZE);
}

ICMP::ICMP(byte* data, MutablePacket& packet, ICMPMesssages::EchoReply msg)
    : m_data(reinterpret_cast<ICMPHeader*>(data)), m_payloadLength(0)
{
    std::memset(data, 0, BASE_SIZE);

    type(ControlType::EchoReply);
    code(ControlCode::EchoReply);

    setPayload(packet, msg.optionalDataPtr, msg.optionalDataLength);
}

ICMP::ICMP(byte* data, MutablePacket& packet, ICMPMesssages::EchoRequest msg)
    : m_data(reinterpret_cast<ICMPHeader*>(data)), m_payloadLength(0)
{
    std::memset(data, 0, BASE_SIZE);
    
    type(ControlType::EchoRequest);
    code(ControlCode::EchoRequest);

    byte4 contentVal = msg.identifier << 16 | msg.sequence;

    content(contentVal);

    setPayload(packet, msg.optionalDataPtr, msg.optionalDataLength);
}

ICMP::ICMP(byte* data, MutablePacket& packet, ICMPMesssages::DestinationUnreachable msg)
    : m_data(reinterpret_cast<ICMPHeader*>(data)), m_payloadLength(0)
{
    std::memset(data, 0, BASE_SIZE);
    
    type(ControlType::DestUnreachable);
    code(msg.code);
}

ICMP::ICMP(byte* data, MutablePacket& packet, ICMPMesssages::TimeExceeded msg)
    : m_data(reinterpret_cast<ICMPHeader*>(data))
{
    std::memset(data, 0, BASE_SIZE);
    
    type(ControlType::TimeExceeded);
    code(msg.code);

    const byte2 len = sizeof(IPv4Header) + 8;
    setPayload(packet, msg.originalPacketPtr, len);
}

ICMP& ICMP::type(const byte value)
{
    m_data->type = value;

    return *this;
}

ICMP& ICMP::type(const ControlType value)
{
    return type(static_cast<byte>(value));
}

byte ICMP::type() const
{
    return m_data->type;
}

ICMP& ICMP::code(const byte value)
{
    m_data->code = value;

    return *this;
}

ICMP& ICMP::code(const ControlCode value)
{
    return code(static_cast<byte>(value));
}

byte ICMP::code() const
{
    return m_data->code;
}

ICMP& ICMP::checksum(const byte2 value)
{
    m_data->checksum = Endianness::toNetwork(value);

    return *this;
}

byte2 ICMP::checksum()
{
    return Endianness::fromNetwork(m_data->checksum);
}

ICMP& ICMP::content(const byte4 value)
{
    m_data->content = Endianness::toNetwork(value);

    return *this;
}

byte4 ICMP::content()
{
    return Endianness::toNetwork(m_data->content);
}

ICMP& ICMP::setPayload(MutablePacket& packet, const byte* payload, const byte2 length)
{
    byte2 lastLength = m_payloadLength;
    
    packet.replaceFromAddr(getPayloadPtr(), lastLength, payload, length);
    
    m_payloadLength = length;

    return *this;
}

byte* ICMP::getPayloadPtr()
{
    return addr() + sizeof(ICMPHeader) + m_payloadLength;
}

byte2 ICMP::getPayloadLength()
{
    return m_payloadLength;
}

size_t ICMP::getSize() const
{
    return BASE_SIZE + m_payloadLength;
}

void ICMP::addr(byte* address)
{
    m_data = reinterpret_cast<ICMPHeader*>(address);
}

byte* ICMP::addr() const
{
    return reinterpret_cast<byte*>(m_data);
}

ProvidedProtocols ICMP::protType() const
{
    return ProvidedProtocols::ICMP;
}


void ICMP::encodePre(MutablePacket& packet, const size_t index)
{
    checksum(0);
}

void ICMP::encodePost(MutablePacket& packet, const size_t index)
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
