#include "RawProtocol.h"

Raw::Raw(byte* data)
    : Protocol(), m_size(0), m_data(data)
{
}

Raw& Raw::pushBack(const byte value, MutablePacket& packet)
{
    packet.insertBytes(value, 1);

    m_size++;

    return *this;
}

Raw& Raw::pushBack(const byte* values, const size_t length, MutablePacket& packet)
{
    packet.insertByteArr(values, length);

    m_size += length;

    return *this;
}

Raw& Raw::pushBack(const std::vector<byte>& values, MutablePacket& packet)
{
    packet.insertByteArr(values.data(), values.size());

    m_size += values.size();

    return *this;
}

void Raw::setSize(byte4 size)
{
    m_size = size;
}

void Raw::addr(byte* address)
{
    m_data = address;
}

byte* Raw::addr() const
{
    return m_data;
}

ProvidedProtocols Raw::protType() const
{
    return ProvidedProtocols::Raw;
}

size_t Raw::getSize() const
{
    return m_size;
}

std::ostream& operator<<(std::ostream& os, const Raw& raw)
{
    os << raw.addr() ;

    return os;
}
