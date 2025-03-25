#include "Packet.h"
#include <iomanip>

Packet::Packet() 
    : m_curSize(0)
{}

const byte* Packet::buffer() const
{
    return m_buffer;
}

const size_t Packet::size() const
{
    return m_curSize;
}

std::ostream& operator<<(std::ostream& os, Packet& packet)
{
    os << std::dec << "Packet [" << packet.m_curSize << "]" << std::endl;
    for (size_t i = 0; i < packet.m_curSize; i++)
    {
        os << std::setfill('0') << std::setw(2) << std::hex << (int)packet.m_buffer[i] << ' ';
    }
    os << std::dec;

    return os;
}
