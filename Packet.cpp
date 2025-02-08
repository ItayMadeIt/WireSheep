#include "Packet.h"

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
