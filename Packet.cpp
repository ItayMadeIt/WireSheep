#include "Packet.h"

Packet::Packet(std::unique_ptr<Protocol> firstLayer) 
    : m_firstLayer(std::move(firstLayer))
{ }

Protocol* Packet::getFirstLayer() const
{
    return m_firstLayer.get();
}

Protocol* Packet::operator[](size_t index)
{
    Protocol* cur = m_firstLayer.get();
    for (size_t i = 0; i < index; i++)
    {
        cur = cur->getNextProtocol();
    }
    return cur;
}

Protocol* Packet::operator[](ProtocolTypes protocolType)
{
    Protocol* cur = m_firstLayer.get();

    // Until the protocol is the same 
    while (cur->getProtocol() != protocolType)
    {
        // Next
        cur = cur->getNextProtocol();
        
        // If next is null, no protocol with `protocolType` was found
        if (!cur)
        {
            return nullptr;
        }
    }
    return cur;
}

const std::vector<byte>& Packet::compile()
{
    m_firstLayer->serialize(m_bytes);

    return m_bytes;
}

const std::vector<byte>& Packet::compileRaw()
{
    m_firstLayer->serializeRaw(m_bytes);

    return m_bytes;
}

Packet::operator std::vector<byte>() const
{
    return m_bytes;
}

Packet::operator const std::vector<byte>&() const
{
    return m_bytes;
}
