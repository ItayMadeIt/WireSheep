#include "Packet.h"

Packet::Packet(std::unique_ptr<ProtocolNode> firstLayer)
    : m_head(std::move(firstLayer)), m_tail(m_head.get())
{

}

Protocol* Packet::operator[](const size_t index)
{
    ProtocolNode* cur = m_head.get();
    
    for (size_t i = 0; i < index; i++)
    {
        if (!cur->next())
        {
            return nullptr;
        }
        cur = cur->next();
    }

    return (Protocol*)cur;
}

Protocol* Packet::operator[](const AllProtocols protocolType)
{
    ProtocolNode& cur = *m_head.get();

    while (cur->getProtocol() != protocolType)
    {
        if (!cur.next())
        {
            return nullptr;
        }

        cur = *cur.next();
    }

    return cur.getSelf();
}

const std::vector<byte>& Packet::compile()
{
    ProtocolNode* cur = m_head.get();
    size_t packetSize = cur->getSelf()->getSize();
    while (cur->next())
    {
        cur = cur->next();
        packetSize += cur->getSelf()->getSize();
    }

    m_buffer.clear();
    m_buffer.reserve(packetSize);

    cur = m_head.get();
    size_t position = 0;

    // encode layer and go forward
    while (cur) 
    {
        Protocol* curProtocol = cur->getSelf();
        curProtocol->encodeLayer(m_buffer, position);

        position += curProtocol->getSize();
        if (!cur->next())
        {
            break;
        }

        cur = cur->next();
    }

    // cur holds last layer
    
    // encode layer and go backward
    while (cur)
    {
        Protocol* curProtocol = cur->getSelf();

        position -= curProtocol->getSize();

        if (curProtocol->includesChecksum())
        {
            curProtocol->calculateChecksum(m_buffer, position, cur->prev()->getSelf());
        }

        curProtocol->encodeLayerPost(m_buffer, position);

        if (!cur->prev())
        {
            break;
        }

        cur = cur->prev();
    }
        
    return m_buffer;
}

const std::vector<byte>& Packet::compileRaw()
{
    ProtocolNode* cur = m_head.get();
    size_t packetSize = cur->getSelf()->getSize();
    while (cur->next())
    {
        cur = cur->next();
        packetSize += cur->getSelf()->getSize();
    }

    m_buffer.clear();
    m_buffer.reserve(packetSize);

    cur = m_head.get();
    size_t position = 0;

    // encode layer and go forward
    while (cur)
    {
        Protocol* curProtocol = cur->getSelf();
        curProtocol->encodeLayerRaw(m_buffer, position);
        position += curProtocol->getSize();

        if (!cur->next())
        {
            break;
        }

        cur = cur->next();
    }

    // cur holds last layer

    // encode layer and go backward
    while (cur)
    {
        Protocol* curProtocol = cur->getSelf();

        position -= curProtocol->getSize();

        curProtocol->encodeLayerPostRaw(m_buffer, position);

        if (!cur->prev())
        {
            break;
        }

        cur = cur->prev();
    }

    return m_buffer;
}

Packet::operator std::vector<byte>() const
{
    return m_buffer;
}

Packet::operator const std::vector<byte>&() const
{
    return m_buffer;
}
