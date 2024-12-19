#include "Raw.h"

Raw::Raw() : Protocol(ProtocolTypes::Raw)
{

}

Raw& Raw::push_back(const byte value)
{
    m_data.push_back(value);

    return *this;
}

Raw& Raw::push_back(const byte* values, const size_t length)
{
    size_t lastSize = m_data.size();

    m_data.resize(m_data.size() + length);
    memcpy(m_data.data() + lastSize, values, length);

    return *this;
}

Raw& Raw::push_back(const std::vector<byte>& values)
{
    size_t lastSize = m_data.size();

    m_data.resize(m_data.size() + values.size());
    memcpy(m_data.data() + lastSize, values.data(), values.size());

    return *this;
}

void Raw::serializeArr(byte* ptr) const
{
    memcpy(ptr, m_data.data(), m_data.size());
}

void Raw::deserializeArr(const byte* ptr)
{
}

void Raw::serialize(std::vector<byte>& buffer) const
{
    // Reserve the size
    size_t size = getLayersSize();
    buffer.reserve(size);

    // Add ethernet data to the array
    buffer.resize(buffer.size() + getSize());
    serializeArr(buffer.data());

    // Continue to serialize the data for the following protocols
    if (m_nextProtocol)
    {
        m_nextProtocol->serialize(buffer, getSize());
    }
}

size_t Raw::getSize() const
{
    return m_data.size();
}

void Raw::serialize(std::vector<byte>& buffer, const size_t offset) const
{
    // Add data to the array
    buffer.resize(buffer.size() + getSize());
    serializeArr(buffer.data() + offset);

    // Continue to serialize the data for the following protocols
    if (m_nextProtocol)
    {
        m_nextProtocol->serialize(buffer, getSize());
    }
}
