#include "Raw.h"

Raw::Raw() : Protocol(AllProtocols::Raw)
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

void Raw::writeToBuffer(byte* buffer) const
{
    memcpy(buffer, m_data.data(), m_data.size());
}

void Raw::readFromBuffer(const byte* buffer, const size_t size)
{
}

void Raw::encodeLayer(std::vector<byte>& buffer, const size_t offset)
{
    // Add data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);
}

void Raw::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
    // Add data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);
}

size_t Raw::getSize() const
{
    return m_data.size();
}