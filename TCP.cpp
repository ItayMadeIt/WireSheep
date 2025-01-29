#include "TCP.h"
#include "EndianHandler.h"
#include "Ethernet.h"

void TCP::writeToBuffer(byte* ptr) const
{
    byte2 var2 = EndiannessHandler::toNetworkEndian(m_srcPort);
    std::memcpy(ptr, &var2, sizeof(var2));
    ptr += sizeof(var2);

    var2 = EndiannessHandler::toNetworkEndian(m_dstPort);
    std::memcpy(ptr, &var2, sizeof(var2));
    ptr += sizeof(var2);

    byte4 var4 = EndiannessHandler::toNetworkEndian(m_seqNum);
    std::memcpy(ptr, &var4, sizeof(var4));
    ptr += sizeof(var4);

    var4 = EndiannessHandler::toNetworkEndian(m_ackNum);
    std::memcpy(ptr, &var4, sizeof(var4));
    ptr += sizeof(var4);

    // only last four bits of data offset and 4 bits of reserved
    byte var1 = EndiannessHandler::toNetworkEndian((byte)((m_dataOffset << 4) | (m_reserved)));
    std::memcpy(ptr, &var1, sizeof(var1));
    ptr += sizeof(var1);

    var1 = EndiannessHandler::toNetworkEndian(m_flags);
    std::memcpy(ptr, &var1, sizeof(var1));
    ptr += sizeof(var1);

    var2 = EndiannessHandler::toNetworkEndian(m_window);
    std::memcpy(ptr, &var2, sizeof(var2));
    ptr += sizeof(var2);

    var2 = EndiannessHandler::toNetworkEndian(m_checksum);
    std::memcpy(ptr, &var2, sizeof(var2));
    ptr += sizeof(var2);

    var2 = EndiannessHandler::toNetworkEndian(m_urgentPtr);
    std::memcpy(ptr, &var2, sizeof(var2));
    ptr += sizeof(var2);
    
    for (const std::unique_ptr<OptionBase>& option : m_options)
    {
        option->encode(ptr);
        ptr += option->m_length;
    }
}

void TCP::readFromBuffer(const byte* buffer, const size_t size)
{
}


void TCP::calculateOptionsSize()
{
    m_optionsSize = 0;
    for (const auto& option : m_options)
    {
        m_optionsSize += option->BASE_LENGTH;
    }

    // allign to multiples of 4
    m_optionsSize = (m_optionsSize + 3) / 4;
}

size_t TCP::getSize() const
{
    return TCP::SIZE + m_optionsSize;
}

void TCP::encodeLayer(std::vector<byte>& buffer, const size_t offset)
{
    calculateOptionsSize();

    m_dataOffset = (TCP::SIZE + (m_optionsSize + 3)) / 4;
    m_checksum = 0;

    // Add TCP data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);

    // calculateChecksum(buffer);

    // Adds padding for the options
    addOptionsPadding(buffer.data() + offset + TCP::SIZE + m_optionsSize);
}

void TCP::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
    // Add TCP data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);

    // Adds padding for the options, (To disable should set m_optionSize to 0)
    addOptionsPadding(buffer.data() + offset + TCP::SIZE + m_optionsSize);
}

void TCP::addOptionsPadding(byte* ptr) const
{
    // If option size == 0, it's invalid, meaning no padding
    if (m_optionsSize == 0)
    {
        return;
    }

    byte2 paddingLength = (4 - m_optionsSize % 4);

    std::memset(ptr, 0, paddingLength);
}

TCP::TCP() : Protocol(AllProtocols::TCP),
        m_seqNum(0), m_ackNum(0),
        m_srcPort(0), m_dstPort(0),
        m_flags(0), m_reserved(0),
        m_window(0), m_urgentPtr(0),
        m_checksum(0), m_dataOffset(0),
        m_optionsSize(0)
{

}

TCP::TCP(const TCP& other) : Protocol(AllProtocols::TCP),
            m_seqNum(other.m_seqNum), m_ackNum(other.m_ackNum), 
            m_checksum(other.m_checksum), m_dataOffset(other.m_dataOffset), 
            m_srcPort(other.m_srcPort), m_dstPort(other.m_dstPort),
            m_flags(other.m_flags), m_reserved(other.m_reserved),
            m_window(other.m_window), m_urgentPtr(other.m_urgentPtr),
            m_optionsSize(other.m_optionsSize)
{
    for (const std::unique_ptr<OptionBase>& option : other.m_options)
    {
        m_options.emplace_back(option->clone());
    }
}

void TCP::calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol)
{
    if (!protocol)
    {
        // will throw exception
        return;
    }
    AllProtocols otherProtocol = protocol->getProtocol();
    if (otherProtocol == AllProtocols::IPv4)
    {
        // isn't implemented yet
    }
    else if (otherProtocol == AllProtocols::IPv6)
    {
        // isn't implemented yet
    }
    else
    {
        // Will throw exception
        return;
    }

    byte* tcpPtr = buffer.data() + offset;

    // isn't implemented yet
}

TCP& TCP::srcPort(const byte2 value)
{
    m_srcPort = value;

    return *this;
}

byte2 TCP::srcPort() const
{
    return m_srcPort;
}

TCP& TCP::dstPort(const byte2 value)
{
    m_dstPort = value;

    return *this;
}

byte2 TCP::dstPort() const
{
    return m_dstPort;
}

TCP& TCP::seqNum(const byte4 value)
{
    m_seqNum = value;

    return *this;
}

byte4 TCP::seqNum() const
{
    return m_seqNum;
}

TCP& TCP::ackNum(const byte4 value)
{
    m_ackNum = value;

    return *this;
}

byte4 TCP::ackNum() const
{
    return m_ackNum;
}

TCP& TCP::dataOffset(const byte value)
{
    m_dataOffset = value;

    return *this;
}

byte TCP::dataOffset() const
{
    return m_dataOffset;
}

TCP& TCP::reserved(const byte value)
{
    m_reserved = value;
    
    return *this;
}

byte TCP::reserved() const
{
    return m_reserved;
}

TCP& TCP::window(const byte2 value)
{
    m_window = value;

    return *this;
}

byte2 TCP::window() const
{
    return m_window;
}

TCP& TCP::checksum(const byte2 value)
{
    m_checksum = value;

    return *this;
}

byte2 TCP::checksum() const
{
    return m_checksum;
}

TCP& TCP::urgentPtr(const byte2 value)
{
    m_urgentPtr = value;

    return *this;
}

byte2 TCP::urgentPtr() const
{
    return m_urgentPtr;
}

TCP& TCP::flags(const byte value)
{
    m_flags = value;

    return *this;
}

byte TCP::flags()
{
    return m_flags;
}





constexpr TCP::Flags operator|(TCP::Flags a, TCP::Flags b)
{
    using T = std::underlying_type_t<TCP::Flags>;
    return static_cast<TCP::Flags>(static_cast<T>(a) | static_cast<T>(b));
}

constexpr TCP::Flags operator&(TCP::Flags a, TCP::Flags b)
{
    using T = std::underlying_type_t<TCP::Flags>;
    return static_cast<TCP::Flags>(static_cast<T>(a) & static_cast<T>(b));
}

// OPTIONS

TCP::OptionBase::OptionBase(byte optionType, byte length)
    : m_optionType(optionType), m_length(length)
{}

void TCP::OptionBase::encode(byte* ptr) const
{
    // copy option header
    std::memcpy(ptr, &m_optionType, sizeof(m_optionType));
    ptr++;
    std::memcpy(ptr, &m_length, sizeof(m_length));
}

TCP::OptionEndList::OptionEndList() : 
    Option<OptionEndList>(OptionTypeValues::EndOfOptionList, OptionEndList::BASE_LENGTH)
{}

void TCP::OptionEndList::encode(byte * ptr) const
{
    std::memcpy(ptr, &m_optionType, sizeof(m_optionType));
}

TCP::OptionNoOperation::OptionNoOperation() : 
    TCP::Option<OptionNoOperation>(OptionTypeValues::NoOperation, OptionNoOperation::BASE_LENGTH)
{ }

void TCP::OptionNoOperation::encode(byte * ptr) const
{
    std::memcpy(ptr, &m_optionType, sizeof(m_optionType));
}

TCP::OptionMaxSegmentSize::OptionMaxSegmentSize(const byte2 maxSegmentSize) :
    TCP::Option<OptionMaxSegmentSize>(OptionTypeValues::MaximumSegmentSize, OptionMaxSegmentSize::BASE_LENGTH),
    m_maxSegmentSize(maxSegmentSize)
{ }

void TCP::OptionMaxSegmentSize::encode(byte* ptr) const
{
    Option::encode(ptr);
    ptr += Option::BASE_LENGTH;

    byte2 val = EndiannessHandler::toNetworkEndian(m_maxSegmentSize);
    std::memcpy(ptr, &val, sizeof(val));
}

TCP::OptionWindowScale::OptionWindowScale(const byte windowScale) : 
    TCP::Option<OptionWindowScale>(OptionTypeValues::WindowScale, OptionWindowScale::BASE_LENGTH),
    m_windowScale(windowScale)
{ }

void TCP::OptionWindowScale::encode(byte * ptr) const
{
    Option::encode(ptr);
    ptr += Option::BASE_LENGTH;

    std::memcpy(ptr, &m_windowScale, sizeof(m_windowScale));
}


TCP::OptionSelectiveAckPermitted::OptionSelectiveAckPermitted() :
    TCP::Option<OptionSelectiveAckPermitted>(OptionTypeValues::SelectiveAckPermitted, OptionSelectiveAckPermitted::BASE_LENGTH)
{ }
