#include "DNS.h"

std::vector<byte> DNS::formatDomain(const std::string& domain)
{
     std::vector<byte> address;

    size_t startIndex = 0;
    size_t endIndex;

    // Process each dot
    while ((endIndex = domain.find('.', startIndex)) != std::string::npos)
    {
        // Get length of the section
        size_t length = endIndex - startIndex;

        // Add number for the amount of chars
        address.emplace_back(static_cast<byte>(length));

        // Add the segment data
        const std::string segment = domain.substr(startIndex, length);
        address.insert(address.end(), segment.begin(), segment.end());

        // Move startIndex to the character after the dot
        startIndex = endIndex + 1;
    }

    // Handle the last segment
    size_t lastLength = domain.size() - startIndex;
    address.emplace_back(static_cast<byte>(lastLength));

    if (lastLength > 0)
    {
        const std::string lastSegment = domain.substr(startIndex, lastLength);
        address.insert(address.end(), lastSegment.begin(), lastSegment.end());
    }

    // Add null terminator
    address.emplace_back('\0');

    return address;
}


DNS::DNS() : Protocol(AllProtocols::DNS), m_flags(0)
{
}

DNS& DNS::addQuestion(const std::string& qAddr, const byte2 qType, const byte2 qClass)
{
    m_questions.emplace_back(DNS::formatDomain(qAddr), qType, qClass);

    return *this;
}

DNS::QuestionResourceRecord DNS::getQuestionResponse(const size_t index)
{
    return m_questions[index];
}

DNS& DNS::popQuestion()
{
    m_questions.pop_back();

    return *this;
}

DNS& DNS::addAnswer(const std::string& aAddr, const byte2 aType, const byte2 aClass, const byte4 aTtl, const std::vector<byte>& aData)
{
    m_answers.emplace_back(DNS::formatDomain(aAddr), aType, aClass, aTtl, aData);

    return *this;
}

DNS::ResourceRecord DNS::getAnswerResponse(const size_t index)
{
    return m_answers[index];
}

DNS& DNS::popAnswer()
{
    m_answers.pop_back();

    return *this;
}

DNS& DNS::addAuthResponse(const std::string& arAddr, const byte2 arType, const byte2 arClass, const byte4 arTtl, const std::vector<byte>& arData)
{
    m_authRR.emplace_back(DNS::formatDomain(arAddr), arType, arClass, arTtl, arData);

    return *this;
}

DNS::ResourceRecord DNS::getAuthResponse(const size_t index)
{
    return m_authRR[index];
}

DNS& DNS::popAuthResponse()
{
    m_authRR.pop_back();

    return *this;
}

DNS& DNS::addAdditionalResponse(const std::string& arAddr, const byte2 arType, const byte2 arClass, const byte4 arTtl, const std::vector<byte>& arData)
{
    m_additionalRR.emplace_back(DNS::formatDomain(arAddr), arType, arClass, arTtl, arData);

    return *this;
}

DNS::ResourceRecord DNS::getAdditionalResponse(const size_t index)
{
    return m_additionalRR[index];
}

DNS& DNS::popAdditionalResponse()
{
    m_additionalRR.pop_back();

    return *this;
}

DNS& DNS::flags(byte2 newFlags)
{
    m_flags = newFlags;

    return *this;
}

DNS& DNS::flags(FlagsIndices newFlags)
{
    m_flags = (byte2)newFlags;

    return *this;
}

byte2 DNS::flags()
{
    return m_flags;
}

DNS& DNS::setQuestionLength(const byte2 value)
{
    m_questionLength = value;

    return *this;
}

DNS& DNS::setAnswersLength(const byte2 value)
{
    m_answerLength = value;

    return *this;
}

DNS& DNS::setAuthRRLength(const byte2 value)
{
    m_authLength = value;

    return *this;
}

DNS& DNS::setAdditionalRRLength(const byte2 value)
{
    m_additionalLength = value;

    return *this;
}

void DNS::serializeArr(byte* ptr) const
{
    byte2 var;

    // Add values in the header: 
    var = EndiannessHandler::toNetworkEndian(m_transcationID);
    std::memcpy(ptr, &var, sizeof(m_transcationID));
    ptr += sizeof(m_transcationID);

    var = EndiannessHandler::toNetworkEndian(m_flags);
    std::memcpy(ptr, &var, sizeof(m_flags));
    ptr += sizeof(var);

    var = EndiannessHandler::toNetworkEndian(static_cast<byte2>(m_questions.size()));
    std::memcpy(ptr, &var, sizeof(var));
    ptr += sizeof(var);

    var = EndiannessHandler::toNetworkEndian(m_answers.size());
    std::memcpy(ptr, &var, sizeof(m_answers));
    ptr += sizeof(var);

    var = EndiannessHandler::toNetworkEndian(m_authRR.size());
    std::memcpy(ptr, &var, sizeof(m_authRR));
    ptr += sizeof(var);

    var = EndiannessHandler::toNetworkEndian(m_additionalRR.size());
    std::memcpy(ptr, &var, sizeof(m_additionalRR));
    ptr += sizeof(var);

    // Add the resource records

    for (const DNS::QuestionResourceRecord& q : m_questions)
    {
        // Copy the address
        std::memcpy(ptr, q.m_address.data(), q.m_address.size());
        ptr += q.m_address.size();

        // Copy all other question data
        var = EndiannessHandler::toNetworkEndian(q.m_type);
        std::memcpy(ptr, &var, sizeof(var));
        ptr += sizeof(var);

        var = EndiannessHandler::toNetworkEndian(q.m_class);
        std::memcpy(ptr, &var, sizeof(var));
        ptr += sizeof(var);
    }
    
    for (const DNS::ResourceRecord& ans : m_answers)
    {
        serializeArrRecord(ans, ptr);
    }
    for (const DNS::ResourceRecord rr : m_authRR)
    {
        serializeArrRecord(rr, ptr);
    }
    for (const DNS::ResourceRecord rr : m_additionalRR)
    {
        serializeArrRecord(rr, ptr);
    }

}

void DNS::deserializeArr(const byte* ptr)
{
}

void DNS::serialize(std::vector<byte>& buffer)
{
    // Reserve the size
    size_t size = getLayersSize();
    buffer.reserve(size);

    // Add ethernet data to the array
    buffer.resize(buffer.size() + getSize());
    serializeArr(buffer.data());

    // Specific to DNS
    // Set lengths
    m_questionLength = (byte2)m_questions.size();
    m_additionalLength = (byte2)m_additionalRR.size();
    m_authLength = (byte2)m_authRR.size();
    m_answerLength = (byte2)m_answers.size();


    // Continue to serialize the data for the following protocols
    if (m_nextProtocol)
    {
        m_nextProtocol->serialize(buffer, getSize());
    }
}

void DNS::serializeRaw(std::vector<byte>& buffer) const
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
        m_nextProtocol->serializeRaw(buffer, getSize());
    }
}

size_t DNS::getSize() const
{
    size_t headerSize = sizeof(m_transcationID) + sizeof(m_flags) + sizeof(byte2) + sizeof(byte2) + sizeof(byte2) + sizeof(byte2);
    size_t payloadSize = 0;

    if (!(m_flags & (byte)DNS::FlagsIndices::QR))
    {
        for (const DNS::QuestionResourceRecord& q : m_questions)
        {
            payloadSize += (q.m_address.size()) + sizeof(q.m_class) + sizeof(q.m_type);
        }
    }
    // If it's a responses
    else
    {
        for (const DNS::ResourceRecord& ans : m_answers)
        {
            payloadSize += (ans.m_address.size()) + sizeof(ans.m_type) + sizeof(ans.m_class) + 
                sizeof(ans.m_ttl) + sizeof(byte2) + ans.m_rdata.size();
        }

        for (const DNS::ResourceRecord rr : m_authRR)
        {
            payloadSize += (rr.m_address.size()) + sizeof(rr.m_type) + sizeof(rr.m_class) + 
                sizeof(rr.m_ttl) + sizeof(byte2) + rr.m_rdata.size();
        }

        for (const DNS::ResourceRecord rr : m_additionalRR)
        {
            payloadSize += (rr.m_address.size()) + sizeof(rr.m_type) + sizeof(rr.m_class) + 
                sizeof(rr.m_ttl) + sizeof(byte2) + rr.m_rdata.size();
        }
    }

    return headerSize + payloadSize;
}

void DNS::serialize(std::vector<byte>& buffer, const size_t offset)
{
    // Get the amount of bytes we have left to input
    size_t bytesAmount = buffer.capacity() - buffer.size();

    // Add ipv4 data to the array
    buffer.resize(buffer.size() + getSize());
    serializeArr(buffer.data() + offset);

    // Specific to DNS
    // Set lengths
    m_questionLength = (byte2)m_questions.size();
    m_additionalLength = (byte2)m_additionalRR.size();
    m_authLength = (byte2)m_authRR.size();
    m_answerLength = (byte2)m_answers.size();

    // Continue to serialize the data for the following protocols
    if (m_nextProtocol)
    {
        m_nextProtocol->serialize(buffer, offset + getSize());
    }
}

void DNS::serializeRaw(std::vector<byte>& buffer, const size_t offset) const
{
    // Add ipv4 data to the array
    buffer.resize(buffer.size() + getSize());
    serializeArr(buffer.data() + offset);

    // Continue to serialize the data for the following protocols
    if (m_nextProtocol)
    {
        m_nextProtocol->serializeRaw(buffer, offset + getSize());
    }
}

void DNS::serializeArrRecord(const DNS::ResourceRecord& record, byte*& ptr) const
{
    byte2 val;
    std::memcpy(ptr, record.m_address.data(), record.m_address.size());
    ptr += record.m_address.size();

    val = EndiannessHandler::toNetworkEndian(record.m_type);
    std::memcpy(ptr, &val, sizeof(val));
    ptr += sizeof(val);
    
    val = EndiannessHandler::toNetworkEndian(record.m_class);
    std::memcpy(ptr, &val, sizeof(val));
    ptr += sizeof(val);


    val = EndiannessHandler::toNetworkEndian(record.m_ttl);
    std::memcpy(ptr, &val, sizeof(val));
    ptr += sizeof(val);

    val = EndiannessHandler::toNetworkEndian(static_cast<byte2>(record.m_rdata.size()));
    std::memcpy(ptr, &val, sizeof(val)); 
    ptr += sizeof(val);
    
    std::memcpy(ptr, record.m_rdata.data(), record.m_rdata.size());
    ptr += record.m_rdata.size();
}

DNS::ResourceRecord::ResourceRecord(const std::vector<byte>& address, const byte2 typeVal, const byte2 classVal, const byte4 ttlVal, const std::vector<byte>& rdata)
    : m_address(address), m_type(typeVal), m_class(classVal), m_ttl(ttlVal), m_rdata(rdata)
{
}

DNS::QuestionResourceRecord::QuestionResourceRecord(const std::vector<byte>& address, const byte2 typeVal, const byte2 classVal)
    : m_address(address), m_type(typeVal), m_class(classVal)
{
}
