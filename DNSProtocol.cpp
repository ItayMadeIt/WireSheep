#include "DNSProtocol.h"
#include "IPv4Protocol.h"

DomainBytes DNS::formatDomain(const std::string& domain)
{
    DomainBytes result{};
    size_t writeIndex = 0;

    size_t startIndex = 0;
    size_t endIndex;

    // Process each dot
    while ((endIndex = domain.find('.', startIndex)) != std::string::npos)
    {
        // Length of segment
        byte length = endIndex - startIndex;

        if (writeIndex + 1 + length >= MAX_DOMAIN_SIZE)
            throw std::runtime_error("Domain name too long");

        // write length
        result[writeIndex++] = static_cast<byte>(length);
        // write domain
        for (size_t i = 0; i < length; i++)
        {
            result[writeIndex++] = static_cast<byte>(domain[startIndex + i]);
        }

        startIndex = endIndex + 1;
    }
    
    size_t lastLength = domain.size() - startIndex;
    if (writeIndex + 1 + lastLength + 1 > MAX_DOMAIN_SIZE)
    {
        throw std::runtime_error("Domain name too long");
    }

    // write length
    result[writeIndex++] = static_cast<byte>(lastLength);

    // write domain
    for (size_t i = 0; i < lastLength; ++i)
    {
        result[writeIndex++] = static_cast<byte>(domain[startIndex + i]);
    }
    
    // null terminator
    result[writeIndex++] = 0;

    return result;
}


DNS::DNS() : Protocol(), m_flags(0)
{
}

DNS& DNS::addQuestion(const std::string& qAddr, const byte2 qType, const byte2 qClass)
{
    QuestionResourceRecord q{qAddr, qType, qClass };

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


void DNS::writeToBuffer(byte* buffer) const
{
    byte2 var;

    // Add values in the header: 
    var = Endianness::toNetwork(m_transcationID);
    std::memcpy(buffer, &var, sizeof(m_transcationID));
    buffer += sizeof(m_transcationID);

    var = Endianness::toNetwork(m_flags);
    std::memcpy(buffer, &var, sizeof(m_flags));
    buffer += sizeof(var);

    var = Endianness::toNetwork(static_cast<byte2>(m_questions.size()));
    std::memcpy(buffer, &var, sizeof(var));
    buffer += sizeof(var);

    var = Endianness::toNetwork(m_answers.size());
    std::memcpy(buffer, &var, sizeof(m_answers));
    buffer += sizeof(var);

    var = Endianness::toNetwork(m_authRR.size());
    std::memcpy(buffer, &var, sizeof(m_authRR));
    buffer += sizeof(var);

    var = Endianness::toNetwork(m_additionalRR.size());
    std::memcpy(buffer, &var, sizeof(m_additionalRR));
    buffer += sizeof(var);

    // Add the resource records

    for (const DNS::QuestionResourceRecord& q : m_questions)
    {
        // Copy the address
        std::memcpy(buffer, q.m_domain.data(), q.m_domain.size());
        buffer += q.m_domain.size();

        // Copy all other question data
        var = Endianness::toNetwork(q.m_type);
        std::memcpy(buffer, &var, sizeof(var));
        buffer += sizeof(var);

        var = Endianness::toNetwork(q.m_class);
        std::memcpy(buffer, &var, sizeof(var));
        buffer += sizeof(var);
    }
    
    for (const DNS::ResourceRecord& ans : m_answers)
    {
        encodeRecord(ans, buffer);
    }
    for (const DNS::ResourceRecord rr : m_authRR)
    {
        encodeRecord(rr, buffer);
    }
    for (const DNS::ResourceRecord rr : m_additionalRR)
    {
        encodeRecord(rr, buffer);
    }

}

void DNS::readFromBuffer(const byte* buffer, const size_t size)
{
    // Not implemented yet
}


size_t DNS::getSize() const
{
    size_t headerSize = sizeof(m_transcationID) + sizeof(m_flags) + sizeof(byte2) + sizeof(byte2) + sizeof(byte2) + sizeof(byte2);
    size_t payloadSize = 0;

    if (!(m_flags & (byte)DNS::FlagsIndices::QR))
    {
        for (const DNS::QuestionResourceRecord& q : m_questions)
        {
            payloadSize += (q.m_domain.size()) + sizeof(q.m_class) + sizeof(q.m_type);
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

void DNS::encodeLayerPre(std::vector<byte>& buffer, const size_t offset)
{
    // Set lengths
    m_questionLength = (byte2)m_questions.size();
    m_additionalLength = (byte2)m_additionalRR.size();
    m_authLength = (byte2)m_authRR.size();
    m_answerLength = (byte2)m_answers.size();

    // Add DNS data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);
}

void DNS::encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
{
    // Add DNS data to the array
    buffer.resize(buffer.size() + getSize());
    writeToBuffer(buffer.data() + offset);
}

void DNS::encodeRecord(const DNS::ResourceRecord& record, byte*& ptr) const
{
    byte2 val;
    std::memcpy(ptr, record.m_address.data(), record.m_address.size());
    ptr += record.m_address.size();

    val = Endianness::toNetwork(record.m_type);
    std::memcpy(ptr, &val, sizeof(val));
    ptr += sizeof(val);
    
    val = Endianness::toNetwork(record.m_class);
    std::memcpy(ptr, &val, sizeof(val));
    ptr += sizeof(val);

    val = Endianness::toNetwork(record.m_ttl);
    std::memcpy(ptr, &val, sizeof(val));
    ptr += sizeof(val);

    val = Endianness::toNetwork(static_cast<byte2>(record.m_rdata.size()));
    std::memcpy(ptr, &val, sizeof(val)); 
    ptr += sizeof(val);
    
    std::memcpy(ptr, record.m_rdata.data(), record.m_rdata.size());
    ptr += record.m_rdata.size();
}

DNS::ResourceRecord::ResourceRecord(const std::vector<byte>& address, const byte2 typeVal, const byte2 classVal, const byte4 ttlVal, const std::vector<byte>& rdata)
    : m_domain(address), m_type(typeVal), m_class(classVal), m_ttl(ttlVal), m_rdata(rdata)
{
}

DNS::QuestionResourceRecord::QuestionResourceRecord(const std::string& address, const byte2 typeVal, const byte2 classVal)
    : m_type(typeVal), m_class(classVal), m_domain(formatDomain(address))
{}
