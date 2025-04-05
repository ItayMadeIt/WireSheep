#include "DNSProtocol.h"
#include "IPv4Protocol.h"

DomainBytes DNS::formatDomain(const std::string& domain)
{
    DomainBytes result;
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

    result.resize(writeIndex);

    return result;
}

DomainBytes DNS::formatDomain(const char* domain)
{
    DomainBytes result;
    size_t writeIndex = 0;

    const char* start = domain;
    const char* end = domain;

    while (*end != '\0')
    {
        if (*end == '.')
        {
            size_t length = end - start;
            if (writeIndex + 1 + length >= MAX_DOMAIN_SIZE)
            {
                throw std::runtime_error("Domain name too long");
            }

            result[writeIndex++] = static_cast<byte>(length);
            for (size_t i = 0; i < length; ++i)
            {
                result[writeIndex++] = static_cast<byte>(start[i]);
            }

            start = end + 1;
        }
        ++end;
    }

    size_t lastLength = end - start;
    if (writeIndex + 1 + lastLength + 1 > MAX_DOMAIN_SIZE)
    {
        throw std::runtime_error("Domain name too long");
    }


    result[writeIndex++] = static_cast<byte>(lastLength);
    for (size_t i = 0; i < lastLength; ++i)
    {
        result[writeIndex++] = static_cast<byte>(start[i]);
    }


    result[writeIndex++] = 0; 
    result.resize(writeIndex);
    return result;


}

DomainBytes DNS::consumeDomain(const byte* ptr) const
{
    DomainBytes result;

    if (*ptr != 0)
    {
        byte2 signature = Endianness::fromNetwork(*reinterpret_cast<const byte2*>(ptr));
        if ((signature & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000)
        {
            byte* domainAddr = addr() + (signature & 0b0011'1111'1111'1111);
            return consumeDomain(domainAddr);
        }
    }

    byte2 index = 0;
    while (ptr[index] != '\0')
    {
        result[index] = ptr[index];
        index++;
    }
    result[index++] = '\0';

    result.resize(index);

    return result;
}

DomainBytes DNS::decodeDomain(const DomainBytes& dnsDomain)
{
    DomainBytes result;

    const byte* ptr = dnsDomain.begin();
    const byte* end = dnsDomain.end();

    while (ptr < end && *ptr != 0)
    {
        byte len = *ptr;
        ++ptr;

        if (ptr + len > end)
        {
            break;
        }

        if (!result.empty())
        {
            result.push_back('.');
        }

        result.insert(ptr, len);

        ptr += len;
    }

    result.push_back('\0');

    return result;
}

DNS::DNS(byte* data)
    : m_data(reinterpret_cast<DNSHeader*>(data))
{
    m_questionsEndLoc = BASE_SIZE;
    m_answersEndLoc = BASE_SIZE;
    m_authRREndLoc = BASE_SIZE;
    m_additionalRREndLoc = BASE_SIZE;
}

DNS& DNS::transactionID(const byte2 value)
{
    m_data->transactionID = Endianness::toNetwork(value);

    return *this;
}

byte2 DNS::transactionID() const
{
    return Endianness::fromNetwork(m_data->transactionID);
}

DNS& DNS::addQuestion(MutablePacket& packet, const DomainBytes& qAddr, byte2 qType, byte2 qClass)
{
    questionLength(questionLength() + 1);

    qType = Endianness::toNetwork(qType);
    qClass = Endianness::toNetwork(qClass);

    QuestionResourceRecord record(qAddr, qType, qClass);
    
    packet.shiftFromAddr(
        reinterpret_cast<byte*>(m_data) + m_questionsEndLoc, 
        record.m_domain.size() + sizeof(record.m_type) + sizeof(record.m_class)
    );

    std::memcpy(addr() + m_questionsEndLoc, record.m_domain.begin(), record.m_domain.size());
    m_questionsEndLoc += record.m_domain.size();

    std::memcpy(addr() + m_questionsEndLoc, &record.m_type, sizeof(record.m_type));
    m_questionsEndLoc += sizeof(record.m_type);

    std::memcpy(addr() + m_questionsEndLoc, &record.m_class, sizeof(record.m_class));
    m_questionsEndLoc += sizeof(record.m_class);

    return *this;
}

DNS::QuestionResourceRecord DNS::getQuestionResponse(const size_t index) const
{
    // ptr to questions begin
    byte* ptr = reinterpret_cast<byte*>(m_data) + BASE_SIZE; 

    byte2 specialDomain = 0;

    for (size_t i = 0; i < index; i++)
    {
        byte2 firstBytes = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));

        if ((firstBytes & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000) // compressed
        {
            specialDomain = firstBytes;
            ptr += 2;
        }
        else
        {
            while (*ptr)
            {
                byte len = *ptr;
                ptr += len + 1;
            }
            ptr++;
        }

        ptr += 2 + 2 + 4;

        byte2 rdlength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
        ptr += 2 + rdlength;
    }

    DomainBytes domain = consumeDomain(ptr);

    byte2 firstBytes = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    if ((firstBytes & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000) // compressed
    {
        ptr += sizeof(byte2);
    }
    else
    {
        ptr += domain.size();
    }


    byte2 netType = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(netType);

    byte2 netClass = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));


     return QuestionResourceRecord(
        domain,
        netType,
        netClass
    );
}

DNS& DNS::addAnswer(MutablePacket& packet, const DomainBytes& aAddr, byte2 aType, byte2 aClass, byte4 aTtl, const RDataBytes& aData)
{
    answersLength(answersLength() + 1);

    aType = Endianness::toNetwork(aType);
    aClass = Endianness::toNetwork(aClass);
    aTtl = Endianness::toNetwork(aTtl);
    byte2 rdataSize = Endianness::toNetwork(static_cast<byte2>(aData.size()));

    ResourceRecord record(aAddr, aType, aClass, aTtl, aData);

    packet.shiftFromAddr(
        reinterpret_cast<byte*>(m_data) + m_answersEndLoc,
        record.m_domain.size() + sizeof(record.m_type) + sizeof(record.m_class) + sizeof(record.m_ttl) + sizeof(byte2) + record.m_rdata.size()
    );


    std::memcpy(addr() + m_answersEndLoc, record.m_domain.begin(), record.m_domain.size());
    m_answersEndLoc += record.m_domain.size();

    std::memcpy(addr() + m_answersEndLoc, &record.m_type, sizeof(record.m_type));
    m_answersEndLoc += sizeof(record.m_type);

    std::memcpy(addr() + m_answersEndLoc, &record.m_class, sizeof(record.m_class));
    m_answersEndLoc += sizeof(record.m_class);

    std::memcpy(addr() + m_answersEndLoc, &record.m_ttl, sizeof(record.m_ttl));
    m_answersEndLoc += sizeof(record.m_ttl);

    std::memcpy(addr() + m_answersEndLoc, &rdataSize, sizeof(rdataSize));
    m_answersEndLoc += sizeof(rdataSize);

    std::memcpy(addr() + m_answersEndLoc, aData.begin(), rdataSize);
    m_answersEndLoc += sizeof(rdataSize);
    return *this;
}

DNS::ResourceRecord DNS::getAnswerResponse(const size_t index)const
{
    // ptr to questions begin
    byte* ptr = reinterpret_cast<byte*>(m_data) + m_questionsEndLoc;

    byte2 specialDomain = 0;

    for (size_t i = 0; i < index; i++)
    {
        byte2 firstBytes = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
        
        if ((firstBytes & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000) // compressed
        {
            specialDomain = firstBytes;
            ptr += 2;
        }
        else
        {
            while (*ptr)
            {
                byte len = *ptr;
                ptr += len + 1;
            }
            ptr++;
        }

        ptr += 2 + 2 + 4;

        byte2 rdlength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
        ptr += 2 + rdlength;
    }

    DomainBytes domain = consumeDomain(ptr);

    byte2 firstBytes = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    if ((firstBytes & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000) // compressed
    {
        ptr += sizeof(byte2);
    }
    else
    {
        ptr += domain.size();
    }

    byte2 netType = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(netType);

    byte2 netClass = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(netClass);

    byte4 netTtl = Endianness::fromNetwork(*reinterpret_cast<byte4*>(ptr));
    ptr += sizeof(netTtl);

    byte2 rdataLength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    // limit that to MAX_RDATA_SIZE
    if (rdataLength > MAX_RDATA_SIZE)
    {
        rdataLength = MAX_RDATA_SIZE;
    }
    ptr += sizeof(rdataLength);

    RDataBytes rdata{ ptr, ptr + rdataLength };

    return ResourceRecord(
        domain,
        netType,
        netClass,
        netTtl,
        rdata
    );
}

DNS& DNS::addAuthResponse(MutablePacket& packet, const DomainBytes& aAddr, byte2 aType, byte2 aClass, byte4 aTtl, const RDataBytes& aData)
{
    authRRLength(authRRLength() + 1);

    aType = Endianness::toNetwork(aType);
    aClass = Endianness::toNetwork(aClass);
    aTtl = Endianness::toNetwork(aTtl);
    byte2 rdataSize = Endianness::toNetwork(static_cast<byte2>(aData.size()));

    ResourceRecord record(aAddr, aType, aClass, aTtl, aData);

    packet.shiftFromAddr(
        reinterpret_cast<byte*>(m_data) + m_authRREndLoc,
        record.m_domain.size() + sizeof(record.m_type) + sizeof(record.m_class) + sizeof(record.m_ttl) + record.m_rdata.size()
    );

    std::memcpy(addr() + m_authRREndLoc, record.m_domain.begin(), record.m_domain.size());
    m_authRREndLoc += record.m_domain.size();

    std::memcpy(addr() + m_authRREndLoc, &record.m_type, sizeof(record.m_type));
    m_authRREndLoc += sizeof(record.m_type);

    std::memcpy(addr() + m_authRREndLoc, &record.m_class, sizeof(record.m_class));
    m_authRREndLoc += sizeof(record.m_class);

    std::memcpy(addr() + m_authRREndLoc, &record.m_ttl, sizeof(record.m_ttl));
    m_authRREndLoc += sizeof(record.m_ttl);

    std::memcpy(addr() + m_authRREndLoc, &rdataSize, sizeof(rdataSize));
    m_authRREndLoc += sizeof(rdataSize);

    std::memcpy(addr() + m_authRREndLoc, aData.begin(), rdataSize);
    m_authRREndLoc += sizeof(rdataSize);
    return *this;
}

DNS::ResourceRecord DNS::getAuthResponse(const size_t index) const
{
    // ptr to auth begin
    byte* ptr = reinterpret_cast<byte*>(m_data) + m_answersEndLoc;

    for (size_t i = 0; i < index; i++)
    {
        if ((Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr)) & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000) // compressed
        {
            ptr += 2;
        }
        else
        {
            while (*ptr)
            {
                byte len = *ptr;
                ptr += len + 1;
            }
            ptr++;
        }

        ptr += 2 + 2 + 4;

        byte2 rdlength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
        ptr += 2 + rdlength;
    }


    DomainBytes domain = consumeDomain(ptr);
    ptr += domain.size();

    byte2 netType = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(netType);

    byte2 netClass = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(netClass);

    byte4 netTtl = Endianness::fromNetwork(*reinterpret_cast<byte4*>(ptr));
    ptr += sizeof(netTtl);

    byte2 rdataLength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(rdataLength);

    RDataBytes rdata{ ptr, ptr + rdataLength };

    return ResourceRecord(
        domain,
        netType,
        netClass,
        netTtl,
        rdata
    );

}

DNS& DNS::addAdditionalResponse(MutablePacket& packet, const DomainBytes& aAddr, byte2 aType, byte2 aClass, byte4 aTtl, const RDataBytes& aData)
{
    additionalRRLength(additionalRRLength() + 1);

    aType = Endianness::toNetwork(aType);
    aClass = Endianness::toNetwork(aClass);
    aTtl = Endianness::toNetwork(aTtl);
    byte2 rdataSize = Endianness::toNetwork(static_cast<byte2>(aData.size()));

    ResourceRecord record(aAddr, aType, aClass, aTtl, aData);

    packet.shiftFromAddr(
        reinterpret_cast<byte*>(m_data) + m_additionalRREndLoc,
        record.m_domain.size() + sizeof(record.m_type) + sizeof(record.m_class) + sizeof(record.m_ttl) + record.m_rdata.size()
    );

    std::memcpy(addr() + m_additionalRREndLoc, record.m_domain.begin(), record.m_domain.size());
    m_additionalRREndLoc += record.m_domain.size();

    std::memcpy(addr() + m_additionalRREndLoc, &record.m_type, sizeof(record.m_type));
    m_additionalRREndLoc += sizeof(record.m_type);

    std::memcpy(addr() + m_additionalRREndLoc, &record.m_class, sizeof(record.m_class));
    m_additionalRREndLoc += sizeof(record.m_class);

    std::memcpy(addr() + m_additionalRREndLoc, &record.m_ttl, sizeof(record.m_ttl));
    m_additionalRREndLoc += sizeof(record.m_ttl);

    std::memcpy(addr() + m_additionalRREndLoc, &rdataSize, sizeof(rdataSize));
    m_additionalRREndLoc += sizeof(rdataSize);

    std::memcpy(addr() + m_additionalRREndLoc, aData.begin(), rdataSize);
    m_additionalRREndLoc += sizeof(rdataSize);

    return *this;
}

DNS::ResourceRecord DNS::getAdditionalResponse(const size_t index) const
{
    // ptr to additional answers begin
    byte* ptr = reinterpret_cast<byte*>(m_data) + m_authRREndLoc;
    
    for (size_t i = 0; i < index; i++)
    {
        if ((Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr)) & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000) // compressed
        {
            ptr += 2;
        }
        else
        {
            while (*ptr)
            {
                byte len = *ptr;
                ptr += len + 1;
            }
            ptr++;
        }

        ptr += 2 + 2 + 4;

        byte2 rdlength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
        ptr += 2 + rdlength;
    }

    DomainBytes domain = consumeDomain(ptr);
    ptr += domain.size();

    byte2 netType = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(netType);

    byte2 netClass = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(netClass);

    byte4 netTtl = Endianness::fromNetwork(*reinterpret_cast<byte4*>(ptr));
    ptr += sizeof(netTtl);

    byte2 rdataLength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += sizeof(rdataLength);

    RDataBytes rdata{ ptr, ptr + rdataLength };

    return ResourceRecord(
        domain,
        netType,
        netClass,
        netTtl,
        rdata
    );
}

DNS& DNS::flags(byte2 newFlags)
{
    m_data->flags = Endianness::toNetwork(newFlags);

    return *this;
}

DNS& DNS::flags(FlagsIndices newFlags)
{
    return flags((byte2)newFlags);
}

byte2 DNS::flags()
{
    return Endianness::toNetwork(m_data->flags);
}

DNS& DNS::questionLength(const byte2 value)
{
    m_data->questionsLength = Endianness::toNetwork(value);

    return *this;
}

byte2 DNS::questionLength() const
{
    return Endianness::fromNetwork(m_data->questionsLength);
}

DNS& DNS::answersLength(const byte2 value)
{
    m_data->answerLength = Endianness::toNetwork(value);;

    return *this;
}

byte2 DNS::answersLength() const
{
    return Endianness::fromNetwork(m_data->answerLength);
}

DNS& DNS::authRRLength(const byte2 value)
{
    m_data->authoritiveRRLength = Endianness::toNetwork(value);;

    return *this;
}

byte2 DNS::authRRLength() const
{
    return Endianness::fromNetwork(m_data->authoritiveRRLength);
}

DNS& DNS::additionalRRLength(const byte2 value)
{
    m_data->additionalRRLength = Endianness::toNetwork(value);;

    return *this;
}

byte2 DNS::additionalRRLength() const
{
    return Endianness::fromNetwork(m_data->additionalRRLength);
}

size_t DNS::getSize() const
{
    return m_additionalRREndLoc;
}

void DNS::addr(byte* address)
{
    m_data = reinterpret_cast<DNSHeader*>(address);
}

byte* DNS::addr() const
{
    return reinterpret_cast<byte*>(m_data);
}

ProvidedProtocols DNS::protType() const
{
    return ID;
}

bool DNS::syncFields(byte4 remainingSize)
{
    if (remainingSize < DNS::BASE_SIZE)
    {
        return false;
    }

    if (remainingSize == DNS::BASE_SIZE)
    {
        return (
            questionLength() == 0 &&
            answersLength() == 0 &&
            authRRLength() == 0 &&
            additionalRRLength() == 0
        );
    }

    byte* ptr = (byte*)m_data + BASE_SIZE;

    // Go over questions
    byte2 questions = questionLength();
    if (!processQuestions(ptr, questions, remainingSize))
    {
        return false;
    }

    m_questionsEndLoc = static_cast<byte2>(ptr - addr());

    auto skipResourceRecord = [&](byte4 remainingSize) -> bool {
        return processResourceRecord(ptr, remainingSize);
    };

    // Skip Answer Resource Records
    if (!skipRecords(answersLength(), skipResourceRecord, remainingSize))
        return false;

    m_answersEndLoc = static_cast<byte2>(ptr - addr());

    // Skip Authority Resource Records
    if (!skipRecords(authRRLength(), skipResourceRecord, remainingSize))
        return false;

    m_authRREndLoc = static_cast<byte2>(ptr - addr());

    // Skip Additional Resource Records
    if (!skipRecords(additionalRRLength(), skipResourceRecord, remainingSize))
        return false;

    m_additionalRREndLoc = static_cast<byte2>(ptr - addr());

    return true;
}
bool DNS::processQuestions(byte*& ptr, byte2 questionCount, byte4 remainingSize)
{
    bool nullDomainSeen = false; // Ensure no 2 null domains (root domain)

    for (byte4 count = 0; count < questionCount; count++)
    {
        size_t totalLength = 0;

        // Process each label in the domain name
        while (true)
        {
            byte labelLength = *ptr;
            ptr++;

            if (labelLength == 0)  // Root domain (null byte)
            {
                if (totalLength == 0 && nullDomainSeen)
                {
                    return false;  // Multiple root domains
                }
             
                nullDomainSeen = true;
                break;  // End of domain name
            }

            // Label length must be between 1 and 63
            if (labelLength < 1 || labelLength > 63)
            {
                return false;
            }

            totalLength += labelLength + 1;
            if (totalLength > 253)  // Total domain length must not exceed 253 characters
            {
                return false;
            }

            // Validate characters in the label
            for (byte4 i = 0; i < labelLength; i++)
            {
                if (ptr >= addr() + remainingSize)
                {
                    return false;  // Out of bounds
                }

                char ch = static_cast<char>(*ptr);

                // Only printable ASCII characters are allowed
                if (ch <= ' ' || ch > '~')
                {
                    return false;
                }

                ++ptr;
            }
        }

        // Skip the question type and class (2 bytes each)
        ptr += sizeof(byte2) + sizeof(byte2);

        if (ptr > addr() + remainingSize)
        {
            return false;
        }
    }

    return true;
}

bool DNS::processResourceRecord(byte*& ptr, byte4 remainingSize)
{
    // Check for compressed name (0xC0)
    if ((Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr)) & 0b1100'0000'0000'0000) == 0b1100'0000'0000'0000)
    {
        ptr += 2;  // Jump over compression pointer
        if (ptr > addr() + remainingSize)
        {
            return false;
        }
    }
    else
    {
        while (true)
        {
            byte labelLength = *ptr;
            ptr++;

            if (labelLength == 0)  // Root domain (null byte)
            {
                break;  // End of domain name
            }

            // Validate label length
            if (labelLength < 1 || labelLength > 63)
            {
                return false;
            }

            for (byte4 i = 0; i < labelLength; i++)
            {
                if (ptr >= addr() + remainingSize)
                {
                    return false;
                }

                char ch = static_cast<char>(*ptr++);

                // Only printable ASCII characters are allowed
                if (ch <= ' ' || ch > '~')
                {
                    return false;
                }
            }
        }
    }

    // Skip RR type, class, TTL, and RDlength (as per RFC)
    ptr += 2 + 2 + 4;

    if (ptr > addr() + remainingSize)
    {
        return false;
    }

    byte2 rdlength = Endianness::fromNetwork(*reinterpret_cast<byte2*>(ptr));
    ptr += 2 + rdlength;

    return (ptr <= addr() + remainingSize);  // Ensure we stay within bounds
}

bool DNS::skipRecords(byte2 recordCount, std::function<bool(byte4)> skipFunc, byte4 remainingSize)
{
    for (size_t i = 0; i < recordCount; ++i)
    {
        if (!skipFunc(remainingSize))
        {
            return false;
        }
    }
    return true;
}

DNS::ResourceRecord::ResourceRecord(const DomainBytes& address, const byte2 typeVal, const byte2 classVal, const byte4 ttlVal, const RDataBytes& rdata)
    : m_domain(address), m_type(typeVal), m_class(classVal), m_ttl(ttlVal), m_rdata(rdata)
{
}

DNS::QuestionResourceRecord::QuestionResourceRecord(const std::string& address, const byte2 typeVal, const byte2 classVal)
    : m_domain(formatDomain(address)), m_type(typeVal), m_class(classVal)
{}

DNS::QuestionResourceRecord::QuestionResourceRecord(const DomainBytes & domain, const byte2 typeVal, const byte2 classVal)
    : m_domain(domain), m_type(typeVal), m_class(classVal)
{}

std::ostream& operator<<(std::ostream& os, const DNS::QuestionResourceRecord& q)
{
    DomainBytes domain = DNS::decodeDomain(q.m_domain);

    return os << "[Q] " << domain.c_str() <<
        "  Type: " << (q.m_type) <<
        "  Class: " << (q.m_class);
}

std::ostream& operator<<(std::ostream& os, const DNS::ResourceRecord& r)
{
    DomainBytes domain = DNS::decodeDomain(r.m_domain);

    os << "[RR] " << domain.c_str()
        << "  Type: " << (r.m_type)
        << "  Class: " << (r.m_class)
        << "  TTL: " << (r.m_ttl)
        << "  RDATA: ";
    os.write(r.m_rdata.c_str(), r.m_rdata.size());
    return os;
}

std::ostream& operator<<(std::ostream& os, const DNS& dns)
{
    os << "[DNS]" << std::endl;
    os << " - transaction ID: " << dns.transactionID() << std::endl;

    for (int i = 0; i < dns.questionLength(); ++i)
        os << "  " << dns.getQuestionResponse(i) << std::endl;

    for (int i = 0; i < dns.answersLength(); ++i)
        os << "  " << dns.getAnswerResponse(i) << std::endl;

    for (int i = 0; i < dns.authRRLength(); ++i)
        os << "  " << dns.getAuthResponse(i) << std::endl;

    for (int i = 0; i < dns.additionalRRLength(); ++i)
        os << "  " << dns.getAdditionalResponse(i) << std::endl;

    return os;
}
