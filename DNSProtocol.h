#pragma once
#include "Protocol.h"
#include "EndianHandler.h"
#include "StaticVector.hpp"
#include "DNSHeader.h"
#include <functional>

constexpr size_t MAX_RDATA_SIZE = 65535; // set 1024 bytes limit (mostly used for 1 IPv4 or similar)
constexpr size_t MAX_DOMAIN_SIZE = 256; // 253 is the limit
using RDataBytes = StaticVector<byte, MAX_RDATA_SIZE>;
using DomainBytes = StaticVector<byte, MAX_DOMAIN_SIZE>;

class DNS : public Protocol
{
public:

	enum class OpCodes : byte
	{
		Querty = 0,
		IQuery = 1,
		Status = 2,

		Notify = 4,
		Update = 5,
	};

	enum class FlagsIndices : byte
	{
		RCODE =  0,      // 4 bits (Response Code)
		CD =     4,      // 1 bit (Checking Disabled)
		AD =     5,      // 1 bit (Authentic Data)
		Z =      6,      // 1 bits (Zero (Reserved))
		RA =     7,      // 1 bit  (Recursion Available)
		RD =     8,      // 1 bit  (Recursion Desired)
		TC =     9,      // 1 bit  (TrunCation)
		AA =     10,     // 1 bit  (Authoritative Answer)
		OPCODE = 11,     // 4 bits (OPCODE)
		QR =     15,     // 1 bit  (Query/Response)
	};

	// Types: https://en.wikipedia.org/wiki/List_of_DNS_record_types
	// IT WASS A WASTE OF TIME
	enum class RRType : byte2
	{
		A = 1,
		NS = 2,
		CNAME = 5,
		SOA = 6,
		PTR = 12,
		HINFO = 13,
		MX = 15,
		TXT = 16,
		RP = 17,
		AFSDB = 18,
		SIG = 24,
		KEY = 25,
		AAAA = 28,
		LOC = 29,
		SRC = 33,
		NAPTR = 35,
		KX = 36,
		CERT = 37,
		DNAME = 39,
		APL = 42,
		DS = 43,
		SSHFP = 44,
		IPSECKEY = 45,
		RRSIG = 46,
		NSEC = 47,
		DNSKEY = 48,
		DHCID = 49,
		NSEC3 = 50,
		NSEC3PARAM = 51,
		TLSA = 52,
		SMINEA = 53,
		HIP = 55,
		CDS = 59,
		CDNSKEY = 60,
		OPENPGPKEY = 61,
		CSYNC = 62,
		ZONEMD = 63,
		SVCB = 64,
		HTTPS = 65,
		EUI48 = 108,
		EUI64 = 109,
		TKEY = 249,
		TSIG = 250,
		URI = 256,
		CAA = 257,
		TA = 32768,
		DLV = 32769,
	};

	// http://www.faqs.org/rfcs/rfc2929.html
	enum class RCode : byte2
	{
		NoError = 0,
		FormErr = 1,
		ServFail = 2,
		NXDomain = 3,
		NotImp = 4,
		Refused = 5,
		YXDomain = 6,
		YXRRSet = 7,
		NXRRSeet = 8,
		NotAuth = 9,
		NotZone = 10,

		BADVERS = 16,
		BADSIG = 16,
		BADKEY = 17,
		BADTIME = 18,
		BADMODE = 19,
		BADNAME = 20,
		BADALG = 21
	};
	
	// http://www.faqs.org/rfcs/rfc2929.html
	enum class RRClass : byte2
	{
		Internet = 1, // (IN)

		Chaos = 3, // (CH)
		Hesoid = 4 // (HS)
	};

	// Each resource record is saved in this format
	class ResourceRecord
	{
		
	// for now everything is public
	public:
		// default constructor
		ResourceRecord(const DomainBytes& address, const byte2 typeVal, const byte2 classVal, const byte4 ttlVal, const RDataBytes& rdata);
		
		// Resource address
		DomainBytes m_domain;

		// Resource type (Based on above enum: Type)
		byte2 m_type;

		// Class
		byte2 m_class;

		// Resource Time To Live (seconds)
		byte4 m_ttl;

		// Resource address
		RDataBytes m_rdata;
	}; 

	// Each question record is saved in this format
	class QuestionResourceRecord
	{
	// for now everything is public
	public:

		QuestionResourceRecord(const std::string& domain, const byte2 typeVal, const byte2 classVal);
		
		QuestionResourceRecord(const DomainBytes& domain, const byte2 typeVal, const byte2 classVal);
		
		// Resource address
		DomainBytes m_domain;

		// Resource type (Based on above enum: Type)
		byte2 m_type;

		// Class
		byte2 m_class;
	};

	static DomainBytes formatDomain(const std::string& domain);
	static DomainBytes formatDomain(const char* domain);
	static DomainBytes decodeDomain(const DomainBytes& dnsDomain);
	
	DNS(byte* data);

	DNS& transactionID(const byte2 value);
	byte2 transactionID() const;

	DNS& addQuestion(MutablePacket& packet, const DomainBytes& qAddr, byte2 qType, byte2 qClass);
	QuestionResourceRecord getQuestionResponse(const size_t index) const;

	DNS& addAnswer(MutablePacket& packet, const DomainBytes& aAddr, byte2 aType, byte2 aClass, byte4 aTtl, const RDataBytes& aData);
	ResourceRecord getAnswerResponse(const size_t index) const;

	DNS& addAuthResponse(MutablePacket& packet, const DomainBytes& aAddr, byte2 aType, byte2 aClass, byte4 aTtl, const RDataBytes& aData);
	ResourceRecord getAuthResponse(const size_t index) const;

	DNS& addAdditionalResponse(MutablePacket& packet, const DomainBytes& aAddr, byte2 aType, byte2 aClass, byte4 aTtl, const RDataBytes& aData);
	ResourceRecord  getAdditionalResponse(const size_t index) const;

	DNS& flags(byte2 newFlags);
	DNS& flags(FlagsIndices newFlags);
	byte2 flags();

	DNS& questionLength    (const byte2 value);
	byte2 questionLength() const;
	DNS& answersLength     (const byte2 value);
	byte2 answersLength() const;
	DNS& authRRLength      (const byte2 value);
	byte2 authRRLength() const;
	DNS& additionalRRLength(const byte2 value);
	byte2 additionalRRLength() const;


	size_t getSize() const override;

	virtual void addr(byte* address) override;
	virtual byte* addr() const override;

	virtual ProvidedProtocols protType() const;

	virtual bool syncFields(byte4 remainingSize) override;

	bool processQuestions(byte*& ptr, byte2 questionCount, byte4 remainingSize);
	bool processResourceRecord(byte*& ptr, byte4 remainingSize);
	bool skipRecords(byte2 recordCount, std::function<bool(byte4)> skipFunc, byte4 remainingSize);

	friend std::ostream& operator<<(std::ostream& os, const QuestionResourceRecord& q);
	friend std::ostream& operator<<(std::ostream& os, const ResourceRecord& r);
	friend std::ostream& operator<<(std::ostream& os, const DNS& dns);

public:
	static constexpr ProvidedProtocols ID = ProvidedProtocols::DNS;
	static constexpr size_t BASE_SIZE = sizeof(DNSHeader);

protected:
	DomainBytes consumeDomain(const byte* ptr) const;

protected:
	DNSHeader* m_data;

	byte2 m_questionsEndLoc;
	byte2 m_answersEndLoc;
	byte2 m_authRREndLoc;
	byte2 m_additionalRREndLoc;
};

