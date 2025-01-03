#pragma once
#include "Protocol.h"
#include "EndianHandler.h"

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
		QR =     0,     // 1 bit  (Query/Response)
		OPCODE = 1,     // 4 bits (OPCODE)
		AA =     5,     // 1 bit  (Authoritative Answer)
		TC =     6,     // 1 bit  (TrunCation)
		RD =     7,     // 1 bit  (Recursion Desired)
		RA =     8,     // 1 bit  (Recursion Available)
		Z =      9,     // 3 bits (Zero (Reserved))
		RCODE = 12,     // 4 bits (Response Code)
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
		ResourceRecord(const std::vector<byte>& address, const byte2 typeVal, const byte2 classVal, const byte4 ttlVal, const std::vector<byte>& rdata);

		// Resource address
		std::vector<byte> m_address; 

		// Resource type (Based on above enum: Type)
		byte2 m_type;

		// Class
		byte2 m_class;

		// Resource Time To Live (seconds)
		byte4 m_ttl;

		// Length of RDATA and RDATA
		std::vector<byte> m_rdata;
	}; 

	// Each question record is saved in this format
	class QuestionResourceRecord
	{
	// for now everything is public
	public:

		// default constructor
		QuestionResourceRecord(const std::vector<byte>& address, const byte2 typeVal, const byte2 classVal);
		
		// Resource address
		std::vector<byte> m_address;

		// Resource type (Based on above enum: Type)
		byte2 m_type;

		// Class
		byte2 m_class;
	};

	static std::vector<byte> formatDomain(const std::string& domain);
	
	DNS();

	void addQuestion(const std::string& qAddr, const byte2 qType, const byte2 qClass);
	QuestionResourceRecord getQuestionResponse(const size_t index);
	void popQuestion();

	void addAnswer(const std::string& aAddr, const byte2 aType, const byte2 aClass, const byte4 aTtl, const std::vector<byte>& aData);;
	ResourceRecord getAnswerResponse(const size_t index);
	void popAnswer();

	void addAuthResponse(const std::string& arAddr, const byte2 arType, const byte2 arClass, const byte4 arTtl, const std::vector<byte>& arData);
	ResourceRecord getAuthResponse(const size_t index);
	void popAuthResponse();

	void addAdditionalResponse(const std::string& arAddr, const byte2 arType, const byte2 arClass, const byte4 arTtl, const std::vector<byte>& arData);
	ResourceRecord  getAdditionalResponse(const size_t index);
	void popAdditionalResponse();

	void flags(byte2 newFlags);
	void flags(FlagsIndices newFlags);
	byte2 flags();

	void setQuestionLength    (const byte2 value);
	void setAnswersLength     (const byte2 value);
	void setAuthRRLength      (const byte2 value);
	void setAdditionalRRLength(const byte2 value);

public:
	const static size_t Size = 12; // min size of 12 bytes

protected:
	byte2 m_transcationID;
	std::vector< QuestionResourceRecord> m_questions; // Include length
	std::vector< ResourceRecord> m_answers; // Include length
	std::vector< ResourceRecord> m_authRR; // Include length
	std::vector< ResourceRecord> m_additionalRR; // Include length
	byte2 m_flags;

	// Length
	byte2 m_questionLength;
	byte2 m_answerLength;
	byte2 m_authLength;
	byte2 m_additionalLength;

	// Inherited via Protocol
	void serializeArr(byte* ptr) const override;
	void deserializeArr(const byte* ptr) override;
	void serialize(std::vector<byte>& buffer) override;
	void serializeRaw(std::vector<byte>& buffer) const override;
	size_t getSize() const override;
	void serialize(std::vector<byte>& buffer, const size_t offset) override;
	void serializeRaw(std::vector<byte>& buffer, const size_t offset) const override;

	void serializeArrRecord(const DNS::ResourceRecord& record, byte*& ptr) const;
};

