#pragma once

#include "EndianHandler.h"
#include "Protocol.h"
#include "Address.h"

using namespace address;

constexpr size_t ETHER_LEN_TYPE = 2;

class Ethernet final : public Protocol 
{
public: 
	// full list: https://en.wikipedia.org/wiki/EtherType#Values
	enum class Protocols
	{
		IPv4 = 0x0800,
		ARP = 0x0806,
		IPv6 = 0x86DD,
	};

	Ethernet();
	Ethernet(const addrMac src, const addrMac dst, const byte2 type);
	Ethernet(const std::string& src, const std::string& dst, const byte2 type);
	Ethernet(std::unique_ptr<Protocol> nextProtocol);
	Ethernet(const addrMac src, const addrMac dst, const byte2 type, std::unique_ptr<Protocol> nextProtocol);
	Ethernet(const std::string& src, const std::string& dst, const byte2 type, std::unique_ptr<Protocol> nextProtocol);
	~Ethernet();

	Ethernet& src(const addrMac value);
	addrMac src() const;

	Ethernet& dst(const addrMac value);
	addrMac dst() const;

	Ethernet& type(const byte2 value);
	Ethernet& type(const Protocols value);
	byte2 type() const;

	virtual size_t getSize() const override;

	virtual void encodeLayer(std::vector<byte>& buffer, const size_t offset) override;
	virtual void encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const override;

	virtual void encodeLayerPost(std::vector<byte>& buffer, const size_t offset) override;

	friend std::ostream& operator<<(std::ostream& os, const Ethernet& ether);

public:
	const static size_t SIZE = 14;

protected:
	virtual void writeToBuffer(byte* buffer) const override;
	virtual void readFromBuffer(const byte* buffer, const size_t size) override;

protected:
	const static size_t MIN_SIZE = 42+12+2;
	
	addrMac m_dst;
	addrMac m_src;
	byte2 m_type;

};

/*
(page-17: https://www.mouser.com/pdfdocs/Ethernet_Basics_rev2_en.pdf?srsltid=AfmBOoocCAd74fWB609hQmksrsmpn6hdr6dwNwAqau5uDOmAiEjnJdUC)

Ethernet Protocol: 
[DA][SA][TYPE]<DATA>[~PADDING]

DA: 
	MAC destination address 

SA:
	MAC source address

TYPE:
	2 Byte value (can be `Length` if < 1500 (0x5DC) otherwise `Type` based on Ethernet II protocol)
	(Implementation currently will only work like it's Ethernet II)


(Padding):
	A minimum of 46 bytes to the whole msg (outside of DA SA and TYPE)
*/
