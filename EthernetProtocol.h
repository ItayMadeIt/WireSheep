#pragma once

#include "EndianHandler.h"
#include "Protocol.h"
#include "Address.h"
#include "EthernetHeader.h"

using namespace address;

constexpr size_t ETHER_LEN_TYPE = 2;

class Ethernet : public Protocol 
{
public: 
	// full list: https://en.wikipedia.org/wiki/EtherType#Values
	enum class Protocols
	{
		IPv4 = 0x0800,
		ARP = 0x0806,
		IPv6 = 0x86DD,
	};

	Ethernet(byte* data);
	~Ethernet();

	Ethernet& src(const AddrMac value);
	AddrMac src() const;

	Ethernet& dst(const AddrMac value);
	AddrMac dst() const;

	Ethernet& type(const byte2 value);
	Ethernet& type(const Protocols value);
	byte2 type() const;

	virtual size_t getSize() const override;
	
	// No need to override pre
	// virtual void encodePre (MutablePacket& packet, size_t protocolIndex) override;
	virtual void encodePost(MutablePacket& packet, size_t protocolIndex) override;

	friend std::ostream& operator<<(std::ostream& os, const Ethernet& ether);

	virtual byte* addr() const override;

public:
	const static size_t BASE_SIZE = 14;

protected:

	const static size_t MIN_SIZE = 0x40;

	EthernetHeader* m_data;
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