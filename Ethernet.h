#pragma once

#include "EndianHandler.h"
#include "Protocol.h"
#include "Address.h"

using namespace address;

constexpr size_t ETHER_LEN_TYPE = 2;

class Ethernet final : public Protocol 
{
public:
	Ethernet();
	Ethernet(const addrMac src, const addrMac dst, const byte2 type);
	~Ethernet();

	void src(const addrMac value);
	addrMac src() const;

	void dst(const addrMac value);
	addrMac dst() const;

	void type(const byte2 value);
	byte2 type() const;

	virtual void serialize(byte* ptr) const override;
	virtual void deserialize(const byte* ptr) override;

	virtual size_t getSize() const override;
	
	friend std::ostream& operator<<(std::ostream& os, const Ethernet ether);

public:
	const static size_t Size = 14;

private:
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
