#pragma once

#include "Protocol.h"
#include "EndianHandler.h"
#include "UDPHeader.h"

class UDP : public Protocol
{
public:
	UDP(byte* data);
	UDP(byte* data, const byte2 src, const byte2 dst);

public:

	UDP&  src(const byte2 value);
	byte2 src() const;
	
	UDP&  dst(const byte2 value);
	byte2 dst() const;
	
	UDP&  length(const byte2 value);
	byte2 length() const;
	
	UDP&  checksum(const byte2 value);
	byte2 checksum() const;

	virtual void addr(byte* address) override;
	virtual byte* addr() const override;

	virtual size_t getSize() const override;

	virtual void encodePre(MutablePacket& packet, const size_t index) override;
	virtual void encodePost(MutablePacket& packet, const size_t index)override;
public:
	const static size_t BASE_SIZE = 8; 

protected:	
	virtual void calculateChecksum(MutablePacket& packet, const size_t index);

	UDPHeader* m_data;
};

