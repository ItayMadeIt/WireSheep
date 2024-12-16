#pragma once

#include "Protocol.h"
#include "EndianHandler.h"

class UDP : public Protocol
{
public:
	UDP();
	UDP(const byte2 src, const byte2 dst);


public:
	static const size_t Size = 8;

	UDP& src(const byte2 value) { m_src = value; return *this; }
	byte2 src() { return m_src; }
	UDP& dst(const byte2 value) { m_dst = value; return *this; }
	byte2 dst() { return m_dst; }
	UDP& length(const byte2 value) { m_length = value; return *this; }
	byte2 length() { return m_length; }
	UDP& checksum(const byte2 value) { m_checksum = value; return *this; }
	byte2 checksum() { return m_checksum; }

protected:
	byte2 m_src;            // source port (16 bits)
	byte2 m_dst;            // destination port (16 bits)
	byte2 m_length;         // length (16 bits)
	byte2 m_checksum;       // checksum (16 bits)
	
	void serializeArr(byte* ptr) const override;
	void deserializeArr(const byte* ptr) override;
	void serialize(std::vector<byte>& buffer) const override;
	size_t getSize() const override;
	void serialize(std::vector<byte>& buffer, const size_t offset) const override;
};

