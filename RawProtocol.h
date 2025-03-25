#pragma once

#include "Protocol.h"
#include "MutablePacket.h"

class  Raw : public Protocol
{
public:
	Raw(byte* data);

public:
	Raw& pushBack(const byte value, MutablePacket& packet);
	Raw& pushBack(const byte* values, const size_t length, MutablePacket& packet);
	Raw& pushBack(const std::vector<byte>& values, MutablePacket& packet);

	virtual byte* addr() const override;

	virtual size_t getSize() const override;
	
	const static size_t BASE_SIZE = 0;

protected:
	byte* m_data;
	size_t m_size;

};
