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

	virtual size_t getSize() const override;

	virtual void addr(byte* address) override;
	virtual byte* addr() const override;

	virtual ProvidedProtocols protType() const;

	friend std::ostream& operator<<(std::ostream& os, const Raw& raw);

public:
	static constexpr ProvidedProtocols ID = ProvidedProtocols::Raw;
	static constexpr size_t BASE_SIZE = 0;

protected:
	byte* m_data;
	size_t m_size;

};
