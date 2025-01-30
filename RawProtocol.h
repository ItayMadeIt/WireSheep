#pragma once

#include "Protocol.h"

class  Raw : public Protocol
{
public:
	Raw();

public:
	Raw& push_back(const byte value);
	Raw& push_back(const byte* values, const size_t length);
	Raw& push_back(const std::vector<byte>& values);

	virtual void encodeLayer(std::vector<byte>& buffer, const size_t offset) override;
	virtual void encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const override;

	size_t getSize() const override;

protected:
	std::vector<byte> m_data;

	virtual void writeToBuffer (byte* buffer) const override;
	virtual void readFromBuffer(const byte* buffer, const size_t size) override;

};
