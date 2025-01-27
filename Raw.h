#pragma once

#include "Protocol.h"

class  Raw : public Protocol
{
public:
	Raw();

	Raw& push_back(const byte value);
	Raw& push_back(const byte* values, const size_t length);
	Raw& push_back(const std::vector<byte>& values);

private:

	std::vector<byte> m_data;

	virtual void writeToBuffer(byte* ptr) const override;
	virtual void readFromBuffer(const byte* ptr) override;

	virtual void encodeLayer(std::vector<byte>& buffer) override;
	virtual void encodeLayer(std::vector<byte>& buffer, const size_t offset) override;
	
	virtual void encodeLayerRaw(std::vector<byte>& buffer) const override;
	virtual void encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const override;
	
	size_t getSize() const override;

};
