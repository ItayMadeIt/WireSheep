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

	virtual void serializeArr(byte* ptr) const override;
	virtual void deserializeArr(const byte* ptr) override;

	virtual void serialize(std::vector<byte>& buffer) override;
	virtual void serialize(std::vector<byte>& buffer, const size_t offset) override;
	
	virtual void serializeRaw(std::vector<byte>& buffer) const override;
	virtual void serializeRaw(std::vector<byte>& buffer, const size_t offset) const override;
	
	size_t getSize() const override;

};
