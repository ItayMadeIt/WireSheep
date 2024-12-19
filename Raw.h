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

	void serializeArr(byte* ptr) const override;
	void deserializeArr(const byte* ptr) override;
	void serialize(std::vector<byte>& buffer) const override;
	size_t getSize() const override;
	void serialize(std::vector<byte>& buffer, const size_t offset) const override;
};
