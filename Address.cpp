#include "Address.h"

using namespace address;


byte& addrIPv4::operator[](const size_t index)
{
	return m_data[index];
}


std::string addrIPv4::toString() const
{
	std::stringstream sstream;

	// Input 2 char hex value into m_data[i]
	for (size_t i = 0; i < ADDR_IP4_BYTES; i++)
	{
		sstream << std::dec << (int)m_data[i];

		if (i != ADDR_IP4_BYTES - 1)
		{
			sstream << '.';
		}
	}

	return sstream.str();
}

addrIPv4 addrIPv4::fromString(const std::string& addr)
{
	addrIPv4 result;
	std::stringstream sstream(addr);

	int curVal;
	char delim;

	// Get dec value into result[i]
	for (size_t i = 0; i < ADDR_IP4_BYTES; i++)
	{
		sstream >> std::dec >> curVal;
		result[i] = (byte)curVal;

		if (i != ADDR_MAC_BYTES - 1)
		{
			sstream >> delim;
		}
	}

	return result;
}

byte& addrMac::operator[](const size_t index)
{
	return m_data[index];
}

std::string addrMac::toString() const
{
	std::stringstream sstream;

	// Input 2 char hex value into m_data[i]
	for (size_t i = 0; i < ADDR_MAC_BYTES; i++)
	{
		sstream << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (int)m_data[i];
		
		if (i != ADDR_MAC_BYTES - 1)
		{
			sstream << ':';
		}
	}

	return sstream.str();
}

addrMac addrMac::fromString(const std::string& addr)
{
	addrMac result;
	std::stringstream sstream(addr);
	
	int curVal;
	char delim;

	// Get 2 char hex value into result[i]
	for (size_t i = 0; i < ADDR_MAC_BYTES; i++)
	{
		sstream >> std::hex >> curVal;
		result[i] = curVal;

		if (i != ADDR_MAC_BYTES - 1)
		{
			sstream >> delim;
		}
	}
	
	return result;
}

byte& addrIPv6::operator[](const size_t index)
{
	return m_data[index];
}

std::string addrIPv6::toString() const
{
	std::stringstream sstream;

	// Input 2 char hex value into m_data[i]
	for (size_t i = 0; i < ADDR_IP6_BYTES; i++)
	{
		sstream << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (int)m_data[i];

		if (i != ADDR_IP6_BYTES - 1 && i % 2 != 0)
		{
			sstream << ':';
		}
	}

	return sstream.str();
}

addrIPv6 addrIPv6::fromString(const std::string& addr)
{
	addrIPv6 result;
	std::stringstream sstream(addr);

	int curVal;
	char delim;

	// Get 4 char hex value into result[i], result[i+1]
	for (size_t i = 0; i < ADDR_IP6_BYTES/2; i++)
	{
		sstream >> std::hex >> curVal;
		// Input it backwards
		result[i*2+1] = (curVal & 0x00FF)     ;
		result[i*2  ] = (curVal & 0xFF00) >> 8;

		if (i != ADDR_IP6_BYTES/2-1)
		{
			sstream >> delim;
		}
	}

	return result;
}
