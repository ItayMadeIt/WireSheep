#include "Address.h"

using namespace address;


addrIPv4::addrIPv4() = default;

addrIPv4::addrIPv4(const std::string& ipv4Str)
{
	std::stringstream sstream(ipv4Str);

	int curVal;
	char delim;

	// Get dec value into result[i]
	for (size_t i = 0; i < ADDR_IP4_BYTES; i++)
	{
		sstream >> std::dec >> curVal;
		m_data[i] = (byte)curVal;

		if (i != ADDR_MAC_BYTES - 1)
		{
			sstream >> delim;
		}
	}
}

byte& addrIPv4::operator[](const size_t index)
{
	return m_data[index];
}

void address::addrIPv4::operator=(const addrIPv4& other)
{
	for (size_t i = 0; i < ADDR_IP4_BYTES; i++)
	{
		m_data[i] = other.m_data[i];
	}
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

addrIPv4 addrIPv4::broadcast = addrIPv4("255.255.255.255");






address::addrMac::addrMac() = default;
addrMac::addrMac(const std::string& macStr)
{
	std::stringstream sstream(macStr);

	int curVal;
	char delim;

	// Get 2 char hex value into result[i]
	for (size_t i = 0; i < ADDR_MAC_BYTES; i++)
	{
		sstream >> std::hex >> curVal;
		m_data[i] = curVal;

		if (i != ADDR_MAC_BYTES - 1)
		{
			sstream >> delim;
		}
	}
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

addrMac addrMac::broadcast = addrMac("FF:FF:FF:FF:FF:FF");




addrIPv6::addrIPv6() = default;

addrIPv6::addrIPv6(const std::string& ipv6Str)
{
	std::stringstream sstream(ipv6Str);

	int curVal;
	char delim;

	// Get 4 char hex value into result[i], result[i+1]
	for (size_t i = 0; i < ADDR_IP6_BYTES / 2; i++)
	{
		sstream >> std::hex >> curVal;
		// Input it backwards
		m_data[i * 2 + 1] = (curVal & 0x00FF);
		m_data[i * 2] = (curVal & 0xFF00) >> 8;

		if (i != ADDR_IP6_BYTES / 2 - 1)
		{
			sstream >> delim;
		}
	}
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



std::ostream& address::operator<<(std::ostream& os, const addrIPv4 ipv4)
{
	return os << ipv4;
}

std::ostream& address::operator<<(std::ostream& os, const addrIPv6 ipv6)
{
	return os << ipv6.toString();
}

std::ostream& address::operator<<(std::ostream& os, const addrMac mac)
{
	return os << mac.toString();
}
