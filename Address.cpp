#include "Address.h"

using namespace address;


AddrIPv4::AddrIPv4() = default;

AddrIPv4::AddrIPv4(const std::string& ipv4Str)
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

byte& AddrIPv4::operator[](const size_t index)
{
	return m_data[index];
}

void address::AddrIPv4::operator=(const AddrIPv4& other)
{
	for (size_t i = 0; i < ADDR_IP4_BYTES; i++)
	{
		m_data[i] = other.m_data[i];
	}
}

std::string AddrIPv4::toString() const
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

AddrIPv4 AddrIPv4::fromString(const std::string& addr)
{
	AddrIPv4 result;
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

AddrIPv4 AddrIPv4::broadcast = AddrIPv4("255.255.255.255");






address::AddrMac::AddrMac() = default;
AddrMac::AddrMac(const std::string& macStr)
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

byte& AddrMac::operator[](const size_t index)
{
	return m_data[index];
}

std::string AddrMac::toString() const
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

AddrMac AddrMac::fromString(const std::string& addr)
{
	AddrMac result;
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

AddrMac AddrMac::broadcast = AddrMac("FF:FF:FF:FF:FF:FF");




AddrIPv6::AddrIPv6() = default;

AddrIPv6::AddrIPv6(const std::string& ipv6Str)
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

byte& AddrIPv6::operator[](const size_t index)
{
	return m_data[index];
}

std::string AddrIPv6::toString() const
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

AddrIPv6 AddrIPv6::fromString(const std::string& addr)
{
	AddrIPv6 result;
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


std::ostream& address::operator<<(std::ostream& os, const AddrIPv4 ipv4)
{
	return os << ipv4.toString();
}

std::ostream& address::operator<<(std::ostream& os, const AddrIPv6 ipv6)
{
	return os << ipv6.toString();
}

std::ostream& address::operator<<(std::ostream& os, const AddrMac mac)
{
	return os << mac.toString();
}
