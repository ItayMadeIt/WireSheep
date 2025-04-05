#include "Address.h"

using namespace address;


AddrIPv4::AddrIPv4() = default;

address::AddrIPv4::AddrIPv4(const byte* copy)
{
	std::memcpy(m_data, copy, ADDR_IP4_BYTES);
}

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

		if (i != ADDR_IP4_BYTES - 1)
		{
			sstream >> delim;
		}
	}
}

address::AddrIPv4::AddrIPv4(const char* ipv4Str)
{
	int curVal = 0;
	int idx = 0;

	for (const char* p = ipv4Str; *p && idx < ADDR_IP4_BYTES; ++p)
	{
		if (*p == '.')
		{
			m_data[idx++] = (byte)curVal;
			curVal = 0;
		}
		else if (*p >= '0' && *p <= '9')
		{
			curVal = curVal * 10 + (*p - '0');
		}
		else
		{
			throw std::runtime_error("Invalid char: " + (*p));
		}
	}
	m_data[idx] = (byte)curVal;
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

bool address::operator==(const AddrIPv4& a, const AddrIPv4 b)
{
	return std::memcmp(a.m_data, b.m_data, ADDR_IP4_BYTES);
}

bool address::operator!=(const AddrIPv4& a, const AddrIPv4 b)
{
	return !(a == b);
}

bool address::operator==(const AddrIPv4& addr, const char* str)
{
	byte parsed[ADDR_IP4_BYTES];
	int curVal = 0;
	int idx = 0;

	for (const char* p = str; *p && idx < ADDR_IP4_BYTES; ++p)
	{
		if (*p == '.')
		{
			parsed[idx++] = (byte)curVal;
			curVal = 0;
		}
		else if (*p >= '0' && *p <= '9')
		{
			curVal = curVal * 10 + (*p - '0');
		}
		else
		{
			return false;
		}
	}

	parsed[idx] = (byte)curVal;

	for (int i = 0; i < ADDR_IP4_BYTES; ++i)
	{
		if (parsed[i] != addr.m_data[i])
		{
			return false;
		}
	}

	return true;
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

AddrIPv4 AddrIPv4::broadcast = AddrIPv4("255.255.255.255");






address::AddrMac::AddrMac() = default;
address::AddrMac::AddrMac(const byte* copy)
{
	std::memcpy(m_data, copy, ADDR_MAC_BYTES);
}
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

address::AddrMac::AddrMac(const char* macStr)
{
	int curVal = 0;
	int idx = 0;

	while (*macStr && idx < ADDR_MAC_BYTES)
	{
		curVal = 0;
		for (int i = 0; i < 2 && *macStr; ++i)
		{
			char c = *macStr;
			++macStr;

			if (c >= '0' && c <= '9')
			{
				curVal = (curVal << 4) + (c - '0');
			}
			else if (c >= 'a' && c <= 'f')
			{
				curVal = (curVal << 4) + (c - 'a' + 10);
			}
			else if (c >= 'A' && c <= 'F')
			{
				curVal = (curVal << 4) + (c - 'A' + 10);
			}
			else
			{
				throw std::runtime_error("Invalid char: (MAC) " + c);
			}
		}

		m_data[idx++] = static_cast<byte>(curVal);

		if (*macStr == ':' || *macStr == '-') ++macStr;
	}
}

bool address::operator==(const AddrMac& a, const AddrMac b)
{
	return std::memcmp(a.m_data, b.m_data, ADDR_MAC_BYTES);
}

bool address::operator!=(const AddrMac& a, const AddrMac b)
{
	return !(a == b);
}

bool address::operator==(const AddrMac& addr, const char* str)
{
	byte parsed[ADDR_MAC_BYTES] = {};
	int idx = 0;

	while (*str && idx < ADDR_MAC_BYTES)
	{
		int curVal = 0;
		for (int i = 0; i < 2 && *str; ++i)
		{
			char c = *str++;
			if (c >= '0' && c <= '9')
				curVal = (curVal << 4) + (c - '0');
			else if (c >= 'a' && c <= 'f')
				curVal = (curVal << 4) + (c - 'a' + 10);
			else if (c >= 'A' && c <= 'F')
				curVal = (curVal << 4) + (c - 'A' + 10);
			else
				return false;
		}

		parsed[idx++] = (byte)curVal;

		if (*str == ':' || *str == '-') ++str;
	}

	if (idx != ADDR_MAC_BYTES)
		return false;

	for (int i = 0; i < ADDR_MAC_BYTES; ++i)
	{
		if (parsed[i] != addr.m_data[i])
			return false;
	}

	return true;
}

bool address::operator!=(const AddrMac& addr, const char* str)
{
	return !(addr == str);
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

AddrMac AddrMac::broadcast = AddrMac("FF:FF:FF:FF:FF:FF");




AddrIPv6::AddrIPv6() = default;

address::AddrIPv6::AddrIPv6(const byte* copy)
{
	std::memcpy(m_data, copy, ADDR_IP6_BYTES);
}

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

address::AddrIPv6::AddrIPv6(const char* ipv6Str)
{
	int curVal = 0;
	int idx = 0;

	while (*ipv6Str && idx < ADDR_IP6_BYTES)
	{
		curVal = 0;
		while (*ipv6Str && *ipv6Str != ':')
		{
			char c = *ipv6Str++;

			if (c >= '0' && c <= '9')
			{
				curVal = (curVal << 4) + (c - '0');
			}
			else if (c >= 'a' && c <= 'f')
			{
				curVal = (curVal << 4) + (c - 'a' + 10);
			}
			else if (c >= 'A' && c <= 'F')
			{
				curVal = (curVal << 4) + (c - 'A' + 10);
			}
			else
			{
				throw std::runtime_error("Invalid char: (IPv6) " + c);
			}
		}

		// store as two bytes, big-endian
		m_data[idx++] = (curVal >> 8) & 0xFF;
		m_data[idx++] = curVal & 0xFF;

		// skip colon
		if (*ipv6Str == ':') ++ipv6Str;
	}
}

byte& AddrIPv6::operator[](const size_t index)
{
	return m_data[index];
}

void address::AddrIPv6::operator=(const AddrIPv6& other)
{
	for (size_t i = 0; i < ADDR_IP6_BYTES; i++)
	{
		m_data[i] = other.m_data[i];
	}
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


bool address::operator!=(const AddrIPv4& addr, const char* str)
{
	return !(addr == str);
}

bool address::operator==(const AddrIPv6& a, const AddrIPv6 b)
{
	return std::memcmp(a.m_data, b.m_data, ADDR_IP6_BYTES);
}

bool address::operator!=(const AddrIPv6& a, const AddrIPv6 b)
{
	return !(a == b);
}

bool address::operator==(const AddrIPv6& addr, const char* str)
{
	byte parsed[ADDR_IP6_BYTES] = {};
	int idx = 0;
	int curVal = 0;
	bool inBlock = false;

	while (*str && idx < ADDR_IP6_BYTES)
	{
		if (*str == ':')
		{
			if (!inBlock) {
				// First colon
				inBlock = true;
			}
			else {
				// Double colon (zero compression)
				int zeroFill = ADDR_IP6_BYTES - idx;
				for (int i = 0; i < zeroFill; ++i)
					parsed[idx++] = 0;
				++str; // skip second ':'
				continue;
			}
			++str;
		}

		curVal = 0;
		int digitCount = 0;

		while (*str && *str != ':' && digitCount < 4)
		{
			char c = *str++;
			if (c >= '0' && c <= '9')
				curVal = (curVal << 4) + (c - '0');
			else if (c >= 'a' && c <= 'f')
				curVal = (curVal << 4) + (c - 'a' + 10);
			else if (c >= 'A' && c <= 'F')
				curVal = (curVal << 4) + (c - 'A' + 10);
			else
				return false;

			++digitCount;
		}

		if (idx + 1 >= ADDR_IP6_BYTES)
			return false;

		parsed[idx++] = (byte)((curVal >> 8) & 0xFF);
		parsed[idx++] = (byte)(curVal & 0xFF);
	}

	for (int i = 0; i < ADDR_IP6_BYTES; ++i)
	{
		if (parsed[i] != addr.m_data[i])
			return false;
	}

	return true;
}

bool address::operator!=(const AddrIPv6& addr, const char* str)
{
	return !(addr == str);
}

std::ostream& address::operator<<(std::ostream& os, const AddrIPv4 ipv4)
{
	char buf[16];
	std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		ipv4.m_data[0], ipv4.m_data[1], ipv4.m_data[2], ipv4.m_data[3]);

	return os << buf;
}

std::ostream& address::operator<<(std::ostream& os, const AddrIPv6 ipv6)
{
	char buf[40];
	int offset = 0;

	for (int i = 0; i < 16; i += 2)
	{
		if (i != 0) buf[offset++] = ':';

		uint16_t val = (ipv6.m_data[i] << 8) | ipv6.m_data[i + 1];
		offset += std::snprintf(buf + offset, sizeof(buf) - offset, "%x", val);
	}

	buf[offset] = '\0';
	return os << buf;
}

std::ostream& address::operator<<(std::ostream& os, const AddrMac mac)
{
	char buf[18];

	std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
		mac.m_data[0], mac.m_data[1], mac.m_data[2], mac.m_data[3], mac.m_data[4], mac.m_data[5]);

	return os << buf;
}
