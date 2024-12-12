#pragma once

#include "Helper.h"
#include <sstream>
#include <iomanip>

namespace address
{
	constexpr size_t ADDR_IP4_BYTES = 4;
	constexpr size_t ADDR_IP6_BYTES = 16;
	constexpr size_t ADDR_MAC_BYTES = 6;

	struct addrIPv4
	{
		byte m_data[ADDR_IP4_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static addrIPv4 fromString(const std::string& addr);

		friend std::ostream& operator<<(std::ostream& os, const addrIPv4 ipv4);
	};

	struct addrIPv6
	{
		byte m_data[ADDR_IP6_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static addrIPv6 fromString(const std::string& addr);
	
		friend std::ostream& operator<<(std::ostream& os, const addrIPv6 ipv6);
	};
	
	struct addrMac
	{
		byte m_data[ADDR_MAC_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static addrMac fromString(const std::string& addr);

		friend std::ostream& operator<<(std::ostream& os, const addrMac mac);
	};

}