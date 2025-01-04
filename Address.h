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
		addrIPv4();
		addrIPv4(const std::string& ipv4Str);

		byte m_data[ADDR_IP4_BYTES];

		byte& operator[](const size_t index);

		void operator=(const addrIPv4& other);

		std::string toString() const;

		static addrIPv4 fromString(const std::string& addr);

		static addrIPv4 broadcast;

		friend std::ostream& operator<<(std::ostream& os, const addrIPv4 ipv4);
	};

	struct addrIPv6
	{
		addrIPv6();
		addrIPv6(const std::string& ipv6Str);

		byte m_data[ADDR_IP6_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static addrIPv6 fromString(const std::string& addr);

		friend std::ostream& operator<<(std::ostream& os, const addrIPv6 ipv6);
	};
	
	struct addrMac
	{
		addrMac();
		addrMac(const std::string& macStr);

		byte m_data[ADDR_MAC_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static addrMac fromString(const std::string& addr);

		static addrMac broadcast;

		friend std::ostream& operator<<(std::ostream& os, const addrMac mac);
	};

}