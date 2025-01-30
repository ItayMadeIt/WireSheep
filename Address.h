#pragma once

#include "Helper.h"
#include <sstream>
#include <iomanip>

namespace address
{
	constexpr size_t ADDR_IP4_BYTES = 4;
	constexpr size_t ADDR_IP6_BYTES = 16;
	constexpr size_t ADDR_MAC_BYTES = 6;

	#pragma pack(push)
	struct AddrIPv4
	{
		AddrIPv4();
		AddrIPv4(const std::string& ipv4Str);

		/// <summary>
		/// Array to store IPv4 (4 bytes).
		/// Data stored in network order.
		/// Big endian.
		/// </summary>
		byte m_data[ADDR_IP4_BYTES];

		byte& operator[](const size_t index);

		void operator=(const AddrIPv4& other);

		std::string toString() const;

		static AddrIPv4 fromString(const std::string& addr);

		static AddrIPv4 broadcast;

		friend std::ostream& operator<<(std::ostream& os, const AddrIPv4 ipv4);
	};
	#pragma pack(pop)

	#pragma pack(push)
	struct addrIPv6
	{
		addrIPv6();
		addrIPv6(const std::string& ipv6Str);

		/// <summary>
		/// Array to store IPv6 (6 bytes).
		/// Data stored in network order.
		/// Big endian.
		/// </summary>
		byte m_data[ADDR_IP6_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static addrIPv6 fromString(const std::string& addr);

		friend std::ostream& operator<<(std::ostream& os, const addrIPv6 ipv6);
	};
	#pragma pack(pop)
	
	#pragma pack(push)
	struct AddrMac
	{
		AddrMac();
		AddrMac(const std::string& macStr);

		/// <summary>
		/// Array to store IPv6 (6 bytes).
		/// Data stored in network order.
		/// Big endian.
		/// </summary>
		byte m_data[ADDR_MAC_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static AddrMac fromString(const std::string& addr);

		static AddrMac broadcast;

		friend std::ostream& operator<<(std::ostream& os, const AddrMac mac);
	};
	#pragma pack(pop)
}