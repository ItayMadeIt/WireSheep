#pragma once

#include "Helper.h"
#include <sstream>
#include <iomanip>

namespace address
{
	constexpr size_t ADDR_IP4_BYTES = 4;
	constexpr size_t ADDR_IP6_BYTES = 16;
	constexpr size_t ADDR_MAC_BYTES = 6;

	// Force tight packing
	#pragma pack(push)
	#pragma pack(1)

	struct AddrIPv4
	{
		AddrIPv4();
		AddrIPv4(const std::string& ipv4Str);
		AddrIPv4(const char* ipv4Str);

		/// <summary>
		/// Array to store IPv4 (4 bytes).
		/// Data stored in network order.
		/// Big endian.
		/// </summary>
		byte m_data[ADDR_IP4_BYTES];

		byte& operator[](const size_t index);

		void operator=(const AddrIPv4& other);

		std::string toString() const;

		static AddrIPv4 broadcast;

		friend std::ostream& operator<<(std::ostream& os, const AddrIPv4 ipv4);
	};
	#pragma pack(pop)

	// Force tight packing
	#pragma pack(push)
	#pragma pack(1)

	struct AddrIPv6
	{
		AddrIPv6();
		AddrIPv6(const std::string& ipv6Str);
		AddrIPv6(const char* ipv6Str);

		/// <summary>
		/// Array to store IPv6 (6 bytes).
		/// Data stored in network order.
		/// Big endian.
		/// </summary>
		byte m_data[ADDR_IP6_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		friend std::ostream& operator<<(std::ostream& os, const AddrIPv6 ipv6);
	};
	#pragma pack(pop)

	// Force tight packing
	#pragma pack(push)
	#pragma pack(1)

	struct AddrMac
	{
		AddrMac();
		AddrMac(const std::string& macStr);
		AddrMac(const char* macStr);

		/// <summary>
		/// Array to store IPv6 (6 bytes).
		/// Data stored in network order.
		/// Big endian.
		/// </summary>
		byte m_data[ADDR_MAC_BYTES];

		byte& operator[](const size_t index);

		std::string toString() const;

		static AddrMac broadcast;

		friend std::ostream& operator<<(std::ostream& os, const AddrMac mac);
	};
	#pragma pack(pop)
}