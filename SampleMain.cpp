#include <pcap.h>
#include <memory>
#include <iostream>
#include <vector>
#include "WireDefs.h"
#include "Helper.h"
#include "Protocol.h"
#include "Address.h"

int main()
{
	using namespace address;

	addrMac mac = addrMac::fromString("0A:B2:1C:FD:0E:FF");
	std::cout << mac.toString() << std::endl;

	addrIPv6 ipv6 = addrIPv6::fromString("FFEE:DDCC:BBAA:9988:7766:5544:3322:1100");
	std::cout << ipv6.toString() << std::endl;

	addrIPv4 ipv4 = addrIPv4::fromString("192.168.100.1");
	std::cout << ipv4.toString() << std::endl;
}