#include <pcap.h>
#include <memory>
#include <iostream>
#include <vector>
#include "Ethernet.h"
#include "Helper.h"

int main()
{
	using namespace address;

	addrMac macDst = addrMac::fromString("E8:AD:A6:FB:FC:74");
	addrMac macSrc = addrMac::fromString("74:56:3C:73:67:B0");

	// Create Ethernet layers
    auto ether = std::make_unique<Ethernet>(macSrc, macDst, 0x0800);
    auto ether2 = std::make_unique<Ethernet>(macDst, macSrc, 0x0123, std::move(ether));

    // Serialize the stack
    std::vector<byte> buffer;
    ether2->serialize(buffer);

	std::cout << "Ethernet bytes: " << std::endl << std::endl;
	printByteArr(buffer.data(), buffer.size());

}