#include <pcap.h>
#include <memory>
#include <iostream>
#include <vector>
#include "Ethernet.h"
#include "Helper.h"
#include "ProtocolStackBuilder.h"

int main()
{
	using namespace address;

	addrMac macDst1 = addrMac::fromString("AA:BB:CC:DD:EE:FF");
	addrMac macSrc1 = addrMac::fromString("FF:EE:DD:CC:BB:AA");

	addrMac macDst2 = addrMac::fromString("11:22:11:22:11:22");
	addrMac macSrc2 = addrMac::fromString("44:33:44:33:44:33");

	ProtocolStackBuilder builder;
	builder.push<Ethernet>(macSrc1, macDst1, 0x0800);
	builder.push<Ethernet>(macSrc2, macDst2, 0x0123);
	
	std::unique_ptr<Protocol> prot1 = builder.first();

	// Serialize the stack
	std::vector<byte> buffer;
	prot1->serialize(buffer);

	std::cout << "Protocol bytes: " << std::endl << std::endl;
	printByteArr(buffer.data(), buffer.size());
}