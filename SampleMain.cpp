#include <pcap.h>
#include <memory>
#include <iostream>
#include <vector>
#include "Ethernet.h"
#include "Helper.h"
#include "PacketBuilder.h"

int main()
{
	using namespace address;

	// Sample mac addresses
	addrMac macDst1 = addrMac::fromString("AA:BB:CC:DD:EE:FF");
	addrMac macSrc1 = addrMac::fromString("FF:EE:DD:CC:BB:AA");

	addrMac macDst2 = addrMac::fromString("11:22:11:22:11:22");
	addrMac macSrc2 = addrMac::fromString("44:33:44:33:44:33");

	// Create packet
	PacketBuilder packetBuilder;

	// Push 2 ethernet layers onto the packet
	packetBuilder.push<Ethernet>(macSrc1, macDst1, 0x0800)
				 .push<Ethernet>(macSrc2, macDst2, 0x0700);

	// Make it into a packet
	Packet pack1 = packetBuilder.build();	

	// Serialize the stack into a buffer
	const std::vector<byte>& buffer = pack1;

	// Print it
	std::cout << "Protocol bytes: " << std::endl << std::endl;
	printByteArr(buffer.data(), buffer.size());
}