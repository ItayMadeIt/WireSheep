#include <pcap.h>
#include <memory>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include "Ethernet.h"
#include "Helper.h"
#include "PacketBuilder.h"
#include "Device.h"

std::string getFirstLineInFile(const std::string& filename)
{
	std::string result;

	std::ifstream file(filename);

	std::getline(file, result);

	return result;
}

int main()
{
	using namespace address;

	std::string fileName = getFirstLineInFile("C:\\Users\\User\\Documents\\device.txt");

	Device device(fileName);
	
	// Create packet
	PacketBuilder packetBuilder;

	// Push 2 ethernet layers onto the packet
	packetBuilder.push<Ethernet>("AA:BB:CC:DD:EE:FF", "FF:EE:DD:CC:BB:AA", 0x0100)
				 .push<Ethernet>("11:22:11:22:11:22", "44:33:44:33:44:33", 0x0100);

	// Make it into a packet
	Packet pack1 = packetBuilder.build();	

	// Push 2 different ethernet layers onto a new packet
	packetBuilder.push<Ethernet>("FF:FF:FF:EE:EE:EE", "EE:EE:EE:FF:FF:FF", 0x0200)
				 .push<Ethernet>("DD:DD:DD:CC:CC:CC", "CC:CC:CC:DD:DD:DD", 0x0200);

	Packet pack2 = packetBuilder.build();	

	// Send the 2 packets (both packets have 2 ethernet protocols which are not really useful)
	device << pack1 << pack2;
	
}