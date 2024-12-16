#include <pcap.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include "Device.h"
#include "PacketBuilder.h"
#include "Ethernet.h"
#include "IPv4.h"

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

	Ethernet etherLayer;
	etherLayer
		.src({"C4:4A:00:51:0C:CD"})
		.dst({"01:00:5E:7F:FF:FB"})
		.type(0x0800);

	IPv4 ipv4Layer;
	ipv4Layer
		.src({ "127.0.0.1" })
		.dst({ "8.8.8.8" })
		.protocol(IPv4::IPProtocols::UDP);
			 


	// Push 2 ethernet layers onto the packet
	packetBuilder << etherLayer << ipv4Layer;

	// Make it into a packet
	Packet pack1 = packetBuilder.build();	

	// Send the 2 packets (both packets have 2 ethernet protocols which are not really useful)
	for (size_t i = 0; i < 10; i++)
	{
		device << pack1;
	}
	
}