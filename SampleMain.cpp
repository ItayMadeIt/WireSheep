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

	addrIPv4 ipv4("127.0.0.1");

	IPv4 ipv4Layer(ipv4, ipv4);
	ipv4Layer.version(4);
	ipv4Layer.protocol(6); // set to not real protocol

	// Push 2 ethernet layers onto the packet
	packetBuilder.push<Ethernet>("AA:BB:CC:DD:EE:FF", "FF:EE:DD:CC:BB:AA", 0x0800)
				 .push<IPv4>(std::move(ipv4Layer));

	// Make it into a packet
	Packet pack1 = packetBuilder.build();	

	// Push 2 different ethernet layers onto a new packet
	//packetBuilder.push<Ethernet>("FF:FF:FF:EE:EE:EE", "EE:EE:EE:FF:FF:FF", 0x0200)
	//			 .push<IPv4>("127.0.0.1", "127.0.0.1");

	// Send the 2 packets (both packets have 2 ethernet protocols which are not really useful)
	device << pack1 ;
	
}