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

	addrIPv4 src4("127.0.0.1");
	addrIPv4 dst4("8.8.8.8");

	IPv4 ipv4Layer(src4, dst4);
	ipv4Layer.version(4);
	ipv4Layer.protocol(IPv4::IPProtocols::ENCAP); // set to not real protocol
	ipv4Layer.ttl(64);
	ipv4Layer.ecn(0b10);

	// Push 2 ethernet layers onto the packet
	packetBuilder.push<Ethernet>("C4:4A:00:51:0C:CD", "01:00:5E:7F:FF:FB", 0x0800)
				 .push<IPv4>(ipv4Layer);

	// Make it into a packet
	Packet pack1 = packetBuilder.build();	

	// Push 2 different ethernet layers onto a new packet
	//packetBuilder.push<Ethernet>("FF:FF:FF:EE:EE:EE", "EE:EE:EE:FF:FF:FF", 0x0200)
	//			 .push<IPv4>("127.0.0.1", "127.0.0.1");

	// Send the 2 packets (both packets have 2 ethernet protocols which are not really useful)
	for (size_t i = 0; i < 10; i++)
	{
		device << pack1;
	}
	
}