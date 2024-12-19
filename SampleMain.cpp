#include <pcap.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include "Device.h"
#include "NetworkUtils.h"
#include "PacketBuilder.h"
#include "Ethernet.h"
#include "IPv4.h"
#include "UDP.h"

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

	std::string deviceName = getFirstLineInFile("C:\\Users\\User\\Documents\\device.txt");

	Device device(deviceName);
	
	// Create packet
	PacketBuilder packetBuilder;

	Ethernet etherLayer;
	etherLayer
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(0x0800);

	IPv4 ipv4Layer;
	ipv4Layer
		.src({ "127.0.0.1" })
		.dst({ "8.8.8.8" })
		.protocol(IPv4::IPProtocols::UDP);

	UDP udpLayer;
	udpLayer
		.length(10)
		.checksum(0x1234)
		.src(100)
		.dst(200);
			 


	// Make it into a packet
	Packet pack = (packetBuilder << etherLayer << ipv4Layer << udpLayer).build();

	// Send the 2 packets (both packets have 2 ethernet protocols which are not really useful)
	for (size_t i = 0; i < 10; i++)
	{
		device << pack;
	}
	
}