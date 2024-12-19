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
#include "Raw.h"

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
		.src({"192.168.1.44"})
		.dst({"8.8.8.8"})
		.protocol(IPv4::IPProtocols::UDP)
		.ecn(0)
		.dscp(0)
		.ttl(128)
		.identifcation(0x1111)
		.totalLength(5 * 4 + 8 + 28); 

	UDP udpLayer;
	udpLayer
		.length(8+28)
		.src(6124)
		.dst(53);
	
	const char* rawData = ("\xFF\xFE\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\dns\x06google\x00\x00\x01\x00\x01");
	Raw raw;
	raw.push_back((const byte*)rawData, 28);

	// Make it into a packet
	Packet pack = (packetBuilder << etherLayer << ipv4Layer << udpLayer << raw).build();

	std::cout << pack << std::endl;

	device << pack;
	
}