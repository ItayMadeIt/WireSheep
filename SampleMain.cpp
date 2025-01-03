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
#include "DNS.h"
#include "DeviceList.h"

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

	DeviceList devices;
	std::cout << devices; 

	Device device(devices[9 - 1]);
	
	// Create packet
	PacketBuilder packetBuilder;

	Ethernet etherLayer;
	etherLayer
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(0x0800);

	IPv4 ipv4Layer;
	ipv4Layer
		.src({ "192.168.1.44" })
		.dst({ "8.8.8.8" })
		.protocol(IPv4::Protocols::UDP)
		.flags(IPv4::Flags::NONE)
		.ecn(0b10);

	UDP udpLayer;
	udpLayer
		.src(6543)
		.dst(53);

	DNS dnsLayer;
	dnsLayer.addQuestion("dns.google", (byte2)DNS::RRType::A, (byte2)DNS::RRClass::Internet);

	// Make it into a packet
	Packet pack = (packetBuilder << etherLayer << ipv4Layer << udpLayer << dnsLayer).build();

	// Print both packets bytes
	std::cout << pack << std::endl;

	// Send packet
	device << pack;
	
}