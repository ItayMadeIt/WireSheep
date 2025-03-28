#include <pcap.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include "Device.h"
#include "NetworkUtils.h"
#include "EthernetProtocol.h"
#include "IPv4Protocol.h"
#include "UDPProtocol.h"
#include "RawProtocol.h"
#include "DNSProtocol.h"
#include "DeviceList.h"
#include "ARPProtocol.h"
#include "TCPProtocol.h"
#include "MutablePacket.h"
#include <thread>

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

	Device device(devices[8]);
	
	MutablePacket packet;

	Ethernet& ethernet = packet.attach<Ethernet>();
	ethernet
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(Ethernet::Protocols::IPv4);

	IPv4& ipv4 = packet.attach<IPv4>();
	ipv4
		.src(device.getDeviceIPv4())
		.dst({ "8.8.8.8" })
		.protocol(IPv4::Protocols::UDP)
		.flags(IPv4::Flags::NONE)
		.ecn(0b10);

	UDP& udp = packet.attach<UDP>();
	udp
		.src(0x1234)
		.dst(53);

	DNS& dns = packet.attach<DNS>();
	dns 
		.addQuestion(packet, DNS::formatDomain("google.com"), (byte2)DNS::RRType::AAAA, (byte2)DNS::RRClass::Internet);

	// calculates everything, for example, padding for Ethernet protocol, IP and transport layers checksum, every dynamic things
	packet.compile(); 

	device << packet;
}