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
#include "ICMP.h"

void* operator new(size_t size)
{
	std::cout << "Size: " << size << std::endl;

	return malloc(size);
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
		.dst({ "8.8.4.4" })
		.protocol(IPv4::Protocols::ICMP)
		.flags(IPv4::Flags::NONE)
		.ecn(0b10);

	ICMP& icmp = packet.attach<ICMP>();
	icmp.echoRequest(packet, 0x1234, 0x5678, "name", sizeof("name"));

	// calculates everything, for example, padding for Ethernet protocol, IP and transport layers checksum, every dynamic things
	packet.compile(); 
	std::cout << packet;

	device << packet;
}