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
#include "ICMPProtocol.h"
#include "RawSniffer.h"
//#include "ClassifySniffer.h"

void* operator new(size_t size)
{
	std::cout << "Size: " << size << std::endl;

	void* ptr = malloc(size);

	if (ptr == nullptr)
	{
		throw std::runtime_error("Couldn't get allocated memory.");
	}

	return ptr;
}

int main()
{
	using namespace address;

	DeviceList devices;

	std::cout << devices;

	Device device(devices[8]);

	RawSniffer sniffer(device);

	sniffer.setFilter("arp or (ip and !udp)");

	sniffer.start(100);
	for (int i = 0; i < 100; i++)
	{
		const IMMutablePacket packet = sniffer.getPacketView(i);
		std::cout << "Packet [" << i << "]" << std::endl;
		std::cout << packet << std::endl;
	}
}