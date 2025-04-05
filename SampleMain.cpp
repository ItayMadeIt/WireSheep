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
#include "Classifier.h"
#include "ClassifySniffer.h"


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

bool myFilter(ClassifiedPacket& packet)
{
	/*
	// For example DNS

	IPv4* ip = nullptr;
	if (!packet.tryGet<IPv4>(ip))
	{
		return false;
	}

	address::AddrIPv4 addr = "8.8.4.4";
	if (ip->src() != addr && ip->dst() != addr)
	{
		return false;
	}

	DNS* dns = nullptr;
	if (!packet.tryGet<DNS>(dns))
	{
		return false;
	}

	return true;*/

	/*
	// ARP request
	ARP* arp = nullptr;
	if (!packet.tryGet<ARP>(arp))
	{
		return false;
	}

	return arp->protocolLength() == ADDR_IP4_BYTES && arp->hardwareLength() == ADDR_MAC_BYTES;
	*/

	ICMP* icmp;
	return packet.tryGet<ICMP>(icmp);
}

int main()
{
	using namespace address;

	DeviceList devices;

	std::cout << devices;

	Device device(devices[6]);

	Classifier::init();

	ClassifySniffer sniffer(device, &Classifier::basicClassifier());

	const int CAPTURE_AMOUNT = 2;

	sniffer.setFilter(myFilter);
	bool succeed = sniffer.capture(CAPTURE_AMOUNT);

	if (!succeed)
	{
		std::cerr << "Capture failed." << std::endl;
		return - 1; 
	}

	for (ClassifiedPacket& packet : sniffer)
	{
		std::cout << "Packet " << " ["  << packet.getRaw().size() << "]" << std::endl;
		std::cout << packet.getRaw() << std::endl;
	
		Ethernet& ether = packet.get<Ethernet>();
		std::cout << ether << std::endl;

		IPv4& ip = packet.get<IPv4>();
		std::cout << ip << std::endl;
		
		ICMP& arp = packet.get<ICMP>();
		std::cout << arp << std::endl;
	}
}