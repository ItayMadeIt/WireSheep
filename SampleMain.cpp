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

bool applyEther(ClassifiedPacket& packet)
{
	packet.add<Ethernet>();
 
	return true;
}

bool applyARP(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;
	Ethernet& ether = packet.get<Ethernet>(protocolIndex);

	if (ether.type() != (byte2)Ethernet::Protocols::ARP)
	{
		return false;
	}

	packet.add<ARP>();
	return true;
}

bool applyIPv4(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;
	Ethernet& ether = packet.get<Ethernet>(protocolIndex);
	
	if (ether.type() != (byte2)Ethernet::Protocols::IPv4)
	{
		return false;
	}

	IPv4& ipv4 = packet.add<IPv4>();

	// valid ipv4 data
	if (ipv4.version() != 4 && ipv4.ihl() >= 5)
	{
		packet.pop();
		return false;
	}

	return true;
}

bool applyUDP(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;
	IPv4& ipv4 = packet.get<IPv4>(protocolIndex);
	if (ipv4.protocol() != (byte)IPv4::Protocols::UDP)
	{
		return false;
	}

	packet.add<UDP>();

	return true;
}

bool applyTCP(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;

	IPv4& ipv4 = packet.get<IPv4>(protocolIndex);
	if (ipv4.protocol() != (byte)IPv4::Protocols::TCP)
	{
		return false;
	}

	packet.add<TCP>();

	return true;
}

bool applyDNS(ClassifiedPacket& packet)
{
	DNS& dns = packet.add<DNS>();
	if (!dns.syncFields(packet.unidentifiedPacketSize() + DNS::BASE_SIZE))
	{
		packet.pop();
		return false;
	}

	return true;
}

bool myFilter(ClassifiedPacket& packet)
{
	// For example DNS + question name is dns.google

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

	return true;
}

int main()
{
	using namespace address;

	DeviceList devices;

	std::cout << devices;

	Device device(devices[6]);

	Classifier classifier;
	classifier.addRule(ProvidedProtocols::None, applyEther);
	classifier.addRule(ProvidedProtocols::Ethernet, applyIPv4);
	classifier.addRule(ProvidedProtocols::Ethernet, applyARP);
	classifier.addRule(ProvidedProtocols::IPv4, applyUDP);
	classifier.addRule(ProvidedProtocols::IPv4, applyTCP);
	classifier.addRule(ProvidedProtocols::UDP, applyDNS);

	ClassifySniffer sniffer(device, &classifier);

	//sniffer.setFilter("udp");
	sniffer.setFilter(myFilter);
	bool succeed = sniffer.capture(5);

	if (!succeed)
	{
		std::cerr << "Capture failed." << std::endl;
		return - 1;
	}

	for (int i = 0; i < 5; i++)
	{
		ClassifiedPacket& packet = sniffer.getClassifiedPacket(i);

		std::cout << "Packet #" << i << " ["  << packet.getRaw().size() << "]" << std::endl;
		std::cout << packet.getRaw() << std::endl;
	
		DNS& dns = packet.get<DNS>();
		std::cout << dns << std::endl << std::endl;

	}
}