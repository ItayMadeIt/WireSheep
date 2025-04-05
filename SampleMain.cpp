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
	
	/*
	ICMP* icmp;
	return packet.tryGet<ICMP>(icmp);
	*/
	return false;
}

bool dnsFilter(ClassifiedPacket& packet)
{
	DNS* dns;
	return (packet.tryGet<DNS>(dns));
}

void sendDnsPacket(Device& device)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	MutablePacket packet;
	Ethernet& ether = packet.attach<Ethernet>();
	// from my device to my device
	ether.src(device.getDeviceMac());
	ether.dst(device.getDeviceMac());
	ether.type(Ethernet::Protocols::IPv4);

	IPv4& ipv4 = packet.attach<IPv4>();
	ipv4.dscp((byte)IPv4::Services::CS0);
	ipv4.version(4);
	ipv4.ihl(5);
	ipv4.identification(0x1234);
	ipv4.src(device.getDeviceIPv4());
	ipv4.dst("8.8.8.8");
	ipv4.protocol(IPv4::Protocols::UDP);
	ipv4.ttl(64);

	UDP& udp = packet.attach<UDP>();
	udp.src(0x1234);
	udp.dst(53);

	DNS& dns = packet.attach<DNS>();
	dns.addQuestion(packet, DNS::formatDomain("wikipedia.com"), (byte)DNS::RRType::A, (byte)DNS::RRClass::Internet);

	packet.compile();

	device << packet;
	std::cout << "Sent wikipedia.com" << std::endl;

	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	packet.detach();// remove last DNS
	DNS& dns2 = packet.attach<DNS>();
	dns2.addQuestion(packet, DNS::formatDomain("youtube.com"), (byte)DNS::RRType::A, (byte)DNS::RRClass::Internet);

	packet.compile();

	device << packet;
	std::cout << "Sent youtube.com" << std::endl;
}

int main()
{
	using namespace address;

	DeviceList devices;

	std::cout << devices;

	Device device(devices[6]);

	Classifier::init();

	ClassifySniffer sniffer(device, &Classifier::basicClassifier());

	const int CAPTURE_AMOUNT = 8;

	sniffer.setFilter("udp"); // basic filter
	sniffer.setFilter(dnsFilter); // udp port filter
	sniffer.setCallback(
		[&device](ClassifiedPacket& recvPacket) -> void
		{
			std::cout << "Packet " << " [" << recvPacket.getRaw().size() << "]" << std::endl;

			DNS& recvDNS = recvPacket.get<DNS>();
			std::cout << recvDNS << std::endl;
		}
	);
	
	std::thread sendThread(
		[&]()
		{
			sendDnsPacket(device);
		}
	);

	bool succeed = sniffer.callbackCapture(CAPTURE_AMOUNT);
	sendThread.join();

	return 0;
}