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
#include "ARP.h"
#include "TCP.h"

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

	Device device(devices[3]);
	
	// Create packet
	PacketBuilder packetBuilder;

	Ethernet etherLayer;
	etherLayer
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(Ethernet::ProtocolTypes::IPv4);

	IPv4 ipv4Layer;
	ipv4Layer
		.protocol(IPv4::Protocols::TCP)
		.identifcation(0x8b34)
		.flags(IPv4::Flags::DF)
		.ecn(0)
		.ttl(128)
		.src({ "192.168.1.44" })
		.dst({ "34.223.124.45" })
		.dscp((byte)IPv4::Services::CS0);

	TCP tcpLayer;
	tcpLayer
		.seqNum(0xF1698C60)
		.ackNum(0)
		.srcPort(0x7938)
		.dstPort(80)
		.window(0xFFFF)
		.flags((byte)TCP::Flags::SYN)
		.addOption<TCP::OptionMaxSegmentSize>(1460)
		.addOption<TCP::OptionNoOperation>()
		.addOption<TCP::OptionWindowScale>(8)
		.addOption<TCP::OptionNoOperation>()
		.addOption<TCP::OptionNoOperation>()
		.addOption<TCP::OptionSelectiveAckPermitted>();

	Packet pack = (packetBuilder << etherLayer << ipv4Layer << tcpLayer).build();

	std::cout << pack;

	device << pack;

	/*
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
	*/
}