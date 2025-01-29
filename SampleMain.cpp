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

	Device device(devices[4]);
	
	// Create packet
	PacketBuilder packetBuilder;
	
	/*
	Ethernet ether;
	ether
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(Ethernet::Protocols::IPv4);

	IPv4 ipv4;
	ipv4
		.src({ "192.168.1.41" })
		.dst({ "8.8.8.8" })
		.protocol(IPv4::Protocols::UDP)
		.flags(IPv4::Flags::NONE)
		.ecn(0b10);

	UDP udp;
	udp
		.src(120)
		.dst(80);

	Raw raw;
	raw.push_back('H');
	raw.push_back('i');
	raw.push_back('!');

	Packet packet = (packetBuilder << ether << ipv4 << udp << raw).build();
	// Print both packets bytes
	std::cout << packet << std::endl;

	// Send packet
	device << packet;
	*/

	/*
	Ethernet etherLayer;
	etherLayer
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(Ethernet::Protocols::ARP);

	ARP arpLayer;
	arpLayer
		.hardwareType(ARP::HardwareType::Ether)
		.senderHardwareAddr(device.getDeviceMac())
		.targetHardwareAddr(addrMac::broadcast)
		.senderProtocolAddr({ "192.168.1.41" })
		.targetProtocolAddr({ "192.168.1.1" });

	// Make it into a packet
	Packet pack = (packetBuilder << etherLayer << arpLayer).build();

	// Print both packets bytes
	std::cout << pack << std::endl;

	// Send packet
	device << pack;*/

	/*
	Ethernet etherLayer;
	etherLayer
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(Ethernet::Protocols::IPv4);

	IPv4 ipv4Layer;
	ipv4Layer
		.src({ "192.168.1.41" })
		.dst({ "8.8.8.8" })
		.protocol(IPv4::Protocols::UDP)
		.flags(IPv4::Flags::NONE)
		.ecn(0b10);

	UDP udpLayer;
	udpLayer
		.src(49999)
		.dst(53);

	DNS dnsLayer;
	dnsLayer.addQuestion("example.com", (byte2)DNS::RRType::A, (byte2)DNS::RRClass::Internet);

	// Make it into a packet
	Packet pack = (packetBuilder << etherLayer << ipv4Layer << udpLayer << dnsLayer).build();

	// Print both packets bytes
	std::cout << pack << std::endl;
	
	// Send packet
	device << pack;
	*/
	
	Ethernet etherLayer;
	etherLayer
		.src(device.getDeviceMac())
		.dst(device.getRouterMac())
		.type(Ethernet::Protocols::IPv4);

	IPv4 ipv4Layer;
	ipv4Layer
		.protocol(IPv4::Protocols::TCP)
		.identifcation(0x0)
		.flags(IPv4::Flags::DF)
		.ecn(0)
		.ttl(128)
		.src({ device.getDeviceIPv4() })
		.dst({ "142.250.75.174" })
		.dscp((byte)IPv4::Services::CS0);

	TCP tcpLayer;
	tcpLayer
		.seqNum(0)
		.ackNum(0)
		.srcPort(54321)
		.dstPort(80)
		.window(0xF0)
		.flags((byte2)TCP::Flags::SYN)
		.addOption<TCP::OptionMaxSegmentSize>(1460)
		.addOption<TCP::OptionNoOperation>()
		.addOption<TCP::OptionWindowScale>(8)
		.addOption<TCP::OptionNoOperation>()
		.addOption<TCP::OptionNoOperation>()
		.addOption<TCP::OptionSelectiveAckPermitted>();

	Packet pack = (packetBuilder << etherLayer << ipv4Layer << tcpLayer).build();

	std::cout << pack;

	device << pack;
}