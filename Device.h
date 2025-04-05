#pragma once

#include <pcap/pcap.h>
#include <iostream>
#include <sstream>
#include <string>
#include "Helper.h"
#include "Packet.h"
#include "IMMutablePacket.h"
#include "NetworkUtils.h"

class Device
{
public:
	Device(const std::string& deviceName);
	Device(const char* deviceName);
	Device(const pcap_if_t* devicePtr);
	~Device();

	friend Device& operator<<(Device& device, const Packet& packet);
	friend Device& operator<<(Device& device, const std::vector<byte>& buffer);

	friend int operator>>(Device& device, Packet& packet);
	friend int operator>>(Device& device, IMMutablePacket& packet);

	/// <summary>
	/// Gets the mac address of the network
	/// </summary>
	/// <returns>Network's mac address</returns>
	AddrMac getDeviceMac() const;

	/// <summary>
	/// Gets the mac address of the network's roueter
	/// </summary>
	/// <returns>Network's routere mac address</returns>
	AddrMac getRouterMac() const;

	/// <summary>
	/// Gets the IPv4 address of the network
	/// </summary>
	/// <returns>Network's IPv4 address</returns>
	AddrIPv4 getDeviceIPv4() const;

	/// <summary>
	/// Gets the IPv4 address of the network's roueter
	/// </summary>
	/// <returns>Network's routere IPv4 address</returns>
	AddrIPv4 getRouterIPv4() const;

	pcap_t* getHandle();

private:
	void initDevice(const char* deviceName);

	bool openLiveCapture();
	
	void sendPacket(const Packet& packet);
	void sendPacket(const std::vector<byte>& buffer);

	int recvPacket(pcap_pkthdr*& header, const byte*& pkt_data);

	pcap_t* m_devicePtr;
	char m_deviceName[MAX_DEVICE_NAME];
	DeviceMacs m_macs;
	DeviceIPv4 m_ipv4s;
};
