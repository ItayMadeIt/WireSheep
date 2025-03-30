#pragma once

#include <pcap/pcap.h>
#include <iostream>
#include <sstream>
#include <string>
#include "Helper.h"
#include "Packet.h"
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

private:
	void sendPacket(const Packet& packet);
	void sendPacket(const std::vector<byte>& buffer);

	pcap_t* m_devicePtr;
	char m_deviceName[MAX_DEVICE_NAME];
	DeviceMacs m_macs;
	DeviceIPv4 m_ipv4s;
};
