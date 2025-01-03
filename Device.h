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
	Device(const pcap_if_t* windowsDevicePtr);
	~Device();

	friend Device& operator<<(Device& device, const Packet& packet);

	/// <summary>
	/// Gets the mac address of the network
	/// </summary>
	/// <returns>Network's mac address</returns>
	addrMac getDeviceMac() const;
	/// <summary>
	/// Gets the mac address of the network's roueter
	/// </summary>
	/// <returns>Network's routere mac address</returns>
	addrMac getRouterMac() const;

private:
	void sendPacket(const Packet& packet);

	pcap_t* m_devicePtr;
	std::string m_deviceName;
	DeviceMacs m_macs;
};
