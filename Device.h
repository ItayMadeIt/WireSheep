#pragma once

#include <pcap/pcap.h>
#include <iostream>
#include <sstream>
#include <string>
#include "Helper.h"
#include "Packet.h"

class Device
{
public:
	Device(const std::string& deviceName);
	~Device();

	friend Device& operator<<(Device& device, const Packet& packet);

private:
	void sendPacket(const Packet& packet);

	pcap_t* m_devicePtr;
	std::string m_deviceName;
};
