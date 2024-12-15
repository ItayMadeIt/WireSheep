#pragma once

#include <pcap/pcap.h>
#include <iostream>
#include <string>

class Device
{
public:
	Device(const std::string& deviceName);
	~Device();


private:
	pcap_t* m_devicePtr;
	std::string m_deviceName;
};
