#pragma once

#include <pcap/pcap.h>
#include <ostream>

class DeviceList
{
public:
	DeviceList();
	~DeviceList();

	friend std::ostream& operator<<(std::ostream& os, const DeviceList& deviceList);

	pcap_if_t* operator[](const size_t index);

private:
	pcap_if_t* m_firstDevice;
};