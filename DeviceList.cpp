#include "DeviceList.h"
#include "ARPProtocol.h"
#include <iostream>

DeviceList::DeviceList()
{
	char errBuffer[1024];
	if (pcap_findalldevs(&m_firstDevice, errBuffer) != 0)
	{
		std::cerr << "[Error DeviceList::DeviceList()] " << errBuffer << std::endl;
	}
}

DeviceList::~DeviceList()
{
	pcap_freealldevs(m_firstDevice);
}

pcap_if_t* DeviceList::operator[](const size_t index)
{
	pcap_if_t* device = m_firstDevice;
	for (size_t i = 0; i < index; i++)
	{
		if (!device)
		{
			return nullptr;
		}

		device = device->next;
	}
	return device;
}

std::ostream& operator<<(std::ostream& os, const DeviceList& deviceList)
{
	os << "Device List:\n";

	size_t index = 0;

	for (pcap_if_t* curDevice = deviceList.m_firstDevice;
		curDevice != NULL; curDevice = curDevice->next)
	{
		os << " Device #" << index++ << '\n';
		os << "  Name: " << curDevice->name << '\n';
		os << "  Description: " << curDevice->description << '\n';

		// Will add addresses sometime later
	}

	os << std::endl;

	return os;
}
