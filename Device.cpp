#include "Device.h"

Device::Device(const std::string& deviceName) 
	: m_deviceName(deviceName)
{ 
	char errBuffer[PCAP_ERRBUF_SIZE];
	
	m_devicePtr = pcap_create(deviceName.c_str(), errBuffer);

	if (!m_devicePtr)
	{
 		throw std::exception(errBuffer);
	}

	// If activating failed
	if (pcap_activate(m_devicePtr) != 0)
	{
		strcpy_s(errBuffer, pcap_geterr(m_devicePtr));
		pcap_close(m_devicePtr);
		throw std::runtime_error(errBuffer);
	}

	m_macs = NetworkUtils::getDeviceMacs(deviceName);
}

Device::Device(const pcap_if_t* devicePtr)
{
	char errBuffer[PCAP_ERRBUF_SIZE];

	m_devicePtr = pcap_create(devicePtr->name, errBuffer);

	if (!m_devicePtr)
	{
		throw std::exception(errBuffer);
	}

	// If activating failed
	if (pcap_activate(m_devicePtr) != 0)
	{
		strcpy_s(errBuffer, pcap_geterr(m_devicePtr));
		pcap_close(m_devicePtr);
		throw std::runtime_error(errBuffer);
	}

	for (const pcap_addr* addressIt = devicePtr->addresses; addressIt != nullptr; addressIt = addressIt->next)
	{
		if (addressIt->addr->sa_family == AF_INET) // ipv4
		{
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)addressIt->addr;
			
			char ipStr[INET_ADDRSTRLEN];

			inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, sizeof(ipStr));

			m_ipv4s.host = AddrIPv4(ipStr);
		}
	}

	m_macs = NetworkUtils::getDeviceMacs(devicePtr->name);
}

Device::~Device()
{
	// Deactivate and close the device
	if (m_devicePtr)
	{
		pcap_close(m_devicePtr);
	}
}

AddrMac Device::getDeviceMac() const
{
	return m_macs.host;
}

AddrMac Device::getRouterMac() const
{
	return m_macs.router;
}

AddrIPv4 Device::getDeviceIPv4() const
{
	return m_ipv4s.host;
}

AddrIPv4 Device::getRouterIPv4() const
{
	throw std::exception("Not implemented");
	return m_ipv4s.router;
}

void Device::sendPacket(const Packet& packet)
{
	const std::vector<byte>& buffer = packet;

	// Send the packet
	if (pcap_sendpacket(m_devicePtr, buffer.data(), buffer.size()) != 0)
	{
		throw std::exception("Failed to send packet.");
	}
}

Device& operator<<(Device& device, const Packet& packet)
{
	device.sendPacket(packet);

	return device;
}
