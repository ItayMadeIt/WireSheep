#include "Device.h"

Device::Device(const std::string& deviceName)
{
	if (deviceName.size() >= MAX_DEVICE_NAME)
	{
		throw std::runtime_error("Invalid Device Name");
	}
	std::memcpy(m_deviceName, deviceName.c_str(), deviceName.size());

	char errBuffer[PCAP_ERRBUF_SIZE];

	m_devicePtr = pcap_create(m_deviceName, errBuffer);

	if (!m_devicePtr)
	{
		throw std::exception(errBuffer);
	}

	pcap_set_promisc(m_devicePtr, 1);
	//pcap_set_immediate_mode(m_devicePtr, 1);
	pcap_set_buffer_size(m_devicePtr, 4 * 1024 * 1024);
	pcap_set_timeout(m_devicePtr, 1000);

	// If activating failed
	if (pcap_activate(m_devicePtr) != 0)
	{
		strcpy_s(errBuffer, pcap_geterr(m_devicePtr));
		pcap_close(m_devicePtr);
		throw std::runtime_error(errBuffer);
	}

	m_macs = NetworkUtils::getDeviceMacs(m_deviceName);
}

Device::Device(const char* deviceName)
{
	size_t size = strlen(deviceName);
	if (size >= MAX_DEVICE_NAME)
	{
		throw std::runtime_error("Invalid Device Name");
	}

	std::memcpy(m_deviceName, deviceName, strlen(deviceName) + 1);

	char errBuffer[PCAP_ERRBUF_SIZE];
	
	m_devicePtr = pcap_create(m_deviceName, errBuffer);

	if (!m_devicePtr)
	{
 		throw std::exception(errBuffer);
	}

	pcap_set_promisc(m_devicePtr, 1);
	//pcap_set_immediate_mode(m_devicePtr, 1);
	pcap_set_buffer_size(m_devicePtr, 4 * 1024 * 1024);
	pcap_set_timeout(m_devicePtr, 1000);

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

	pcap_set_promisc(m_devicePtr, 1);
	//pcap_set_immediate_mode(m_devicePtr, 1);
	pcap_set_buffer_size(m_devicePtr, 4 * 1024 * 1024);
	pcap_set_timeout(m_devicePtr, 1000);

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
	const byte* buffer = packet.buffer();
	const size_t size = packet.size();

	// Send the packet
	if (pcap_sendpacket(m_devicePtr, buffer, size) != 0)
	{
		std::string err = pcap_geterr(m_devicePtr);
		throw std::runtime_error("Failed to send packet: " + err);
	}
}


pcap_t* Device::getHandle()
{
	return m_devicePtr;
}

void Device::sendPacket(const std::vector<byte>& buffer)
{
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

Device& operator<<(Device& device, const std::vector<byte>& buffer)
{
	device.sendPacket(buffer);

	return device;
}
