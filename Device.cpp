#include "Device.h"
#include "IMMutablePacket.h"
#include "StaticVector.hpp"

Device::Device(const std::string& deviceName)
{
	initDevice(deviceName.c_str());
}

Device::Device(const char* deviceName)
{
	initDevice(deviceName);
}

Device::Device(const pcap_if_t* devicePtr)
{
	initDevice(devicePtr->name);

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
}

Device::~Device()
{
	// Deactivate and close the device
	if (m_devicePtr)
	{
		pcap_close(m_devicePtr);
	}
}

void Device::initDevice(const char* deviceName)
{
	size_t size = strlen(deviceName);
	if (size >= MAX_DEVICE_NAME)
	{
		throw std::runtime_error("Invalid Device Name");
	}

	std::memcpy(m_deviceName, deviceName, size + 1);

	char errBuffer[PCAP_ERRBUF_SIZE];

	// Open the device 
	m_devicePtr = pcap_create(m_deviceName, errBuffer);
	if (!m_devicePtr)
	{
		throw std::runtime_error("Failed to create device");
	}

	// Set options BEFORE activation
	if (pcap_set_promisc(m_devicePtr, 1) != 0)
	{
		throw std::runtime_error("Failed to set promiscuous mode");
	}

	if (pcap_set_buffer_size(m_devicePtr, 512 * 1024) != 0)
	{
		throw std::runtime_error("Failed to set buffer size");
	}

	if (pcap_set_timeout(m_devicePtr, 5000) != 0)
	{
		throw std::runtime_error("Failed to set timeout");
	}

	if (pcap_activate(m_devicePtr) != 0)
	{
		throw std::runtime_error("Failed to activate device");
	}

	m_macs = NetworkUtils::getDeviceMacs(deviceName);
}

bool Device::openLiveCapture()
{
	char errBuffer[PCAP_ERRBUF_SIZE];

	static constexpr int MAX_BYTE2_VALUE = 65535;
	m_devicePtr = pcap_open_live(m_deviceName, MAX_BYTE2_VALUE, 1, 1000, errBuffer);

	if (!m_devicePtr)
	{
		std::cerr << "Error opening device for capture: " << errBuffer << std::endl;
		return false;
	}

	return true;
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

int Device::recvPacket(pcap_pkthdr*& header, const byte*& pkt_data)
{
	byte4 res = pcap_next_ex(m_devicePtr, &header, &pkt_data);

	return res;
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

int operator>>(Device& device, Packet& packet)
{
	pcap_pkthdr* pkt_header;
	const byte* pkt_buffer = nullptr;
	int res = device.recvPacket(pkt_header, pkt_buffer);

	std::memcpy(packet.buffer(), pkt_buffer, pkt_header->caplen);
	packet.size(pkt_header->caplen);

	return res;
}


int operator>>(Device& device, IMMutablePacket& packet)
{
	pcap_pkthdr* pkt_header = nullptr;
	const byte* pkt_buffer = nullptr;
	int res = device.recvPacket(pkt_header, pkt_buffer);

	if (res == 0)
	{
		return 0;
	}

	if (pkt_header->caplen > packet.size())
	{
		return -1;
	}

	std::memcpy(packet.buffer(), pkt_buffer, pkt_header->caplen);
	packet.size(pkt_header->caplen);

	packet.setTimestamp(pkt_header->ts);

	return res;
}
