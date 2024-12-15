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
}

Device::~Device()
{
	// Deactivate and close the device
	if (m_devicePtr)
	{
		pcap_close(m_devicePtr);
	}
}
