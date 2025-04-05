#include "ClassifySniffer.h"
#include <functional>

ClassifySniffer::ClassifySniffer(Device& device, Classifier* classifier)
	: m_device(device), m_buffer(), m_classifiedPackets(), m_running(false), m_classifier(classifier), m_filter(nullptr)
{}

void ClassifySniffer::setClassifier(Classifier* newClassifier)
{
	m_classifier = newClassifier;
}

bool ClassifySniffer::capture(byte4 maxPackets)
{
	if (m_classifier == nullptr)
	{
		return false;
	}

	m_running = true;

	while (m_running && m_classifiedPackets.count() < maxPackets)
	{
		byte* backPtr = m_buffer.end();
		IMMutablePacket curPacket{ backPtr, MAX_PACKET_SIZE};

		int res = m_device >> curPacket; 

		// error
		if (res == 0)
		{
			std::cout << "Timeout occurred. Reason: " << pcap_geterr(m_device.getHandle()) << "\n";
			m_running = false;
			return false;
		}
		
		if (res == -1)
		{
			// my special `buffer too large error`
			continue;
		}

		if (res < 0)
		{
			std::cerr << "[Error] " << pcap_geterr(m_device.getHandle()) << std::endl;
			return false;
		}

		m_buffer.resize(m_buffer.size() + curPacket.size());
		m_classifiedPackets.emplace_back(backPtr, (byte4)curPacket.size(), curPacket.getTimestamp());
		
		m_classifier->parse(m_classifiedPackets.back());
		
		if (m_filter == nullptr)
		{
			continue;
		}

		if (m_filter(m_classifiedPackets.back()) == false)
		{
			m_classifiedPackets.pop_back();
			m_buffer.erase_back(curPacket.size());
		}
	}

	return true;
}

bool ClassifySniffer::callbackCapture(byte4 maxPackets)
{
	if (m_classifier == nullptr)
	{
		return false;
	}

	m_running = true;

	m_packets = 0;

	while (m_running && m_packets < maxPackets)
	{
		int res = pcap_dispatch(m_device.getHandle(), -1, packetHandler, reinterpret_cast<u_char*>(this));

		if (res == 0)
		{
			std::cerr << "[Error] Dispatch timed out" << std::endl;
			continue;
		}

		if (res == -1)
		{
			std::cerr << "[Error] " << pcap_geterr(m_device.getHandle()) << std::endl;
			return false;
		}
	}

	return true;
}

void ClassifySniffer::setCallback(std::function<void(ClassifiedPacket& packet)> callback)
{
	m_callback = callback;
}

void ClassifySniffer::setFilter(const char* filterStr)
{
	pcap_t* handle = m_device.getHandle();

	struct bpf_program filter;

	// Compile filter (optimized = 1, netmask = 0 if unknown)
	if (pcap_compile(handle, &filter, filterStr, 1, PCAP_NETMASK_UNKNOWN) == -1)
	{
		throw std::runtime_error(pcap_geterr(handle));
	}

	if (pcap_setfilter(handle, &filter) == -1)
	{
		throw std::runtime_error(pcap_geterr(handle));
	}
}

void ClassifySniffer::setFilter(std::function<bool(ClassifiedPacket& packet)> filter)
{
	m_filter = filter;
}

ClassifiedPacket& ClassifySniffer::getClassifiedPacket(byte4 index)
{
	return m_classifiedPackets[index];
}

void ClassifySniffer::packetHandler(u_char* userData, const pcap_pkthdr* header, const u_char* packetData)
{
	reinterpret_cast<ClassifySniffer*>(userData)->createPacketHandler(header, packetData);
}

void ClassifySniffer::createPacketHandler(const pcap_pkthdr* header, const u_char* packetData)
{
	byte* backPtr = m_buffer.end();
	IMMutablePacket curPacket{ backPtr, MAX_PACKET_SIZE };

	if (header->caplen > MAX_PACKET_SIZE)
	{
		return;
	}

	std::memcpy(curPacket.buffer(), packetData, header->caplen);
	curPacket.size(header->caplen);
	curPacket.setTimestamp(header->ts);

	m_buffer.resize(m_buffer.size() + curPacket.size());
	m_classifiedPackets.emplace_back(backPtr, (byte4)curPacket.size(), curPacket.getTimestamp());

	m_classifier->parse(m_classifiedPackets.back());

	if (m_filter == nullptr)
	{
		m_callback(m_classifiedPackets.back());
		m_packets++;
		return;
	}

	if (m_filter(m_classifiedPackets.back()) == false)
	{
		// remove it
		m_classifiedPackets.pop_back();
		m_buffer.erase_back(curPacket.size());
	}
	else
	{
		m_callback(m_classifiedPackets.back());
		m_packets++;
	}
}
