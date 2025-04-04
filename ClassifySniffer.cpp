#include "ClassifySniffer.h"

ClassifySniffer::ClassifySniffer(Device& device, Classifier* classifier)
	: m_device(device), m_buffer(), m_classifiedPackets(), m_running(false), m_classifier(classifier), m_customFilter(nullptr)
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

		m_buffer.insert(curPacket.buffer(), curPacket.size());
		m_classifiedPackets.emplace_back(backPtr, (byte4)curPacket.size(), curPacket.getTimestamp());
		
		m_classifier->parse(m_classifiedPackets.back());
		
		if (m_customFilter == nullptr)
		{
			continue;
		}

		if (m_customFilter(m_classifiedPackets.back()) == false)
		{
			m_classifiedPackets.pop_back();
			m_buffer.erase_back(curPacket.size());
		}
	}

	return true;
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

void ClassifySniffer::setFilter(bool(*customFilter)(ClassifiedPacket& packet))
{
	m_customFilter = customFilter;
}

ClassifiedPacket& ClassifySniffer::getClassifiedPacket(byte4 index)
{
	return m_classifiedPackets[index];
}
