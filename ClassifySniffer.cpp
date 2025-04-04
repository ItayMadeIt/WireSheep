#include "ClassifySniffer.h"

ClassifySniffer::ClassifySniffer(Device& device, Classifier* classifier)
	: m_device(device), m_buffer(), m_classifiedPackets(), m_running(false), m_classifier(classifier)
{}

void ClassifySniffer::setClassifier(Classifier* newClassifier)
{
	m_classifier = newClassifier;
}

void ClassifySniffer::capture(byte4 maxPackets)
{
	if (m_classifier == nullptr)
	{
		return;
	}

	m_running = true;

	pcap_pkthdr* header;
	const u_char* pkt_data;

	while (m_running && m_classifiedPackets.count() < maxPackets)
	{
		int res = (pcap_next_ex(m_device.getHandle(), &header, &pkt_data));

		// error
		if (res <= 0)
		{
			m_running = false;
			return;
		}

		byte* backPtr = m_buffer.end();
		m_buffer.insert(pkt_data, header->caplen);
		
		m_classifiedPackets.emplace_back(backPtr, (byte4)header->caplen, header->ts);
		
		m_classifier->parse(m_classifiedPackets.back());
	}

	std::cout << "Classified count: " << m_classifiedPackets.count() << std::endl;
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

ClassifiedPacket& ClassifySniffer::getClassifiedPacket(byte4 index)
{
	return m_classifiedPackets[index];
}
