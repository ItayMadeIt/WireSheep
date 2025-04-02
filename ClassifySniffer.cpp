#include "ClassifySniffer.h"

ClassifySniffer::ClassifySniffer(Device& device, Classifier* classifier)
	: m_device(device), m_buffer(), m_classifiedPackets(0), m_running(false), m_classifier(classifier)
{}

void ClassifySniffer::setClassifier(Classifier & newClassifier)
{
	m_classifier = newClassifier;
}

void ClassifySniffer::start(byte4 maxPackets)
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

		byte* curEnd = m_buffer.end();

		m_buffer.insert(pkt_data, header->caplen);
		m_classifiedPackets.emplace_back(curEnd, (byte4)header->caplen, header->ts);
		m_classifier->parse(m_classifiedPackets.back());
	}
}

const ClassifiedPacket& ClassifySniffer::getClassifiedPacket(byte4 index) const
{
	return m_classifiedPackets[index];
}
