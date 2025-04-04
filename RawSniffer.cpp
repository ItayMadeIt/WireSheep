#include "RawSniffer.h"
#include <pcap/pcap.h>

RawSniffer::RawSniffer(Device& device)
	: m_device(device), m_packetViews()
{}

void RawSniffer::capture(byte4 maxPackets)
{
	pcap_pkthdr* header;
	const u_char* pkt_data;

	while (m_packetViews.count() < maxPackets)
	{
		int res = pcap_next_ex(m_device.getHandle(), &header, &pkt_data);

		if (res == 0)
		{
			break;
		}

		if (res < 0)
		{
			std::cerr << "Error capturing packets\n";
			return;
		}

		byte* curEnd = m_buffer.end();
		m_buffer.insert(pkt_data, header->caplen);
		m_packetViews.emplace_back(curEnd, static_cast<byte4>(header->caplen), header->ts);
	}
}

void RawSniffer::setFilter(const char* filterStr)
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

void RawSniffer::packetHandler(u_char* userData, const pcap_pkthdr* header, const u_char* pkt_data)
{
	std::cout << "captured" << std::endl;

	RawSniffer* sniffer = reinterpret_cast<RawSniffer*>(userData);

	if (header->caplen > MAX_PACKET_SIZE || sniffer->m_packetViews.count() >= sniffer->MAX_PACKETS)
	{
		return;
	}

	byte* curEnd = sniffer->m_buffer.end();
	sniffer->m_buffer.insert(pkt_data, header->caplen);
	sniffer->m_packetViews.emplace_back(curEnd, static_cast<byte4>(header->caplen), header->ts);
}


const IMMutablePacket& RawSniffer::getPacketView(byte4 index) const
{
	return m_packetViews[index];
}
