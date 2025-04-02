#include "RawSniffer.h"
#include <pcap/pcap.h>

RawSniffer::RawSniffer(Device& device)
	: m_device(device), m_packetViews()
{}

void RawSniffer::start(byte4 maxPackets)
{
	m_running = true;

	pcap_pkthdr* header;
	const u_char* pkt_data;

	while (m_running && m_packetViews.count() < maxPackets)
	{
		int res = pcap_dispatch(
			m_device.getHandle(), 
			16, 
			&RawSniffer::packetHandler, 
			reinterpret_cast<u_char*>(this)
		);

		if (res < 0)
		{
			std::cerr << "Error capturing packets\n";
			m_running = false;
			return;
		}
	}
}

void RawSniffer::stop()
{
	m_running = false;
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
