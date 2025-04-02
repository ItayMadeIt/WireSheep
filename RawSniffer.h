#pragma once

#include "Device.h"
#include "StaticVector.hpp"
#include "IMMutablePacket.h"

class RawSniffer {
public:
	RawSniffer(Device& device);

	void start(byte4 maxPackets = 0x200);
	void stop();

	void setFilter(const char* filterStr);

	const IMMutablePacket& getPacketView(byte4 index) const;

private:
	constexpr static const byte4 POOL_BUFFER_SIZE = 0x5000;
	constexpr static const byte4 MAX_PACKETS = 0x100;

	static void packetHandler(u_char* userData, const pcap_pkthdr* header, const u_char* pkt_data);
	
	Device& m_device;
	bool m_running;

	StaticVector<byte, POOL_BUFFER_SIZE> m_buffer;
	StaticVector<IMMutablePacket, sizeof(IMMutablePacket)* MAX_PACKETS> m_packetViews;
};
