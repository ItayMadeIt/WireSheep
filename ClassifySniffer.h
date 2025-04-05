#pragma once

#include <functional>
#include "Device.h"
#include "StaticVector.hpp"
#include "IMMutablePacket.h"
#include "ClassifiedPacket.h"
#include "Classifier.h"


class ClassifySniffer {
public:
	ClassifySniffer(Device& device, Classifier* classifier=nullptr);

	void setClassifier(Classifier* newClassifier);

	bool capture(byte4 maxPackets = 0x200);
	bool callbackCapture(byte4 maxPackets);

	void setCallback(std::function<void(ClassifiedPacket& packet)> callback);

	void setFilter(const char* filterStr);
	void setFilter(std::function<bool(ClassifiedPacket& packet)> filter);

	ClassifiedPacket& getClassifiedPacket(byte4 index);


	struct PacketIterator
	{
		using iterator_category = std::forward_iterator_tag;
		using difference_type = std::ptrdiff_t;
		using value_type = ClassifiedPacket;
		using pointer = ClassifiedPacket*;  // or also value_type*
		using reference = ClassifiedPacket&;  // or also value_type&

		PacketIterator(pointer ptr) : m_ptr(ptr) {}

		reference operator*() const { return *m_ptr; }
		pointer operator->() { return m_ptr; }

		PacketIterator& operator++() { m_ptr++; return *this; }
		PacketIterator operator++(int) { PacketIterator tmp = *this; ++(*this); return tmp; }

		friend bool operator== (const PacketIterator& a, const PacketIterator& b) { return a.m_ptr == b.m_ptr; };
		friend bool operator!= (const PacketIterator& a, const PacketIterator& b) { return a.m_ptr != b.m_ptr; };

	private:
		pointer m_ptr;
	};


	PacketIterator begin() { return { m_classifiedPackets.begin() }; }
	PacketIterator end() { return { m_classifiedPackets.end() }; }

private:
	static void packetHandler(u_char* userData, const pcap_pkthdr* header, const u_char* packetData);
	void createPacketHandler(const pcap_pkthdr* header, const u_char* packetData);

private:
	constexpr static const byte4 POOL_BUFFER_SIZE = 0x5000;
	constexpr static const byte4 MAX_PACKETS = 0x100;

	std::function<bool(ClassifiedPacket& packet)> m_filter;
	std::function<void(ClassifiedPacket& packet)> m_callback;
	byte4 m_packets;

	Device& m_device;
	bool m_running;

	Classifier* m_classifier;

	StaticVector<byte, POOL_BUFFER_SIZE> m_buffer;
	StaticVector<ClassifiedPacket, sizeof(ClassifiedPacket)* MAX_PACKETS> m_classifiedPackets;
};
