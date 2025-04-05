#pragma once

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

	void setFilter(const char* filterStr);
	void setFilter(bool (*customFilter)(ClassifiedPacket& packet));

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
	constexpr static const byte4 POOL_BUFFER_SIZE = 0x5000;
	constexpr static const byte4 MAX_PACKETS = 0x100;

	bool (*m_customFilter)(ClassifiedPacket& packet);

	Device& m_device;
	bool m_running;

	Classifier* m_classifier;

	StaticVector<byte, POOL_BUFFER_SIZE> m_buffer;
	StaticVector<ClassifiedPacket, sizeof(ClassifiedPacket)* MAX_PACKETS> m_classifiedPackets;
};
