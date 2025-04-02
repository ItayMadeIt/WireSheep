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

	void start(byte4 maxPackets = 0x200);
	void stop();

	const ClassifiedPacket& getClassifiedPacket(byte4 index) const;

private:
	constexpr static const byte4 POOL_BUFFER_SIZE = 0x5000;
	constexpr static const byte4 MAX_PACKETS = 0x100;

	Device& m_device;
	bool m_running;

	Classifier* m_classifier;

	StaticVector<byte, POOL_BUFFER_SIZE> m_buffer;
	StaticVector<ClassifiedPacket, sizeof(ClassifiedPacket)* MAX_PACKETS> m_classifiedPackets;
};
