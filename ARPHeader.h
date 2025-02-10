#pragma once

#include "Address.h"

using namespace address;

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct ARPHeader
{
	byte2 m_hardwareType;
	byte2 m_protocolType;

	byte m_hardwareLength;
	byte m_protocolLength;

	byte2 m_operation;

	// Sender Hardware address
	// Sender Protocol address
	// Target Hardware address
	// Target Protocol address
};

#pragma pack(pop)