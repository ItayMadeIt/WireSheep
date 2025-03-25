#pragma once

#include "Address.h"

using namespace address;

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct ARPHeader
{
	byte2 hardwareType;
	byte2 protocolType;

	byte  hardwareLength;
	byte  protocolLength;

	byte2 operation;

	// Sender Hardware address
	// Sender Protocol address
	// Target Hardware address
	// Target Protocol address
};

#pragma pack(pop)