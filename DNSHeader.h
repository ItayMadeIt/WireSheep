#pragma once

#include "WireDefs.h"

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct DNSHeader
{
	byte2 transactionID;
	byte2 flags;
	byte2 questionsLength;
	byte2 answerLength;
	byte2 authoritiveRRLength;
	byte2 additionalRRLength;
};

#pragma pack(pop)