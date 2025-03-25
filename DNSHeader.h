#pragma once

#include "WireDefs.h"

// Force tight packing
#pragma pack(push)
#pragma pack(1)

struct DNSHeader
{
	byte2 transactionID;
	byte2 flags;
	byte2 amountQuestions;
	byte2 amountAnswers;
	byte2 amountAuthoritiveRR;
	byte2 amountAdditionalRR;
};

#pragma pack(pop