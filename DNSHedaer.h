#pragma once

#include "WireDefs.h"

#pragma pack(push)

struct DNSData
{
	byte2 m_transactionID;
	byte2 m_flags;
	byte2 m_amountQuestions;
	byte2 m_amountAnswers;
	byte2 m_amountAuthoritiveRR;
	byte2 m_amountAdditionalRR;
};

#pragma pack(pop