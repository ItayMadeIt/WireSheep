#pragma once

#include "Address.h"

using namespace address;

#pragma pack(push)

struct ARPHeader
{
	byte2 m_hardwareType;
	byte2 m_protocolType;

	byte m_hardwareLength;
	byte m_protocolLength;

	byte2 m_operation;
};

#pragma pack(pop)